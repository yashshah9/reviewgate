"""HTTP API for reviewgate."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import Depends, FastAPI, Header, HTTPException
from platformkit.protocols import Principal
from pydantic import BaseModel, Field

from reviewgate.__version__ import __version__
from reviewgate.config import Settings
from reviewgate.evals import EvalCase, run_eval
from reviewgate.platform import build_kit
from reviewgate.store import ReviewStore

settings = Settings()
kit = build_kit(settings)
store = ReviewStore(
    block_threshold=settings.block_threshold,
    warn_threshold=settings.warn_threshold,
)

app = FastAPI(title="reviewgate", version=__version__)


class ReviewRequest(BaseModel):
    diff: str = Field(..., min_length=1, max_length=500_000)
    repo: str = Field(default="local/demo", max_length=200)
    pr_number: int | None = Field(default=None, ge=1)
    title: str = Field(default="", max_length=300)


class SuppressRequest(BaseModel):
    rule_ids: list[str] = Field(..., min_length=1, max_length=50)


class EvalCaseModel(BaseModel):
    id: str | None = None
    diff: str
    expect_decision: str | None = None
    must_find_rule: str | None = None
    must_not_find_rule: str | None = None
    min_risk: float | None = None
    max_risk: float | None = None


class EvalRequest(BaseModel):
    cases: list[EvalCaseModel] = Field(..., min_length=1)


class GithubWebhook(BaseModel):
    action: str = "opened"
    repository: dict[str, Any] = Field(default_factory=dict)
    pull_request: dict[str, Any] = Field(default_factory=dict)
    diff: str = Field(..., min_length=1, max_length=500_000)


def _bearer_token(authorization: Annotated[str | None, Header()] = None) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer token")
    return authorization.split(" ", 1)[1].strip()


def require_principal(token: Annotated[str, Depends(_bearer_token)]) -> Principal:
    principal = kit.auth.authenticate(token)
    if principal is None:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return principal


def _finding_dict(f: Any) -> dict[str, Any]:
    return {
        "rule_id": f.rule_id,
        "title": f.title,
        "severity": f.severity.value,
        "category": f.category,
        "file": f.file,
        "line": f.line,
        "excerpt": f.excerpt,
        "remediation": f.remediation,
    }


def _review_dict(r: Any) -> dict[str, Any]:
    return {
        "id": r.id,
        "repo": r.repo,
        "pr_number": r.pr_number,
        "title": r.title,
        "risk_score": r.risk_score,
        "decision": r.decision,
        "findings": [_finding_dict(f) for f in r.findings],
        "comment_markdown": r.comment,
        "suppressed": r.suppressed,
    }


@app.get("/health")
def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "version": __version__,
        "auth": settings.auth_driver,
        "audit": settings.audit_driver,
        "queue": settings.queue_driver,
        "reviews": len(store.reviews),
        "block_threshold": settings.block_threshold,
        "warn_threshold": settings.warn_threshold,
    }


@app.post("/v1/review")
def review(
    body: ReviewRequest,
    principal: Annotated[Principal, Depends(require_principal)],
) -> dict[str, Any]:
    tenant_id = principal.tenant_id or principal.id
    result = store.review(
        diff=body.diff,
        repo=body.repo,
        pr_number=body.pr_number,
        title=body.title,
    )
    kit.audit.emit(
        actor=principal.id,
        action="review.run",
        payload={
            "review_id": result.id,
            "decision": result.decision,
            "risk_score": result.risk_score,
            "findings": len(result.findings),
        },
        tenant_id=tenant_id,
        resource_type="review",
        resource_id=result.id,
    )
    kit.queue.enqueue(
        "reviewgate.reviewed",
        {"review_id": result.id, "decision": result.decision},
    )
    return _review_dict(result)


@app.get("/v1/reviews/{review_id}")
def get_review(
    review_id: str,
    principal: Annotated[Principal, Depends(require_principal)],
) -> dict[str, Any]:
    del principal
    result = store.get(review_id)
    if result is None:
        raise HTTPException(status_code=404, detail="review not found")
    return _review_dict(result)


@app.get("/v1/reviews")
def list_reviews(
    principal: Annotated[Principal, Depends(require_principal)],
    limit: int = 20,
) -> dict[str, Any]:
    del principal
    limit = max(1, min(limit, 100))
    items = list(reversed(store.reviews[-limit:]))
    return {
        "count": len(items),
        "reviews": [
            {
                "id": r.id,
                "repo": r.repo,
                "pr_number": r.pr_number,
                "decision": r.decision,
                "risk_score": r.risk_score,
                "findings": len(r.findings),
            }
            for r in items
        ],
    }


@app.post("/v1/suppressions")
def add_suppressions(
    body: SuppressRequest,
    principal: Annotated[Principal, Depends(require_principal)],
) -> dict[str, Any]:
    if "admin" not in principal.roles:
        raise HTTPException(status_code=403, detail="admin required")
    rules = store.suppress(body.rule_ids)
    kit.audit.emit(
        actor=principal.id,
        action="review.suppress",
        payload={"rule_ids": body.rule_ids},
        tenant_id=principal.tenant_id or principal.id,
    )
    return {"suppressions": rules}


@app.post("/v1/webhooks/github")
def github_webhook(
    body: GithubWebhook,
    principal: Annotated[Principal, Depends(require_principal)],
) -> dict[str, Any]:
    """Stub GitHub App webhook: accepts PR metadata + unified diff."""
    tenant_id = principal.tenant_id or principal.id
    repo = (
        body.repository.get("full_name")
        or body.repository.get("name")
        or "unknown/repo"
    )
    pr = body.pull_request
    pr_number = pr.get("number")
    title = str(pr.get("title") or f"PR webhook {body.action}")
    result = store.review(
        diff=body.diff,
        repo=str(repo),
        pr_number=int(pr_number) if pr_number is not None else None,
        title=title,
    )
    kit.audit.emit(
        actor=principal.id,
        action="webhook.github",
        payload={
            "action": body.action,
            "review_id": result.id,
            "decision": result.decision,
        },
        tenant_id=tenant_id,
        resource_type="review",
        resource_id=result.id,
    )
    return {
        "status": "processed",
        "action": body.action,
        "review": _review_dict(result),
    }


@app.post("/v1/eval")
def eval_endpoint(
    body: EvalRequest,
    principal: Annotated[Principal, Depends(require_principal)],
) -> dict[str, Any]:
    tenant_id = principal.tenant_id or principal.id
    cases = [
        EvalCase(
            id=c.id or f"case-{i}",
            diff=c.diff,
            expect_decision=c.expect_decision,
            must_find_rule=c.must_find_rule,
            must_not_find_rule=c.must_not_find_rule,
            min_risk=c.min_risk,
            max_risk=c.max_risk,
        )
        for i, c in enumerate(body.cases)
    ]
    results = run_eval(
        cases,
        block_threshold=settings.block_threshold,
        warn_threshold=settings.warn_threshold,
    )
    passed = sum(1 for r in results if r.passed)
    kit.audit.emit(
        actor=principal.id,
        action="eval.run",
        payload={"total": len(results), "passed": passed},
        tenant_id=tenant_id,
    )
    return {
        "total": len(results),
        "passed": passed,
        "failed": len(results) - passed,
        "pass_rate": passed / len(results) if results else 0.0,
        "results": [
            {
                "id": r.case.id,
                "passed": r.passed,
                "reason": r.reason,
                "decision": r.decision,
                "risk_score": r.risk,
                "rule_ids": r.rule_ids,
            }
            for r in results
        ],
    }


@app.post("/v1/admin/reset")
def reset_store(
    principal: Annotated[Principal, Depends(require_principal)],
) -> dict[str, str]:
    if "admin" not in principal.roles:
        raise HTTPException(status_code=403, detail="admin required")
    store.clear()
    return {"status": "cleared"}
