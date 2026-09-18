"""reviewgate functional tests."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from reviewgate import api as api_module
from reviewgate.evals import run_golden_suite
from reviewgate.platform import build_kit
from reviewgate.store import ReviewStore

CLEAN = """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1,2 +1,3 @@
 def add(a, b):
+    return a + b
"""

SECRET = """diff --git a/cfg.py b/cfg.py
--- a/cfg.py
+++ b/cfg.py
@@ -1,1 +1,2 @@
+AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
"""


@pytest.fixture
def client() -> Iterator[TestClient]:
    api_module.settings.api_keys = "dev-key:demo-tenant"
    api_module.settings.admin_keys = "admin-key"
    api_module.settings.auth_driver = "api_key"
    api_module.settings.audit_driver = "memory"
    api_module.settings.queue_driver = "memory"
    api_module.settings.store_driver = "memory"
    api_module.kit = build_kit(api_module.settings)
    api_module.store = ReviewStore(
        block_threshold=api_module.settings.block_threshold,
        warn_threshold=api_module.settings.warn_threshold,
    )
    with TestClient(api_module.app) as test_client:
        yield test_client


AUTH = {"Authorization": "Bearer dev-key"}
ADMIN = {"Authorization": "Bearer admin-key"}


def test_health(client: TestClient) -> None:
    body = client.get("/health").json()
    assert body["status"] == "ok"
    assert body["version"]


def test_review_requires_auth(client: TestClient) -> None:
    assert client.post("/v1/review", json={"diff": CLEAN}).status_code == 401


def test_review_clean_allow(client: TestClient) -> None:
    body = client.post("/v1/review", headers=AUTH, json={"diff": CLEAN, "repo": "acme/app"}).json()
    assert body["decision"] == "allow"
    assert body["findings"] == []
    assert body["risk_score"] == 0.0
    assert "reviewgate" in body["comment_markdown"]


def test_review_secret_block(client: TestClient) -> None:
    body = client.post(
        "/v1/review",
        headers=AUTH,
        json={"diff": SECRET, "repo": "acme/app", "pr_number": 12},
    ).json()
    assert body["decision"] == "block"
    assert any(f["rule_id"] == "secret-aws-key" for f in body["findings"])
    assert body["risk_score"] >= 0.7

    got = client.get(f"/v1/reviews/{body['id']}", headers=AUTH).json()
    assert got["id"] == body["id"]

    listed = client.get("/v1/reviews", headers=AUTH).json()
    assert listed["count"] >= 1


def test_github_webhook(client: TestClient) -> None:
    body = client.post(
        "/v1/webhooks/github",
        headers=AUTH,
        json={
            "action": "opened",
            "repository": {"full_name": "acme/app"},
            "pull_request": {"number": 7, "title": "add key"},
            "diff": SECRET,
        },
    ).json()
    assert body["status"] == "processed"
    assert body["review"]["decision"] == "block"
    assert body["review"]["pr_number"] == 7


def test_suppression_requires_admin(client: TestClient) -> None:
    assert (
        client.post(
            "/v1/suppressions",
            headers=AUTH,
            json={"rule_ids": ["secret-aws-key"]},
        ).status_code
        == 403
    )
    client.post(
        "/v1/suppressions",
        headers=ADMIN,
        json={"rule_ids": ["secret-aws-key"]},
    )
    body = client.post("/v1/review", headers=AUTH, json={"diff": SECRET}).json()
    assert body["decision"] == "allow"
    assert body["findings"] == []


def test_sarif_check_run_traces_and_policy(client: TestClient) -> None:
    packs = client.get("/v1/policies", headers=AUTH).json()["packs"]
    assert any(p["id"] == "secrets" for p in packs)

    body = client.post(
        "/v1/review",
        headers=AUTH,
        json={"diff": SECRET, "repo": "acme/app", "policy_pack": "secrets"},
    ).json()
    assert body["policy_pack"] == "secrets"
    assert body["decision"] == "block"
    assert body["findings"][0]["fingerprint"]
    assert "latency_ms" in body

    rid = body["id"]
    sarif = client.get(f"/v1/reviews/{rid}/sarif", headers=AUTH).json()
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"]
    assert sarif["runs"][0]["properties"]["decision"] == "block"

    check = client.get(f"/v1/reviews/{rid}/check-run", headers=AUTH).json()
    assert check["conclusion"] == "failure"
    assert check["output"]["annotations"]

    traces = client.get("/v1/traces", headers=AUTH).json()
    assert traces["count"] >= 1
    assert traces["traces"][0]["policy_pack"] == "secrets"

    # secrets pack ignores soft DEBUG findings
    debug = """diff --git a/main.py b/main.py
--- a/main.py
+++ b/main.py
@@ -1,1 +1,2 @@
+DEBUG = True
"""
    soft = client.post(
        "/v1/review",
        headers=AUTH,
        json={"diff": debug, "policy_pack": "secrets"},
    ).json()
    assert soft["decision"] == "allow"


def test_eval_endpoint(client: TestClient) -> None:
    resp = client.post(
        "/v1/eval",
        headers=AUTH,
        json={
            "cases": [
                {
                    "id": "clean",
                    "diff": CLEAN,
                    "expect_decision": "allow",
                },
                {
                    "id": "secret",
                    "diff": SECRET,
                    "must_find_rule": "secret-aws-key",
                    "expect_decision": "block",
                },
            ]
        },
    )
    body = resp.json()
    assert body["passed"] == 2
    assert body["failed"] == 0


def test_reset_requires_admin(client: TestClient) -> None:
    assert client.post("/v1/admin/reset", headers=AUTH).status_code == 403
    assert client.post("/v1/admin/reset", headers=ADMIN).status_code == 200


def test_golden_suite_gate() -> None:
    results, rate = run_golden_suite()
    failed = [r for r in results if not r.passed]
    assert failed == [], [(r.case.id, r.reason, r.decision, r.risk) for r in failed]
    assert rate == 1.0


def test_baseline_compare_detects_regression() -> None:
    from reviewgate.evals import (
        EvalCase,
        EvalResult,
        compare_to_baseline,
        snapshot_from_results,
    )

    results, rate = run_golden_suite()
    baseline = snapshot_from_results(results, pass_rate=rate)
    assert compare_to_baseline(results, baseline) == []
    broken = [
        EvalResult(
            case=EvalCase(id=results[0].case.id, diff="x"),
            passed=False,
            reason="forced",
            decision="allow",
            risk=0.0,
            rule_ids=[],
        ),
        *results[1:],
    ]
    regs = compare_to_baseline(broken, baseline)
    assert any(results[0].case.id in m and "was pass, now fail" in m for m in regs)


def test_memory_backend_reload_roundtrip() -> None:
    """Durable backend contract without Postgres: fake store + reload."""
    from reviewgate.store import ReviewResult, ReviewStore

    class FakeStore:
        def __init__(self) -> None:
            self.rows: list[ReviewResult] = []

        def ensure_schema(self) -> None:
            return None

        def load_recent(self, *, limit: int = 500) -> list[ReviewResult]:
            return list(self.rows)[-limit:]

        def save_review(self, review: ReviewResult) -> None:
            self.rows.append(review)

        def clear(self) -> None:
            self.rows.clear()

    backend = FakeStore()
    store = ReviewStore(backend=backend)
    result = store.review(diff=SECRET, repo="acme/app")
    assert result.decision == "block"
    assert len(backend.rows) == 1
    with store._lock:
        store.reviews.clear()
        store.traces.clear()
    assert store.reviews == []
    assert store.load() == 1
    assert store.get(result.id) is not None
    assert store.get(result.id).decision == "block"  # type: ignore[union-attr]
