"""Optional durable backends for ReviewStore."""

from __future__ import annotations

import json
from typing import Any, Protocol, runtime_checkable

from reviewgate.scanner import Finding, Severity
from reviewgate.store import ReviewResult

_SCHEMA = """
CREATE TABLE IF NOT EXISTS reviewgate_reviews (
    id TEXT PRIMARY KEY,
    repo TEXT NOT NULL,
    pr_number INTEGER,
    title TEXT NOT NULL,
    risk_score DOUBLE PRECISION NOT NULL,
    decision TEXT NOT NULL,
    findings JSONB NOT NULL,
    comment TEXT NOT NULL,
    policy_pack TEXT NOT NULL,
    latency_ms INTEGER NOT NULL,
    suppressed JSONB NOT NULL,
    created_at DOUBLE PRECISION NOT NULL,
    tenant_id TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS reviewgate_reviews_created_idx
    ON reviewgate_reviews (created_at DESC);
CREATE INDEX IF NOT EXISTS reviewgate_reviews_tenant_idx
    ON reviewgate_reviews (tenant_id);
CREATE TABLE IF NOT EXISTS reviewgate_suppressions (
    id TEXT PRIMARY KEY
);
ALTER TABLE reviewgate_reviews ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT '';
"""


@runtime_checkable
class ReviewBackend(Protocol):
    def ensure_schema(self) -> None: ...

    def save_review(self, review: ReviewResult) -> None: ...

    def load_recent(self, *, limit: int = 500) -> list[ReviewResult]: ...

    def get_review(self, review_id: str) -> ReviewResult | None: ...

    def load_suppressions(self) -> list[str]: ...

    def save_suppressions(self, ids: list[str]) -> None: ...

    def clear(self) -> None: ...


def _finding_to_dict(f: Finding) -> dict[str, Any]:
    return {
        "rule_id": f.rule_id,
        "title": f.title,
        "severity": f.severity.value,
        "category": f.category,
        "file": f.file,
        "line": f.line,
        "excerpt": f.excerpt,
        "remediation": f.remediation,
        "fingerprint": f.fingerprint,
    }


def _finding_from_dict(d: dict[str, Any]) -> Finding:
    return Finding(
        rule_id=str(d["rule_id"]),
        title=str(d["title"]),
        severity=Severity(str(d["severity"])),
        category=str(d["category"]),
        file=str(d["file"]),
        line=int(d["line"]) if d.get("line") is not None else None,
        excerpt=str(d["excerpt"]),
        remediation=str(d["remediation"]),
        fingerprint=str(d.get("fingerprint") or ""),
    )


def _review_from_row(row: Any) -> ReviewResult:
    findings_raw = row[6]
    if isinstance(findings_raw, str):
        findings_raw = json.loads(findings_raw)
    suppressed_raw = row[10]
    if isinstance(suppressed_raw, str):
        suppressed_raw = json.loads(suppressed_raw)
    tenant_id = str(row[12]) if len(row) > 12 and row[12] is not None else ""
    return ReviewResult(
        id=str(row[0]),
        repo=str(row[1]),
        pr_number=int(row[2]) if row[2] is not None else None,
        title=str(row[3]),
        risk_score=float(row[4]),
        decision=str(row[5]),
        findings=[_finding_from_dict(f) for f in findings_raw],
        comment=str(row[7]),
        policy_pack=str(row[8]),
        latency_ms=int(row[9]),
        suppressed=[str(x) for x in suppressed_raw],
        created_at=float(row[11]),
        tenant_id=tenant_id,
    )


_SELECT_COLS = (
    "id, repo, pr_number, title, risk_score, decision, findings, "
    "comment, policy_pack, latency_ms, suppressed, created_at, tenant_id"
)


class PostgresReviewStore:
    def __init__(self, dsn: str) -> None:
        try:
            import psycopg
        except ImportError as exc:  # pragma: no cover
            raise ImportError(
                "Postgres reviews require psycopg. Install platformkit[postgres]."
            ) from exc
        self._psycopg = psycopg
        self._dsn = dsn

    def ensure_schema(self) -> None:
        with self._psycopg.connect(self._dsn) as conn:
            conn.execute(_SCHEMA)
            conn.commit()

    def save_review(self, review: ReviewResult) -> None:
        with self._psycopg.connect(self._dsn) as conn:
            conn.execute(
                "INSERT INTO reviewgate_reviews "
                "(id, repo, pr_number, title, risk_score, decision, findings, comment, "
                "policy_pack, latency_ms, suppressed, created_at, tenant_id) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s::jsonb,%s,%s,%s,%s::jsonb,%s,%s) "
                "ON CONFLICT (id) DO NOTHING",
                (
                    review.id,
                    review.repo,
                    review.pr_number,
                    review.title,
                    review.risk_score,
                    review.decision,
                    json.dumps([_finding_to_dict(f) for f in review.findings]),
                    review.comment,
                    review.policy_pack,
                    review.latency_ms,
                    json.dumps(review.suppressed),
                    review.created_at,
                    review.tenant_id,
                ),
            )
            conn.commit()

    def load_recent(self, *, limit: int = 500) -> list[ReviewResult]:
        with self._psycopg.connect(self._dsn) as conn:
            rows = conn.execute(
                f"SELECT {_SELECT_COLS} FROM ("
                f"  SELECT {_SELECT_COLS} "
                "  FROM reviewgate_reviews ORDER BY created_at DESC LIMIT %s"
                ") recent ORDER BY created_at ASC",
                (limit,),
            ).fetchall()
        return [_review_from_row(r) for r in rows]

    def get_review(self, review_id: str) -> ReviewResult | None:
        with self._psycopg.connect(self._dsn) as conn:
            row = conn.execute(
                f"SELECT {_SELECT_COLS} FROM reviewgate_reviews WHERE id = %s",
                (review_id,),
            ).fetchone()
        if row is None:
            return None
        return _review_from_row(row)

    def load_suppressions(self) -> list[str]:
        with self._psycopg.connect(self._dsn) as conn:
            rows = conn.execute("SELECT id FROM reviewgate_suppressions ORDER BY id").fetchall()
        return [str(r[0]) for r in rows]

    def save_suppressions(self, ids: list[str]) -> None:
        with self._psycopg.connect(self._dsn) as conn:
            conn.execute("DELETE FROM reviewgate_suppressions")
            for item in ids:
                conn.execute(
                    "INSERT INTO reviewgate_suppressions (id) VALUES (%s) ON CONFLICT DO NOTHING",
                    (item,),
                )
            conn.commit()

    def clear(self) -> None:
        with self._psycopg.connect(self._dsn) as conn:
            conn.execute("DELETE FROM reviewgate_reviews")
            conn.execute("DELETE FROM reviewgate_suppressions")
            conn.commit()


def build_backend(driver: str, *, postgres_dsn: str) -> ReviewBackend | None:
    if driver in {"", "memory", "none"}:
        return None
    if driver == "postgres":
        store = PostgresReviewStore(postgres_dsn)
        store.ensure_schema()
        return store
    raise ValueError(f"Unknown review store driver {driver!r}")
