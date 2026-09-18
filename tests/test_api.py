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
