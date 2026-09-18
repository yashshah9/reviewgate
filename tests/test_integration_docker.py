"""Docker integration for reviewgate."""

from __future__ import annotations

import os
import time

import httpx
import pytest

BASE = os.environ.get("REVIEWGATE_BASE_URL", "http://127.0.0.1:8092")
AUTH = {"Authorization": "Bearer dev-key"}

pytestmark = pytest.mark.skipif(
    os.environ.get("RUN_DOCKER_INTEGRATION") != "1",
    reason="Set RUN_DOCKER_INTEGRATION=1 against a live compose stack",
)

SECRET = """diff --git a/cfg.py b/cfg.py
--- a/cfg.py
+++ b/cfg.py
@@ -1,1 +1,2 @@
+AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
"""


def _wait_healthy(timeout: float = 60.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if httpx.get(f"{BASE}/health", timeout=2.0).status_code == 200:
                return
        except httpx.HTTPError:
            pass
        time.sleep(1)
    raise RuntimeError(f"reviewgate not healthy at {BASE}")


def test_docker_review_webhook_eval() -> None:
    _wait_healthy()
    httpx.post(
        f"{BASE}/v1/admin/reset",
        headers={"Authorization": "Bearer admin-key"},
        timeout=5.0,
    )
    rev = httpx.post(
        f"{BASE}/v1/review",
        headers=AUTH,
        json={"diff": SECRET, "repo": "acme/app", "pr_number": 3},
        timeout=10.0,
    )
    body = rev.json()
    assert body["decision"] == "block"
    assert body["risk_score"] >= 0.7

    wh = httpx.post(
        f"{BASE}/v1/webhooks/github",
        headers=AUTH,
        json={
            "action": "synchronize",
            "repository": {"full_name": "acme/app"},
            "pull_request": {"number": 3, "title": "sync"},
            "diff": SECRET,
        },
        timeout=10.0,
    )
    assert wh.json()["review"]["decision"] == "block"

    ev = httpx.post(
        f"{BASE}/v1/eval",
        headers=AUTH,
        json={
            "cases": [
                {
                    "diff": SECRET,
                    "must_find_rule": "secret-aws-key",
                    "expect_decision": "block",
                }
            ]
        },
        timeout=10.0,
    )
    assert ev.json()["passed"] == 1

    health = httpx.get(f"{BASE}/health", timeout=5.0).json()
    assert health["queue"] == "redis"
    assert health["audit"] == "postgres"
