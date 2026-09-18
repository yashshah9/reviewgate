# Demo script (~5 minutes)

## Setup

```bash
uv run reviewgate serve
# or: docker compose up --build -d
curl -s localhost:8092/health | jq
```

## 1. Clean diff → allow (1 min)

```bash
curl -s -X POST localhost:8092/v1/review \
  -H "Authorization: Bearer dev-key" \
  -H "Content-Type: application/json" \
  -d '{"repo":"acme/app","diff":"diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -1,1 +1,2 @@\n+x = 1\n"}' | jq '{decision, risk_score, findings}'
```

Expect `allow`.

## 2. Secret → block (1 min)

```bash
curl -s -X POST localhost:8092/v1/review \
  -H "Authorization: Bearer dev-key" \
  -H "Content-Type: application/json" \
  -d '{"repo":"acme/app","pr_number":42,"diff":"diff --git a/c.py b/c.py\n--- a/c.py\n+++ b/c.py\n@@ -1,1 +1,2 @@\n+AWS_KEY = \"AKIAIOSFODNN7EXAMPLE\"\n"}' | jq '{decision, risk_score, findings: .findings[].rule_id, comment: .comment_markdown}'
```

Expect `block` + `secret-aws-key` and a markdown comment table.

## 3. Webhook stub (1 min)

```bash
curl -s -X POST localhost:8092/v1/webhooks/github \
  -H "Authorization: Bearer dev-key" \
  -H "Content-Type: application/json" \
  -d '{"action":"opened","repository":{"full_name":"acme/app"},"pull_request":{"number":42,"title":"keys"},"diff":"diff --git a/c.py b/c.py\n--- a/c.py\n+++ b/c.py\n@@ -1,1 +1,2 @@\n+AWS_KEY = \"AKIAIOSFODNN7EXAMPLE\"\n"}' | jq .review.decision
```

## 4. Eval gate (1 min)

```bash
reviewgate eval --min-pass-rate 1.0
```

Show pass_rate `1.0` and mention CI runs this on every PR.
