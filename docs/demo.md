# Demo script (~5 minutes)

## Setup

```bash
uv run reviewgate serve
curl -s localhost:8092/health | jq
```

## 1. Policy packs (30s)

```bash
curl -s localhost:8092/v1/policies -H "Authorization: Bearer dev-key" | jq '.packs[].id'
```

## 2. Secret → block + SARIF (2 min)

```bash
REV=$(curl -s -X POST localhost:8092/v1/review \
  -H "Authorization: Bearer dev-key" \
  -H "Content-Type: application/json" \
  -d '{"repo":"acme/app","pr_number":42,"policy_pack":"secrets","diff":"diff --git a/c.py b/c.py\n--- a/c.py\n+++ b/c.py\n@@ -1,1 +1,2 @@\n+AWS_KEY = \"AKIAIOSFODNN7EXAMPLE\"\n"}')
echo "$REV" | jq '{decision, risk_score, fingerprint: .findings[0].fingerprint, latency_ms}'
ID=$(echo "$REV" | jq -r .id)
curl -s localhost:8092/v1/reviews/$ID/sarif -H "Authorization: Bearer dev-key" | jq '.runs[0].properties'
curl -s localhost:8092/v1/reviews/$ID/check-run -H "Authorization: Bearer dev-key" | jq '{conclusion, title: .output.title}'
```

## 3. Webhook returns check_run + sarif (1 min)

```bash
curl -s -X POST localhost:8092/v1/webhooks/github \
  -H "Authorization: Bearer dev-key" \
  -H "Content-Type: application/json" \
  -d '{"action":"opened","repository":{"full_name":"acme/app"},"pull_request":{"number":42,"title":"keys"},"diff":"diff --git a/c.py b/c.py\n--- a/c.py\n+++ b/c.py\n@@ -1,1 +1,2 @@\n+AWS_KEY = \"AKIAIOSFODNN7EXAMPLE\"\n"}' \
  | jq '{decision: .review.decision, conclusion: .check_run.conclusion}'
```

## 4. Eval gate (1 min)

```bash
reviewgate eval --min-pass-rate 1.0
```
