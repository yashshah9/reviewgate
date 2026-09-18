# Architecture

## Pipeline

```
unified diff ──► rule scanners (secrets / injection / authz / dangerous / policy)
              ──► risk_score + gate decision (allow | warn | block)
              ──► PR comment markdown + audit + queue event
eval          ──► golden cases gate (CI)
```

## Scanners

Deterministic regex/rules over **added lines** only (unified diff). Categories:

| Category | Examples |
|----------|----------|
| secrets | AWS keys, API tokens, private key PEM |
| injection | SQL f-strings / format |
| authz | `allow_all`, auth bypass comments |
| dangerous | `eval`/`exec`, `pickle.loads`, `shell=True` |
| policy | `DEBUG=True`, insecure HTTP oauth URLs |

Swap rule packs or add Semgrep later without changing the HTTP surface.

## Gate

```
risk >= block_threshold  → block
risk >= warn_threshold   → warn
else                     → allow
```

Defaults: warn `0.35`, block `0.7`.

## GitHub App (stub)

`POST /v1/webhooks/github` accepts PR metadata + a unified diff and returns the same review payload a real App would post as a check/comment. Wire a real App installation next without changing scoring.

## Eval promotion gate

```bash
reviewgate eval --min-pass-rate 1.0
```

Golden cases live in `evals/cases.json` (bundled under `reviewgate/data/`).
CI fails when the pass rate drops.
