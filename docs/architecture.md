# Architecture

## Pipeline

```
unified diff ──► policy pack (default | secrets | security | strict)
              ──► rule scanners (secrets / injection / authz / dangerous / policy)
              ──► fingerprints + risk_score + gate (allow | warn | block)
              ──► PR comment + SARIF + Check Run + audit + queue
eval          ──► golden cases + baseline regression gate (CI)
store         ──► memory (default) | postgres (compose)
```

## Policy packs

| Pack | Scope |
|------|-------|
| `default` | all built-in rules |
| `secrets` | secrets category only |
| `security` | secrets + injection + authz + dangerous |
| `strict` | critical + high severity only |

Pass `policy_pack` on `/v1/review` or the GitHub webhook stub.

## Exports

- **SARIF 2.1.0** — `GET /v1/reviews/{id}/sarif` (CI upload / code scanning)
- **Check Run** — `GET /v1/reviews/{id}/check-run` (GitHub Checks API shape)

Findings include stable `fingerprint` values for suppressions.

## Gate

```
risk >= block_threshold  → block
risk >= warn_threshold   → warn
else                     → allow
```

Defaults: warn `0.35`, block `0.7`.

## Review store

| Driver | Behavior |
|--------|----------|
| `memory` | in-process only (default) |
| `postgres` | `reviewgate_reviews` table; load on boot; `POST /v1/admin/reload` rehydrates |

Compose sets `REVIEWGATE_STORE_DRIVER=postgres`.

## Eval promotion gate

```bash
reviewgate eval --min-pass-rate 1.0 --baseline evals/baseline.json
# refresh snapshot after intentional scanner changes:
reviewgate eval --write-baseline evals/baseline.json
```

Golden cases live in `evals/cases.json` (bundled under `reviewgate/data/`).
CI fails when the pass rate drops or a previously-passing case regresses.
