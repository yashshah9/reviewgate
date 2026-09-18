# Architecture

## Pipeline

```
unified diff ──► policy pack (default | secrets | security | strict)
              ──► rule scanners (secrets / injection / authz / dangerous / policy)
              ──► fingerprints + risk_score + gate (allow | warn | block)
              ──► PR comment + SARIF + Check Run + audit + queue
eval          ──► golden cases gate (CI)
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

## Eval promotion gate

```bash
reviewgate eval --min-pass-rate 1.0
```

Golden cases live in `evals/cases.json` (bundled under `reviewgate/data/`).
CI fails when the pass rate drops.
