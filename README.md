# reviewgate

Production-shaped **PR security gate**: deterministic scanners, risk scoring, suppressions, webhook stub, and an offline eval promotion gate.

Uses [platformkit](https://github.com/yashshah9/platformkit) for pluggable auth/audit/queues.

## Quick start

```bash
uv venv --python 3.12
uv pip install -e ../platformkit -e ".[dev]"
uv run pytest tests/test_api.py -q
uv run reviewgate eval --min-pass-rate 1.0
uv run reviewgate serve   # :8092
```

## Docker

```bash
docker compose up --build -d redis postgres reviewgate
docker compose run --rm integration
```

## API

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/v1/review` | scan unified diff → findings + gate decision |
| GET | `/v1/reviews` | list recent reviews |
| GET | `/v1/reviews/{id}` | fetch one review |
| POST | `/v1/webhooks/github` | stub GitHub App webhook (diff + PR meta) |
| POST | `/v1/suppressions` | admin rule suppressions |
| POST | `/v1/eval` | run eval cases against scanners |
| POST | `/v1/admin/reset` | clear store (admin) |

## Docs

- [Architecture](docs/architecture.md)
- [Demo script](docs/demo.md)
