"""CLI."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import uvicorn

from reviewgate.config import Settings
from reviewgate.evals import (
    compare_to_baseline,
    load_baseline,
    run_golden_suite,
    write_baseline,
)


def main() -> None:
    parser = argparse.ArgumentParser(prog="reviewgate")
    sub = parser.add_subparsers(dest="cmd", required=True)

    serve = sub.add_parser("serve")
    serve.add_argument("--host", default=None)
    serve.add_argument("--port", type=int, default=None)

    ev = sub.add_parser("eval", help="Run golden eval suite (CI gate)")
    ev.add_argument("--min-pass-rate", type=float, default=None)
    ev.add_argument("--baseline", type=Path, default=None)
    ev.add_argument("--write-baseline", type=Path, default=None)

    args = parser.parse_args()
    settings = Settings()

    if args.cmd == "serve":
        uvicorn.run(
            "reviewgate.api:app",
            host=args.host or settings.host,
            port=args.port or settings.port,
        )
    elif args.cmd == "eval":
        results, rate = run_golden_suite(
            block_threshold=settings.block_threshold,
            warn_threshold=settings.warn_threshold,
        )
        payload = {
            "pass_rate": rate,
            "passed": sum(1 for r in results if r.passed),
            "total": len(results),
            "results": [
                {
                    "id": r.case.id,
                    "passed": r.passed,
                    "reason": r.reason,
                    "decision": r.decision,
                    "risk_score": r.risk,
                }
                for r in results
            ],
        }
        print(json.dumps(payload, indent=2))

        if args.write_baseline is not None:
            write_baseline(args.write_baseline, results, pass_rate=rate)
            print(f"Wrote baseline → {args.write_baseline}", file=sys.stderr)

        minimum = (
            args.min_pass_rate
            if args.min_pass_rate is not None
            else settings.eval_min_pass_rate
        )
        failed = False
        if rate < minimum:
            print(
                f"EVAL GATE FAILED: pass_rate={rate:.2f} < min={minimum:.2f}",
                file=sys.stderr,
            )
            failed = True

        baseline: dict[str, object] | None = None
        baseline_path = args.baseline
        if baseline_path is not None:
            baseline = load_baseline(baseline_path)
        elif args.write_baseline is None:
            try:
                baseline = load_baseline()
                baseline_path = Path("(bundled)")
            except FileNotFoundError:
                baseline = None

        if baseline is not None:
            regressions = compare_to_baseline(results, baseline)
            if regressions:
                print("BASELINE REGRESSIONS:", file=sys.stderr)
                for msg in regressions:
                    print(f"  - {msg}", file=sys.stderr)
                failed = True
            else:
                print(f"BASELINE OK ({baseline_path})", file=sys.stderr)

        if failed:
            raise SystemExit(1)
        print(f"EVAL GATE PASSED: pass_rate={rate:.2f}", file=sys.stderr)


if __name__ == "__main__":
    main()
