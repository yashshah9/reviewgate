"""Golden eval suite for reviewgate scanners."""

from __future__ import annotations

import json
from dataclasses import dataclass
from importlib import resources
from pathlib import Path

from reviewgate.scanner import gate_decision, risk_score, scan_diff


@dataclass
class EvalCase:
    id: str
    diff: str
    expect_decision: str | None = None
    must_find_rule: str | None = None
    must_not_find_rule: str | None = None
    min_risk: float | None = None
    max_risk: float | None = None


@dataclass
class EvalResult:
    case: EvalCase
    passed: bool
    reason: str
    decision: str
    risk: float
    rule_ids: list[str]


def load_cases(path: Path | None = None) -> list[EvalCase]:
    if path is not None:
        raw = json.loads(path.read_text())
    else:
        packaged = resources.files("reviewgate").joinpath("data/cases.json")
        raw = json.loads(packaged.read_text())
    return [
        EvalCase(
            id=c["id"],
            diff=c["diff"],
            expect_decision=c.get("expect_decision"),
            must_find_rule=c.get("must_find_rule"),
            must_not_find_rule=c.get("must_not_find_rule"),
            min_risk=c.get("min_risk"),
            max_risk=c.get("max_risk"),
        )
        for c in raw["cases"]
    ]


def run_case(
    case: EvalCase,
    *,
    block_threshold: float = 0.7,
    warn_threshold: float = 0.35,
) -> EvalResult:
    findings = scan_diff(case.diff)
    risk = risk_score(findings)
    decision = gate_decision(
        risk, block_threshold=block_threshold, warn_threshold=warn_threshold
    )
    rule_ids = [f.rule_id for f in findings]

    if case.expect_decision and decision != case.expect_decision:
        return EvalResult(case, False, "decision_mismatch", decision, risk, rule_ids)
    if case.must_find_rule and case.must_find_rule not in rule_ids:
        return EvalResult(case, False, "missing_rule", decision, risk, rule_ids)
    if case.must_not_find_rule and case.must_not_find_rule in rule_ids:
        return EvalResult(case, False, "unexpected_rule", decision, risk, rule_ids)
    if case.min_risk is not None and risk < case.min_risk:
        return EvalResult(case, False, "risk_too_low", decision, risk, rule_ids)
    if case.max_risk is not None and risk > case.max_risk:
        return EvalResult(case, False, "risk_too_high", decision, risk, rule_ids)
    return EvalResult(case, True, "ok", decision, risk, rule_ids)


def run_eval(
    cases: list[EvalCase],
    *,
    block_threshold: float = 0.7,
    warn_threshold: float = 0.35,
) -> list[EvalResult]:
    return [
        run_case(c, block_threshold=block_threshold, warn_threshold=warn_threshold)
        for c in cases
    ]


def run_golden_suite(
    *,
    block_threshold: float = 0.7,
    warn_threshold: float = 0.35,
) -> tuple[list[EvalResult], float]:
    cases = load_cases()
    results = run_eval(cases, block_threshold=block_threshold, warn_threshold=warn_threshold)
    rate = sum(1 for r in results if r.passed) / len(results) if results else 0.0
    return results, rate


def resolve_baseline_path(path: Path | None = None) -> Path:
    if path is not None:
        return path
    bundled = Path(__file__).resolve().parent / "data" / "baseline.json"
    if bundled.is_file():
        return bundled
    repo = Path(__file__).resolve().parents[2] / "evals" / "baseline.json"
    if repo.is_file():
        return repo
    docker = Path("/app/evals/baseline.json")
    if docker.is_file():
        return docker
    raise FileNotFoundError("evals/baseline.json not found")


def snapshot_from_results(results: list[EvalResult], *, pass_rate: float) -> dict[str, object]:
    return {
        "pass_rate": round(pass_rate, 4),
        "cases": {
            r.case.id: {
                "passed": r.passed,
                "reason": r.reason,
                "decision": r.decision,
                "risk_score": round(r.risk, 4),
                "rule_ids": sorted(r.rule_ids),
            }
            for r in results
        },
    }


def write_baseline(path: Path, results: list[EvalResult], *, pass_rate: float) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(snapshot_from_results(results, pass_rate=pass_rate), indent=2) + "\n",
        encoding="utf-8",
    )


def load_baseline(path: Path | None = None) -> dict[str, object]:
    raw: object = json.loads(resolve_baseline_path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise TypeError("baseline root must be an object")
    return raw


def compare_to_baseline(results: list[EvalResult], baseline: dict[str, object]) -> list[str]:
    """Return regression messages (empty = ok)."""
    regressions: list[str] = []
    prior_cases = baseline.get("cases", {})
    if not isinstance(prior_cases, dict):
        return ["baseline.cases missing or invalid"]
    current = {r.case.id: r for r in results}
    for case_id, prior in prior_cases.items():
        if not isinstance(prior, dict):
            continue
        now = current.get(str(case_id))
        if now is None:
            regressions.append(f"{case_id}: missing from current suite")
            continue
        if prior.get("passed") is True and not now.passed:
            regressions.append(f"{case_id}: was pass, now fail ({now.reason})")
            continue
        prior_decision = prior.get("decision")
        if (
            prior.get("passed") is True
            and prior_decision
            and now.decision != prior_decision
        ):
            regressions.append(
                f"{case_id}: decision changed {prior_decision!r} → {now.decision!r}"
            )
    return regressions
