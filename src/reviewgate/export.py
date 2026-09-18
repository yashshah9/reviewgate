"""Export review findings to SARIF and GitHub Check Run payloads."""

from __future__ import annotations

from typing import Any

from reviewgate.__version__ import __version__
from reviewgate.scanner import Finding, Severity
from reviewgate.store import ReviewResult

_SARIF_LEVEL = {
    Severity.critical: "error",
    Severity.high: "error",
    Severity.medium: "warning",
    Severity.low: "note",
}

_CHECK_CONCLUSION = {
    "allow": "success",
    "warn": "neutral",
    "block": "failure",
}


def to_sarif(result: ReviewResult) -> dict[str, Any]:
    rules_seen: dict[str, Finding] = {}
    for f in result.findings:
        rules_seen.setdefault(f.rule_id, f)

    rules = [
        {
            "id": rid,
            "name": f.title,
            "shortDescription": {"text": f.title},
            "fullDescription": {"text": f.remediation},
            "defaultConfiguration": {"level": _SARIF_LEVEL[f.severity]},
            "properties": {"category": f.category, "severity": f.severity.value},
        }
        for rid, f in rules_seen.items()
    ]
    results = []
    for f in result.findings:
        loc: dict[str, Any] = {
            "physicalLocation": {
                "artifactLocation": {"uri": f.file},
            }
        }
        if f.line is not None:
            loc["physicalLocation"]["region"] = {
                "startLine": f.line,
                "snippet": {"text": f.excerpt},
            }
        results.append(
            {
                "ruleId": f.rule_id,
                "level": _SARIF_LEVEL[f.severity],
                "message": {"text": f"{f.title}: {f.excerpt}"},
                "locations": [loc],
                "fingerprints": {"reviewgate/v1": f.fingerprint},
            }
        )

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "reviewgate",
                        "version": __version__,
                        "informationUri": "https://github.com/yashshah9/reviewgate",
                        "rules": rules,
                    }
                },
                "results": results,
                "properties": {
                    "decision": result.decision,
                    "risk_score": result.risk_score,
                    "policy_pack": result.policy_pack,
                    "review_id": result.id,
                },
            }
        ],
    }


def to_check_run(result: ReviewResult, *, head_sha: str | None = None) -> dict[str, Any]:
    """GitHub Checks API–shaped payload (ready to POST to /repos/.../check-runs)."""
    conclusion = _CHECK_CONCLUSION.get(result.decision, "neutral")
    summary_lines = [
        f"**decision:** `{result.decision}`",
        f"**risk_score:** `{result.risk_score:.2f}`",
        f"**policy_pack:** `{result.policy_pack}`",
        f"**findings:** {len(result.findings)}",
        "",
        result.comment,
    ]
    annotations = []
    for f in result.findings[:50]:
        line = f.line if f.line is not None else 1
        level = {
            Severity.critical: "failure",
            Severity.high: "failure",
            Severity.medium: "warning",
            Severity.low: "notice",
        }[f.severity]
        annotations.append(
            {
                "path": f.file,
                "start_line": line,
                "end_line": line,
                "annotation_level": level,
                "title": f.title,
                "message": f"{f.excerpt}\n\n{f.remediation}",
            }
        )

    sha = (head_sha or "").strip() or "0" * 40
    return {
        "name": "reviewgate",
        "head_sha": sha,
        "status": "completed",
        "conclusion": conclusion,
        "output": {
            "title": f"reviewgate: {result.decision} (risk={result.risk_score:.2f})",
            "summary": "\n".join(summary_lines),
            "text": result.comment,
            "annotations": annotations,
        },
        "external_id": result.id,
    }
