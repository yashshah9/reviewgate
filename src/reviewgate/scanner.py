"""Deterministic security / policy scanners for unified diffs."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from enum import StrEnum


class Severity(StrEnum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"


SEVERITY_WEIGHT: dict[Severity, float] = {
    Severity.critical: 1.0,
    Severity.high: 0.75,
    Severity.medium: 0.4,
    Severity.low: 0.15,
}


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: Severity
    category: str
    pattern: re.Pattern[str]
    remediation: str


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    category: str
    file: str
    line: int | None
    excerpt: str
    remediation: str
    fingerprint: str = ""


# Added lines only (unified diff): track path + line numbers
_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
_FILE = re.compile(r"^\+\+\+ b/(.+)$")

RULES: list[Rule] = [
    Rule(
        id="secret-aws-key",
        title="Hardcoded AWS access key",
        severity=Severity.critical,
        category="secrets",
        pattern=re.compile(r"AKIA[0-9A-Z]{16}"),
        remediation="Remove the key; use a secrets manager or env var.",
    ),
    Rule(
        id="secret-generic-api-key",
        title="Hardcoded API key / token assignment",
        severity=Severity.critical,
        category="secrets",
        pattern=re.compile(
            r"(?i)(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token)\s*=\s*['\"][^'\"]{8,}['\"]"
        ),
        remediation="Do not commit credentials; load from environment or a vault.",
    ),
    Rule(
        id="secret-private-key",
        title="Private key material in diff",
        severity=Severity.critical,
        category="secrets",
        pattern=re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        remediation="Never commit private keys; rotate if already exposed.",
    ),
    Rule(
        id="inj-sql-format",
        title="Possible SQL injection via string format",
        severity=Severity.high,
        category="injection",
        pattern=re.compile(
            r"(?i)(execute|executemany|raw)\s*\(\s*(f['\"]|['\"].*\%|['\"].*\.format\()"
        ),
        remediation="Use parameterized queries / bound parameters.",
    ),
    Rule(
        id="inj-sql-fstring",
        title="SQL built with f-string",
        severity=Severity.high,
        category="injection",
        pattern=re.compile(r"(?i)(SELECT|INSERT|UPDATE|DELETE).+\{[^}]+\}"),
        remediation="Avoid interpolating user input into SQL; use parameters.",
    ),
    Rule(
        id="authz-allow-all",
        title="Permissive authorization / allow-all",
        severity=Severity.high,
        category="authz",
        pattern=re.compile(r"(?i)(allow_all\s*=\s*True|AUTHZ_DISABLED\s*=\s*True|if\s+True:\s*#\s*auth)"),
        remediation="Remove bypasses; enforce authz checks on every sensitive path.",
    ),
    Rule(
        id="authz-skip-check",
        title="Skipped authorization check",
        severity=Severity.high,
        category="authz",
        pattern=re.compile(r"(?i)#\s*(skip|bypass|disable)\s*(auth|authz|permission)"),
        remediation="Do not ship auth bypass comments; gate behind proper roles.",
    ),
    Rule(
        id="danger-eval",
        title="Use of eval/exec on untrusted input",
        severity=Severity.high,
        category="dangerous",
        pattern=re.compile(r"(?<![A-Za-z0-9_])(eval|exec)\s*\("),
        remediation="Avoid eval/exec; use safe parsers or AST-based alternatives.",
    ),
    Rule(
        id="danger-pickle",
        title="Unsafe pickle.loads",
        severity=Severity.high,
        category="dangerous",
        pattern=re.compile(r"pickle\.loads?\s*\("),
        remediation="Do not unpickle untrusted data; use JSON or a typed schema.",
    ),
    Rule(
        id="danger-shell-true",
        title="subprocess with shell=True",
        severity=Severity.medium,
        category="dangerous",
        pattern=re.compile(r"subprocess\.(run|Popen|call)\([^)]*shell\s*=\s*True"),
        remediation="Pass argv lists and keep shell=False.",
    ),
    Rule(
        id="policy-debug-true",
        title="Debug mode enabled",
        severity=Severity.medium,
        category="policy",
        pattern=re.compile(r"(?i)(DEBUG\s*=\s*True|app\.run\([^)]*debug\s*=\s*True)"),
        remediation="Disable debug in production configs.",
    ),
    Rule(
        id="policy-http-url",
        title="Insecure HTTP URL for credentials/callback",
        severity=Severity.low,
        category="policy",
        pattern=re.compile(r"http://[^\s'\"]+(token|secret|callback|oauth)", re.I),
        remediation="Use HTTPS for any URL that carries secrets or auth callbacks.",
    ),
]


def added_lines(diff: str) -> list[tuple[str, int | None, str]]:
    """Return (path, new_line_no, text) for added lines in a unified diff."""
    path = "unknown"
    line_no: int | None = None
    out: list[tuple[str, int | None, str]] = []
    for raw in diff.splitlines():
        m_file = _FILE.match(raw)
        if m_file:
            path = m_file.group(1).strip()
            line_no = None
            continue
        m_hunk = _HUNK.match(raw)
        if m_hunk:
            line_no = int(m_hunk.group(1))
            continue
        if raw.startswith("+") and not raw.startswith("+++"):
            out.append((path, line_no, raw[1:]))
            if line_no is not None:
                line_no += 1
        elif raw.startswith("-") and not raw.startswith("---"):
            continue
        elif line_no is not None and not raw.startswith("\\"):
            # context line advances new-file counter when present in hunk
            if raw.startswith(" ") or raw == "":
                line_no += 1
    return out


def finding_fingerprint(*, rule_id: str, file: str, excerpt: str) -> str:
    raw = f"{rule_id}|{file}|{excerpt}".encode()
    return hashlib.sha256(raw).hexdigest()[:16]


def scan_diff(
    diff: str,
    *,
    suppress: set[str] | None = None,
    rules: list[Rule] | None = None,
) -> list[Finding]:
    suppress = suppress or set()
    active = rules if rules is not None else RULES
    findings: list[Finding] = []
    for path, line_no, text in added_lines(diff):
        for rule in active:
            if rule.id in suppress:
                continue
            if rule.pattern.search(text):
                excerpt = text.strip()[:200]
                fp = finding_fingerprint(rule_id=rule.id, file=path, excerpt=excerpt)
                if fp in suppress:
                    continue
                findings.append(
                    Finding(
                        rule_id=rule.id,
                        title=rule.title,
                        severity=rule.severity,
                        category=rule.category,
                        file=path,
                        line=line_no,
                        excerpt=excerpt,
                        remediation=rule.remediation,
                        fingerprint=fp,
                    )
                )
    return findings


def risk_score(findings: list[Finding]) -> float:
    if not findings:
        return 0.0
    # ponytail: diminishing sum capped at 1.0; upgrade to calibrated model later
    total = 0.0
    ordered = sorted(findings, key=lambda x: SEVERITY_WEIGHT[x.severity], reverse=True)
    for i, f in enumerate(ordered):
        total += SEVERITY_WEIGHT[f.severity] * (0.55**i)
    return round(min(1.0, total), 4)


def gate_decision(score: float, *, block_threshold: float, warn_threshold: float) -> str:
    if score >= block_threshold:
        return "block"
    if score >= warn_threshold:
        return "warn"
    return "allow"


def pr_comment(findings: list[Finding], score: float, decision: str) -> str:
    lines = [
        f"## reviewgate — decision: **{decision}** (risk={score:.2f})",
        "",
    ]
    if not findings:
        lines.append("No policy or security findings on added lines.")
        return "\n".join(lines)
    lines.append("| Severity | Rule | File | Excerpt |")
    lines.append("|----------|------|------|---------|")
    for f in findings[:20]:
        loc = f"{f.file}:{f.line}" if f.line is not None else f.file
        excerpt = f.excerpt.replace("|", "\\|")[:80]
        lines.append(f"| {f.severity.value} | `{f.rule_id}` | `{loc}` | `{excerpt}` |")
    if len(findings) > 20:
        lines.append(f"\n_…and {len(findings) - 20} more._")
    return "\n".join(lines)
