"""Policy packs — select / filter / extend scanner rules."""

from __future__ import annotations

import re
from dataclasses import dataclass

from reviewgate.scanner import RULES, Rule, Severity


@dataclass(frozen=True)
class PolicyPack:
    id: str
    description: str
    rules: tuple[Rule, ...]


def _filter(
    *,
    pack_id: str,
    description: str,
    categories: set[str] | None = None,
    severities: set[Severity] | None = None,
    disable: set[str] | None = None,
) -> PolicyPack:
    disable = disable or set()
    selected: list[Rule] = []
    for rule in RULES:
        if rule.id in disable:
            continue
        if categories is not None and rule.category not in categories:
            continue
        if severities is not None and rule.severity not in severities:
            continue
        selected.append(rule)
    return PolicyPack(id=pack_id, description=description, rules=tuple(selected))


PACKS: dict[str, PolicyPack] = {
    "default": PolicyPack(
        id="default",
        description="All built-in secrets, injection, authz, dangerous, and policy rules",
        rules=tuple(RULES),
    ),
    "secrets": _filter(
        pack_id="secrets",
        description="Secrets only",
        categories={"secrets"},
    ),
    "security": _filter(
        pack_id="security",
        description="Secrets, injection, authz, and dangerous APIs (no soft policy)",
        categories={"secrets", "injection", "authz", "dangerous"},
    ),
    "strict": _filter(
        pack_id="strict",
        description="Critical and high severity only",
        severities={Severity.critical, Severity.high},
    ),
}


def get_pack(pack_id: str) -> PolicyPack:
    pack = PACKS.get(pack_id)
    if pack is None:
        known = ", ".join(sorted(PACKS))
        raise KeyError(f"unknown policy pack {pack_id!r}; known: {known}")
    return pack


def list_packs() -> list[dict[str, object]]:
    return [
        {
            "id": p.id,
            "description": p.description,
            "rule_count": len(p.rules),
            "rule_ids": [r.id for r in p.rules],
        }
        for p in PACKS.values()
    ]


def compile_extra_rule(
    *,
    rule_id: str,
    title: str,
    severity: str,
    category: str,
    pattern: str,
    remediation: str,
) -> Rule:
    return Rule(
        id=rule_id,
        title=title,
        severity=Severity(severity),
        category=category,
        pattern=re.compile(pattern),
        remediation=remediation,
    )
