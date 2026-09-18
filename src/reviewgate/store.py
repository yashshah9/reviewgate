"""In-memory review store."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from threading import Lock

from reviewgate.scanner import (
    Finding,
    gate_decision,
    pr_comment,
    risk_score,
    scan_diff,
)


@dataclass
class ReviewResult:
    id: str
    repo: str
    pr_number: int | None
    title: str
    risk_score: float
    decision: str
    findings: list[Finding]
    comment: str
    created_at: float
    suppressed: list[str] = field(default_factory=list)


@dataclass
class ReviewStore:
    block_threshold: float = 0.7
    warn_threshold: float = 0.35
    reviews: list[ReviewResult] = field(default_factory=list)
    suppressions: set[str] = field(default_factory=set)
    _lock: Lock = field(default_factory=Lock)

    def clear(self) -> None:
        with self._lock:
            self.reviews.clear()
            self.suppressions.clear()

    def suppress(self, rule_ids: list[str]) -> list[str]:
        with self._lock:
            for rid in rule_ids:
                self.suppressions.add(rid)
            return sorted(self.suppressions)

    def review(
        self,
        *,
        diff: str,
        repo: str = "local/demo",
        pr_number: int | None = None,
        title: str = "",
    ) -> ReviewResult:
        with self._lock:
            suppress = set(self.suppressions)
        findings = scan_diff(diff, suppress=suppress)
        score = risk_score(findings)
        decision = gate_decision(
            score,
            block_threshold=self.block_threshold,
            warn_threshold=self.warn_threshold,
        )
        result = ReviewResult(
            id=str(uuid.uuid4()),
            repo=repo,
            pr_number=pr_number,
            title=title or f"review {repo}",
            risk_score=score,
            decision=decision,
            findings=findings,
            comment=pr_comment(findings, score, decision),
            created_at=time.time(),
            suppressed=sorted(suppress),
        )
        with self._lock:
            self.reviews.append(result)
            if len(self.reviews) > 500:
                self.reviews = self.reviews[-500:]
        return result

    def get(self, review_id: str) -> ReviewResult | None:
        with self._lock:
            for r in self.reviews:
                if r.id == review_id:
                    return r
        return None
