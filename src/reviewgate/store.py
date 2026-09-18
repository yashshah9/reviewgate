"""In-memory review store with latency traces."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from threading import Lock
from typing import Any

from reviewgate.policy import get_pack
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
    policy_pack: str = "default"
    latency_ms: int = 0
    suppressed: list[str] = field(default_factory=list)


@dataclass
class ReviewTrace:
    review_id: str
    repo: str
    decision: str
    risk_score: float
    finding_count: int
    latency_ms: int
    policy_pack: str


@dataclass
class ReviewStore:
    block_threshold: float = 0.7
    warn_threshold: float = 0.35
    reviews: list[ReviewResult] = field(default_factory=list)
    traces: list[ReviewTrace] = field(default_factory=list)
    suppressions: set[str] = field(default_factory=set)
    backend: Any | None = None
    _lock: Lock = field(default_factory=Lock)

    def load(self) -> int:
        if self.backend is None:
            return 0
        loaded = self.backend.load_recent(limit=500)
        with self._lock:
            self.reviews = list(loaded)
            self.traces = [
                ReviewTrace(
                    review_id=r.id,
                    repo=r.repo,
                    decision=r.decision,
                    risk_score=r.risk_score,
                    finding_count=len(r.findings),
                    latency_ms=r.latency_ms,
                    policy_pack=r.policy_pack,
                )
                for r in loaded
            ]
        return len(loaded)

    def clear(self) -> None:
        with self._lock:
            self.reviews.clear()
            self.traces.clear()
            self.suppressions.clear()
        if self.backend is not None:
            self.backend.clear()

    def suppress(self, ids: list[str]) -> list[str]:
        """Suppress by rule id and/or finding fingerprint."""
        with self._lock:
            for item in ids:
                self.suppressions.add(item)
            return sorted(self.suppressions)

    def review(
        self,
        *,
        diff: str,
        repo: str = "local/demo",
        pr_number: int | None = None,
        title: str = "",
        policy_pack: str = "default",
    ) -> ReviewResult:
        started = time.perf_counter()
        pack = get_pack(policy_pack)
        with self._lock:
            suppress = set(self.suppressions)
        findings = scan_diff(diff, suppress=suppress, rules=list(pack.rules))
        score = risk_score(findings)
        decision = gate_decision(
            score,
            block_threshold=self.block_threshold,
            warn_threshold=self.warn_threshold,
        )
        latency_ms = int((time.perf_counter() - started) * 1000)
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
            policy_pack=pack.id,
            latency_ms=latency_ms,
            suppressed=sorted(suppress),
        )
        trace = ReviewTrace(
            review_id=result.id,
            repo=repo,
            decision=decision,
            risk_score=score,
            finding_count=len(findings),
            latency_ms=latency_ms,
            policy_pack=pack.id,
        )
        with self._lock:
            self.reviews.append(result)
            self.traces.append(trace)
            if len(self.reviews) > 500:
                self.reviews = self.reviews[-500:]
            if len(self.traces) > 500:
                self.traces = self.traces[-500:]
        if self.backend is not None:
            self.backend.save_review(result)
        return result

    def get(self, review_id: str) -> ReviewResult | None:
        with self._lock:
            for r in self.reviews:
                if r.id == review_id:
                    return r
        if self.backend is not None:
            found: ReviewResult | None = self.backend.get_review(review_id)
            if found is not None:
                with self._lock:
                    if not any(r.id == found.id for r in self.reviews):
                        self.reviews.append(found)
                return found
        return None
