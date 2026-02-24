"""Drift detector — monitors retrieval patterns for anomalies.

Detects when retrieval patterns shift: new sources appearing, trust level
distribution changes, volume spikes, and unusual doc access patterns.
These are indicators of RAG poisoning or knowledge base compromise.
"""

from __future__ import annotations

import time
from collections import Counter, deque
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, List, Optional, Set

from air_rag_trust.models import (
    AlertSeverity,
    DriftAlert,
    RetrievalEvent,
    TrustLevel,
)


@dataclass
class DriftConfig:
    """Configuration for drift detection thresholds."""
    # Window settings
    baseline_window_size: int = 100     # Number of retrievals for baseline
    detection_window_size: int = 20     # Recent window to compare

    # Alert thresholds
    new_source_alert: bool = True
    untrusted_ratio_threshold: float = 0.3    # Alert if >30% untrusted in window
    volume_spike_multiplier: float = 3.0      # Alert if 3x normal retrieval rate
    single_doc_dominance_threshold: float = 0.5  # Alert if one doc is >50% of retrievals
    new_doc_burst_threshold: int = 5          # Alert if >5 new docs in detection window

    # Time-based
    volume_window_seconds: float = 300.0      # 5-minute window for volume checks


@dataclass
class BaselineStats:
    """Statistical baseline for normal retrieval behavior."""
    source_distribution: Dict[str, float] = field(default_factory=dict)
    trust_distribution: Dict[str, float] = field(default_factory=dict)
    avg_retrievals_per_window: float = 0.0
    known_doc_ids: Set[str] = field(default_factory=set)
    known_sources: Set[str] = field(default_factory=set)
    total_retrievals: int = 0


class DriftDetector:
    """Monitors RAG retrieval patterns and alerts on anomalies.

    Usage:
        detector = DriftDetector()

        # Record retrievals
        detector.record_retrieval(
            query="What is our refund policy?",
            retrieved_doc_ids=["doc-1", "doc-2"],
            retrieved_sources=["internal://policies/refund.md", "internal://faq/returns.md"],
            trust_levels=["verified", "verified"],
        )

        # Check for alerts
        alerts = detector.check()
        for alert in alerts:
            print(f"[{alert.severity.value}] {alert.message}")
    """

    def __init__(self, config: Optional[DriftConfig] = None):
        self._config = config or DriftConfig()
        self._events: Deque[RetrievalEvent] = deque(
            maxlen=self._config.baseline_window_size + self._config.detection_window_size
        )
        self._baseline: Optional[BaselineStats] = None
        self._alerts: List[DriftAlert] = []
        self._all_known_doc_ids: Set[str] = set()
        self._all_known_sources: Set[str] = set()

    @property
    def alert_count(self) -> int:
        return len(self._alerts)

    def record_retrieval(
        self,
        query: str,
        retrieved_doc_ids: List[str],
        retrieved_sources: List[str],
        trust_levels: Optional[List[str]] = None,
        agent_id: str = "",
    ) -> None:
        """Record a retrieval event for drift monitoring."""
        event = RetrievalEvent(
            query_hash=RetrievalEvent.hash_query(query),
            retrieved_doc_ids=retrieved_doc_ids,
            retrieved_sources=retrieved_sources,
            agent_id=agent_id,
            trust_levels=trust_levels or [],
        )
        self._events.append(event)

        # Update known sets
        self._all_known_doc_ids.update(retrieved_doc_ids)
        self._all_known_sources.update(retrieved_sources)

        # Rebuild baseline if we have enough data
        if len(self._events) >= self._config.baseline_window_size:
            self._update_baseline()

    def check(self) -> List[DriftAlert]:
        """Run drift detection checks and return any new alerts."""
        if self._baseline is None or len(self._events) < self._config.baseline_window_size:
            return []

        new_alerts = []
        recent = list(self._events)[-self._config.detection_window_size:]

        # 1. New source detection
        if self._config.new_source_alert:
            alert = self._check_new_sources(recent)
            if alert:
                new_alerts.append(alert)

        # 2. Untrusted ratio check
        alert = self._check_untrusted_ratio(recent)
        if alert:
            new_alerts.append(alert)

        # 3. Volume spike
        alert = self._check_volume_spike()
        if alert:
            new_alerts.append(alert)

        # 4. Single doc dominance
        alert = self._check_doc_dominance(recent)
        if alert:
            new_alerts.append(alert)

        # 5. New doc burst
        alert = self._check_new_doc_burst(recent)
        if alert:
            new_alerts.append(alert)

        self._alerts.extend(new_alerts)
        return new_alerts

    def get_alerts(self, severity: Optional[AlertSeverity] = None) -> List[DriftAlert]:
        if severity:
            return [a for a in self._alerts if a.severity == severity]
        return list(self._alerts)

    def clear_alerts(self) -> int:
        count = len(self._alerts)
        self._alerts.clear()
        return count

    def get_baseline(self) -> Optional[BaselineStats]:
        return self._baseline

    def get_stats(self) -> Dict[str, Any]:
        recent = list(self._events)[-self._config.detection_window_size:]

        recent_sources = Counter()
        recent_trust = Counter()
        recent_docs = Counter()
        for ev in recent:
            for src in ev.retrieved_sources:
                recent_sources[src] += 1
            for tl in ev.trust_levels:
                recent_trust[tl] += 1
            for did in ev.retrieved_doc_ids:
                recent_docs[did] += 1

        return {
            "total_events": len(self._events),
            "baseline_built": self._baseline is not None,
            "known_doc_ids": len(self._all_known_doc_ids),
            "known_sources": len(self._all_known_sources),
            "alerts_total": len(self._alerts),
            "recent_window": {
                "events": len(recent),
                "top_sources": dict(recent_sources.most_common(5)),
                "trust_distribution": dict(recent_trust),
                "top_docs": dict(recent_docs.most_common(5)),
            },
        }

    def _update_baseline(self) -> None:
        baseline_events = list(self._events)[:self._config.baseline_window_size]

        source_counts: Counter = Counter()
        trust_counts: Counter = Counter()
        doc_ids: Set[str] = set()
        sources: Set[str] = set()

        for ev in baseline_events:
            for src in ev.retrieved_sources:
                source_counts[src] += 1
                sources.add(src)
            for tl in ev.trust_levels:
                trust_counts[tl] += 1
            doc_ids.update(ev.retrieved_doc_ids)

        total_source_hits = sum(source_counts.values()) or 1
        total_trust_hits = sum(trust_counts.values()) or 1

        self._baseline = BaselineStats(
            source_distribution={s: c / total_source_hits for s, c in source_counts.items()},
            trust_distribution={t: c / total_trust_hits for t, c in trust_counts.items()},
            avg_retrievals_per_window=len(baseline_events) / max(1, self._config.baseline_window_size),
            known_doc_ids=doc_ids,
            known_sources=sources,
            total_retrievals=len(baseline_events),
        )

    def _check_new_sources(self, recent: List[RetrievalEvent]) -> Optional[DriftAlert]:
        if not self._baseline:
            return None

        new_sources = set()
        for ev in recent:
            for src in ev.retrieved_sources:
                if src not in self._baseline.known_sources:
                    new_sources.add(src)

        if new_sources:
            return DriftAlert(
                severity=AlertSeverity.WARNING,
                alert_type="new_source",
                message=f"{len(new_sources)} new source(s) appeared in recent retrievals",
                details={"new_sources": list(new_sources)},
            )
        return None

    def _check_untrusted_ratio(self, recent: List[RetrievalEvent]) -> Optional[DriftAlert]:
        trust_counts: Counter = Counter()
        for ev in recent:
            for tl in ev.trust_levels:
                trust_counts[tl] += 1

        total = sum(trust_counts.values())
        if total == 0:
            return None

        untrusted_count = trust_counts.get("untrusted", 0) + trust_counts.get("quarantined", 0)
        ratio = untrusted_count / total

        if ratio > self._config.untrusted_ratio_threshold:
            return DriftAlert(
                severity=AlertSeverity.CRITICAL,
                alert_type="trust_shift",
                message=f"Untrusted content ratio {ratio:.0%} exceeds threshold {self._config.untrusted_ratio_threshold:.0%}",
                details={"untrusted_ratio": ratio, "trust_counts": dict(trust_counts)},
            )
        return None

    def _check_volume_spike(self) -> Optional[DriftAlert]:
        if not self._baseline:
            return None

        now = time.time()
        window = self._config.volume_window_seconds
        recent_count = sum(
            1 for ev in self._events if now - ev.timestamp < window
        )

        expected = self._baseline.avg_retrievals_per_window * (window / 60)
        if expected > 0 and recent_count > expected * self._config.volume_spike_multiplier:
            return DriftAlert(
                severity=AlertSeverity.WARNING,
                alert_type="volume_spike",
                message=f"Retrieval volume spike: {recent_count} in {window}s (expected ~{expected:.0f})",
                details={"recent_count": recent_count, "expected": expected},
            )
        return None

    def _check_doc_dominance(self, recent: List[RetrievalEvent]) -> Optional[DriftAlert]:
        doc_counts: Counter = Counter()
        for ev in recent:
            for did in ev.retrieved_doc_ids:
                doc_counts[did] += 1

        total = sum(doc_counts.values())
        if total == 0:
            return None

        top_doc, top_count = doc_counts.most_common(1)[0]
        ratio = top_count / total

        if ratio > self._config.single_doc_dominance_threshold:
            return DriftAlert(
                severity=AlertSeverity.WARNING,
                alert_type="doc_dominance",
                message=f"Single document '{top_doc}' dominates {ratio:.0%} of recent retrievals",
                details={"doc_id": top_doc, "ratio": ratio, "count": top_count},
            )
        return None

    def _check_new_doc_burst(self, recent: List[RetrievalEvent]) -> Optional[DriftAlert]:
        if not self._baseline:
            return None

        new_docs = set()
        for ev in recent:
            for did in ev.retrieved_doc_ids:
                if did not in self._baseline.known_doc_ids:
                    new_docs.add(did)

        if len(new_docs) > self._config.new_doc_burst_threshold:
            return DriftAlert(
                severity=AlertSeverity.CRITICAL,
                alert_type="new_doc_burst",
                message=f"{len(new_docs)} new documents appeared in recent retrievals (threshold: {self._config.new_doc_burst_threshold})",
                details={"new_doc_ids": list(new_docs), "count": len(new_docs)},
            )
        return None
