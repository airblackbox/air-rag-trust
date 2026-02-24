"""Unified RAG trust plugin — combines provenance, write gate, and drift detection.

This is the main entry point for integrating air-rag-trust into your application.
"""

from __future__ import annotations

import time
from typing import Any, Callable, Dict, List, Optional

from air_rag_trust.models import (
    AlertSeverity,
    DocumentRecord,
    DriftAlert,
    TrustLevel,
    WriteAction,
)
from air_rag_trust.provenance import ProvenanceTracker
from air_rag_trust.write_gate import WriteGate, WritePolicy, WriteDecision
from air_rag_trust.drift import DriftDetector, DriftConfig


class AirRagTrust:
    """Unified RAG trust layer — provenance, write gating, and drift detection.

    Usage:
        from air_rag_trust import AirRagTrust, WritePolicy, TrustLevel

        # Create with policy
        trust = AirRagTrust(
            write_policy=WritePolicy(
                allowed_sources=["internal://*", "https://docs.company.com/*"],
                blocked_content_patterns=[r"ignore previous instructions", r"system prompt"],
            )
        )

        # Gate and register a document
        result = trust.ingest("Document content here...", source="internal://kb/doc1.md")
        if result["allowed"]:
            print(f"Document {result['doc_id']} registered")

        # Record retrieval for drift monitoring
        trust.record_retrieval(
            query="What is our refund policy?",
            doc_ids=["doc-1", "doc-2"],
            sources=["internal://policies/refund.md"],
            trust_levels=["verified"],
        )

        # Check for anomalies
        alerts = trust.check_drift()

        # Export evidence for compliance
        evidence = trust.export_evidence()
    """

    def __init__(
        self,
        write_policy: Optional[WritePolicy] = None,
        drift_config: Optional[DriftConfig] = None,
        hmac_key: Optional[bytes] = None,
        default_trust: TrustLevel = TrustLevel.STANDARD,
    ):
        self._tracker = ProvenanceTracker(
            hmac_key=hmac_key,
            default_trust=default_trust,
        )
        self._gate = WriteGate(write_policy)
        self._drift = DriftDetector(drift_config)
        self._on_alert_callbacks: List[Callable[[DriftAlert], None]] = []

    @property
    def tracker(self) -> ProvenanceTracker:
        return self._tracker

    @property
    def gate(self) -> WriteGate:
        return self._gate

    @property
    def drift_detector(self) -> DriftDetector:
        return self._drift

    def on_alert(self, callback: Callable[[DriftAlert], None]) -> None:
        """Register a callback for drift alerts."""
        self._on_alert_callbacks.append(callback)

    def ingest(
        self,
        content: str,
        source: str,
        actor: str = "system",
        trust_level: Optional[TrustLevel] = None,
        metadata: Optional[Dict[str, Any]] = None,
        tags: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Gate-check and register a document. Returns result dict."""
        decision = self._gate.evaluate(
            content=content,
            source=source,
            actor=actor,
            action=WriteAction.ADD,
            trust_level=trust_level,
        )

        if not decision.allowed:
            return {
                "allowed": False,
                "reason": decision.reason,
                "flagged_patterns": decision.flagged_patterns,
                "requires_approval": decision.requires_approval,
            }

        if decision.requires_approval:
            return {
                "allowed": False,
                "reason": "Requires manual approval (untrusted source)",
                "requires_approval": True,
                "trust_level": decision.trust_level.value,
                "source": source,
            }

        record = self._tracker.register(
            content=content,
            source=source,
            trust_level=decision.trust_level,
            added_by=actor,
            metadata=metadata,
            tags=tags,
        )

        return {
            "allowed": True,
            "doc_id": record.doc_id,
            "content_hash": record.content_hash,
            "trust_level": record.trust_level.value,
        }

    def ingest_approved(
        self,
        content: str,
        source: str,
        actor: str = "system",
        trust_level: TrustLevel = TrustLevel.STANDARD,
        metadata: Optional[Dict[str, Any]] = None,
        tags: Optional[List[str]] = None,
    ) -> DocumentRecord:
        """Register a pre-approved document (bypasses write gate approval check)."""
        return self._tracker.register(
            content=content,
            source=source,
            trust_level=trust_level,
            added_by=actor,
            metadata=metadata,
            tags=tags,
        )

    def bulk_ingest(
        self,
        documents: List[Dict[str, Any]],
        actor: str = "system",
    ) -> Dict[str, Any]:
        """Ingest multiple documents with bulk policy check."""
        decision = self._gate.evaluate(
            content="bulk",
            source="bulk",
            actor=actor,
            action=WriteAction.BULK_IMPORT,
            batch_size=len(documents),
        )

        if not decision.allowed:
            return {
                "allowed": False,
                "reason": decision.reason,
                "total": len(documents),
                "ingested": 0,
            }

        results = []
        for doc in documents:
            result = self.ingest(
                content=doc.get("content", ""),
                source=doc.get("source", ""),
                actor=actor,
                trust_level=doc.get("trust_level"),
                metadata=doc.get("metadata"),
                tags=doc.get("tags"),
            )
            results.append(result)

        ingested = sum(1 for r in results if r.get("allowed"))
        return {
            "allowed": True,
            "total": len(documents),
            "ingested": ingested,
            "rejected": len(documents) - ingested,
            "results": results,
        }

    def record_retrieval(
        self,
        query: str,
        doc_ids: List[str],
        sources: List[str],
        trust_levels: Optional[List[str]] = None,
        agent_id: str = "",
    ) -> List[DriftAlert]:
        """Record a retrieval event and return any triggered alerts."""
        self._drift.record_retrieval(
            query=query,
            retrieved_doc_ids=doc_ids,
            retrieved_sources=sources,
            trust_levels=trust_levels,
            agent_id=agent_id,
        )

        alerts = self._drift.check()
        for alert in alerts:
            for cb in self._on_alert_callbacks:
                cb(alert)

        return alerts

    def check_drift(self) -> List[DriftAlert]:
        """Manually trigger drift detection checks."""
        return self._drift.check()

    def quarantine(self, doc_id: str, reason: str = "", actor: str = "system") -> bool:
        """Quarantine a document — removes it from retrievable set."""
        return self._tracker.quarantine(doc_id, reason, actor)

    def get_retrievable_ids(self):
        """Get the set of doc IDs safe for retrieval (excludes quarantined)."""
        return self._tracker.get_retrievable_doc_ids()

    def verify_chain(self) -> bool:
        """Verify tamper-evident audit chain integrity."""
        return self._tracker.verify_chain()

    def get_stats(self) -> Dict[str, Any]:
        return {
            "provenance": self._tracker.get_stats(),
            "drift": self._drift.get_stats(),
            "alerts": {
                "total": self._drift.alert_count,
                "critical": len(self._drift.get_alerts(AlertSeverity.CRITICAL)),
                "warning": len(self._drift.get_alerts(AlertSeverity.WARNING)),
            },
        }

    def export_evidence(self) -> Dict[str, Any]:
        """Export full compliance evidence bundle."""
        return {
            "provenance": self._tracker.export_provenance(),
            "drift_stats": self._drift.get_stats(),
            "drift_alerts": [a.to_dict() for a in self._drift.get_alerts()],
            "chain_valid": self._tracker.verify_chain(),
            "exported_at": time.time(),
        }
