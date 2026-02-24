"""air-rag-trust — RAG provenance, write gating, and drift detection for AI agents.

EU AI Act compliance infrastructure for knowledge base integrity.
Part of the AIR Blackbox ecosystem.
"""

__version__ = "0.1.0"

from air_rag_trust.models import (
    AlertSeverity,
    DocumentRecord,
    DriftAlert,
    RetrievalEvent,
    TrustLevel,
    WriteAction,
    WriteEvent,
)
from air_rag_trust.provenance import ProvenanceTracker
from air_rag_trust.write_gate import WriteGate, WritePolicy, WriteDecision
from air_rag_trust.drift import DriftDetector, DriftConfig
from air_rag_trust.plugin import AirRagTrust

__all__ = [
    "AirRagTrust",
    "ProvenanceTracker",
    "WriteGate",
    "WritePolicy",
    "WriteDecision",
    "DriftDetector",
    "DriftConfig",
    "AlertSeverity",
    "DocumentRecord",
    "DriftAlert",
    "RetrievalEvent",
    "TrustLevel",
    "WriteAction",
    "WriteEvent",
]
