"""Core data models for RAG provenance tracking."""

from __future__ import annotations

import enum
import hashlib
import hmac
import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


class TrustLevel(enum.Enum):
    """Trust classification for documents in the knowledge base."""
    VERIFIED = "verified"       # Manually reviewed and approved
    TRUSTED = "trusted"         # From a trusted source, not manually reviewed
    STANDARD = "standard"       # Default level for normal ingestion
    UNTRUSTED = "untrusted"     # External/unknown source
    QUARANTINED = "quarantined" # Flagged for review, excluded from retrieval


class WriteAction(enum.Enum):
    """Types of write operations on the knowledge base."""
    ADD = "add"
    UPDATE = "update"
    DELETE = "delete"
    BULK_IMPORT = "bulk_import"


class AlertSeverity(enum.Enum):
    """Severity levels for drift alerts."""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass
class DocumentRecord:
    """Provenance record for a single document in the knowledge base."""
    doc_id: str
    content_hash: str               # SHA-256 of document content
    source: str                      # Origin URL, file path, or identifier
    trust_level: TrustLevel = TrustLevel.STANDARD
    added_by: str = "system"         # Identity of who/what added the doc
    added_at: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    size_bytes: int = 0
    chunk_count: int = 1

    @staticmethod
    def hash_content(content: str) -> str:
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["trust_level"] = self.trust_level.value
        return d

    @classmethod
    def from_content(
        cls,
        content: str,
        source: str,
        trust_level: TrustLevel = TrustLevel.STANDARD,
        added_by: str = "system",
        metadata: Optional[Dict[str, Any]] = None,
        tags: Optional[List[str]] = None,
    ) -> "DocumentRecord":
        return cls(
            doc_id=str(uuid.uuid4()),
            content_hash=cls.hash_content(content),
            source=source,
            trust_level=trust_level,
            added_by=added_by,
            metadata=metadata or {},
            tags=tags or [],
            size_bytes=len(content.encode("utf-8")),
        )


@dataclass
class WriteEvent:
    """Audit record for a write operation on the knowledge base."""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    action: WriteAction = WriteAction.ADD
    doc_id: str = ""
    actor: str = "system"
    timestamp: float = field(default_factory=time.time)
    source: str = ""
    trust_level: TrustLevel = TrustLevel.STANDARD
    allowed: bool = True
    deny_reason: str = ""
    content_hash: str = ""
    prev_hash: str = ""           # HMAC chain: previous event's signature
    signature: str = ""           # HMAC-SHA256 of this event

    def sign(self, key: bytes, prev_hash: str = "") -> str:
        self.prev_hash = prev_hash
        payload = json.dumps({
            "event_id": self.event_id,
            "action": self.action.value,
            "doc_id": self.doc_id,
            "actor": self.actor,
            "timestamp": self.timestamp,
            "content_hash": self.content_hash,
            "allowed": self.allowed,
            "prev_hash": self.prev_hash,
        }, sort_keys=True)
        self.signature = hmac.new(key, payload.encode(), hashlib.sha256).hexdigest()
        return self.signature

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["action"] = self.action.value
        d["trust_level"] = self.trust_level.value
        return d


@dataclass
class RetrievalEvent:
    """Record of a retrieval (query) against the knowledge base."""
    query_hash: str                  # SHA-256 of the query text
    retrieved_doc_ids: List[str]
    retrieved_sources: List[str]
    timestamp: float = field(default_factory=time.time)
    agent_id: str = ""
    trust_levels: List[str] = field(default_factory=list)

    @staticmethod
    def hash_query(query: str) -> str:
        return hashlib.sha256(query.encode("utf-8")).hexdigest()


@dataclass
class DriftAlert:
    """Alert generated when retrieval patterns deviate from baseline."""
    alert_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    severity: AlertSeverity = AlertSeverity.WARNING
    alert_type: str = ""             # e.g., "new_source", "trust_shift", "volume_spike"
    message: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d
