"""Document provenance tracker — the core registry for RAG knowledge bases.

Tracks every document's origin, hash, trust level, and modification history.
Provides tamper-evident audit chain for all write operations.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from typing import Any, Dict, List, Optional, Set

from air_rag_trust.models import (
    DocumentRecord,
    DriftAlert,
    AlertSeverity,
    TrustLevel,
    WriteAction,
    WriteEvent,
)


class ProvenanceTracker:
    """Registry for document provenance with tamper-evident write audit chain.

    Usage:
        tracker = ProvenanceTracker()
        record = tracker.register("Some document content", source="internal://kb/doc1.md")
        tracker.verify_chain()  # True if no tampering
    """

    def __init__(
        self,
        hmac_key: Optional[bytes] = None,
        default_trust: TrustLevel = TrustLevel.STANDARD,
    ):
        self._hmac_key = hmac_key or os.urandom(32)
        self._default_trust = default_trust
        self._documents: Dict[str, DocumentRecord] = {}   # doc_id -> record
        self._hash_index: Dict[str, str] = {}              # content_hash -> doc_id
        self._source_index: Dict[str, Set[str]] = {}       # source -> set of doc_ids
        self._write_chain: List[WriteEvent] = []
        self._last_signature: str = ""

    @property
    def document_count(self) -> int:
        return len(self._documents)

    @property
    def chain_length(self) -> int:
        return len(self._write_chain)

    def register(
        self,
        content: str,
        source: str,
        trust_level: Optional[TrustLevel] = None,
        added_by: str = "system",
        metadata: Optional[Dict[str, Any]] = None,
        tags: Optional[List[str]] = None,
    ) -> DocumentRecord:
        """Register a new document and record provenance."""
        trust = trust_level or self._default_trust
        record = DocumentRecord.from_content(
            content=content,
            source=source,
            trust_level=trust,
            added_by=added_by,
            metadata=metadata,
            tags=tags,
        )

        # Check for duplicate content
        if record.content_hash in self._hash_index:
            existing_id = self._hash_index[record.content_hash]
            existing = self._documents[existing_id]
            event = WriteEvent(
                action=WriteAction.ADD,
                doc_id=record.doc_id,
                actor=added_by,
                source=source,
                trust_level=trust,
                allowed=False,
                deny_reason=f"Duplicate content (matches {existing_id})",
                content_hash=record.content_hash,
            )
            self._append_event(event)
            return existing

        # Store
        self._documents[record.doc_id] = record
        self._hash_index[record.content_hash] = record.doc_id
        self._source_index.setdefault(source, set()).add(record.doc_id)

        # Audit
        event = WriteEvent(
            action=WriteAction.ADD,
            doc_id=record.doc_id,
            actor=added_by,
            source=source,
            trust_level=trust,
            allowed=True,
            content_hash=record.content_hash,
        )
        self._append_event(event)
        return record

    def update(
        self,
        doc_id: str,
        new_content: str,
        updated_by: str = "system",
    ) -> Optional[DocumentRecord]:
        """Update an existing document's content and re-hash."""
        if doc_id not in self._documents:
            return None

        record = self._documents[doc_id]
        old_hash = record.content_hash

        # Remove old hash index
        if old_hash in self._hash_index:
            del self._hash_index[old_hash]

        # Update
        record.content_hash = DocumentRecord.hash_content(new_content)
        record.size_bytes = len(new_content.encode("utf-8"))
        record.metadata["last_updated_by"] = updated_by
        record.metadata["last_updated_at"] = time.time()
        record.metadata["previous_hash"] = old_hash

        self._hash_index[record.content_hash] = doc_id

        event = WriteEvent(
            action=WriteAction.UPDATE,
            doc_id=doc_id,
            actor=updated_by,
            source=record.source,
            trust_level=record.trust_level,
            allowed=True,
            content_hash=record.content_hash,
        )
        self._append_event(event)
        return record

    def remove(self, doc_id: str, removed_by: str = "system") -> bool:
        """Remove a document from the registry."""
        if doc_id not in self._documents:
            return False

        record = self._documents[doc_id]

        # Clean up indexes
        if record.content_hash in self._hash_index:
            del self._hash_index[record.content_hash]
        if record.source in self._source_index:
            self._source_index[record.source].discard(doc_id)

        del self._documents[doc_id]

        event = WriteEvent(
            action=WriteAction.DELETE,
            doc_id=doc_id,
            actor=removed_by,
            source=record.source,
            trust_level=record.trust_level,
            allowed=True,
            content_hash=record.content_hash,
        )
        self._append_event(event)
        return True

    def quarantine(self, doc_id: str, reason: str = "", quarantined_by: str = "system") -> bool:
        """Move a document to quarantine — excluded from retrieval."""
        if doc_id not in self._documents:
            return False

        record = self._documents[doc_id]
        record.trust_level = TrustLevel.QUARANTINED
        record.metadata["quarantine_reason"] = reason
        record.metadata["quarantined_by"] = quarantined_by
        record.metadata["quarantined_at"] = time.time()

        event = WriteEvent(
            action=WriteAction.UPDATE,
            doc_id=doc_id,
            actor=quarantined_by,
            source=record.source,
            trust_level=TrustLevel.QUARANTINED,
            allowed=True,
            content_hash=record.content_hash,
        )
        self._append_event(event)
        return True

    def get_document(self, doc_id: str) -> Optional[DocumentRecord]:
        return self._documents.get(doc_id)

    def get_by_source(self, source: str) -> List[DocumentRecord]:
        doc_ids = self._source_index.get(source, set())
        return [self._documents[did] for did in doc_ids if did in self._documents]

    def get_by_trust_level(self, trust_level: TrustLevel) -> List[DocumentRecord]:
        return [d for d in self._documents.values() if d.trust_level == trust_level]

    def get_retrievable_doc_ids(self) -> Set[str]:
        """Return doc IDs that are NOT quarantined (safe for retrieval)."""
        return {
            did for did, doc in self._documents.items()
            if doc.trust_level != TrustLevel.QUARANTINED
        }

    def verify_chain(self) -> bool:
        """Verify the integrity of the entire write audit chain."""
        if not self._write_chain:
            return True

        prev_hash = ""
        for event in self._write_chain:
            payload = json.dumps({
                "event_id": event.event_id,
                "action": event.action.value,
                "doc_id": event.doc_id,
                "actor": event.actor,
                "timestamp": event.timestamp,
                "content_hash": event.content_hash,
                "allowed": event.allowed,
                "prev_hash": prev_hash,
            }, sort_keys=True)
            expected = hmac.new(
                self._hmac_key, payload.encode(), hashlib.sha256
            ).hexdigest()
            if event.signature != expected:
                return False
            prev_hash = event.signature

        return True

    def get_write_history(self, doc_id: Optional[str] = None) -> List[WriteEvent]:
        if doc_id:
            return [e for e in self._write_chain if e.doc_id == doc_id]
        return list(self._write_chain)

    def get_stats(self) -> Dict[str, Any]:
        trust_counts = {}
        for doc in self._documents.values():
            key = doc.trust_level.value
            trust_counts[key] = trust_counts.get(key, 0) + 1

        return {
            "total_documents": len(self._documents),
            "unique_sources": len(self._source_index),
            "write_chain_length": len(self._write_chain),
            "chain_valid": self.verify_chain(),
            "trust_distribution": trust_counts,
            "quarantined_count": trust_counts.get("quarantined", 0),
        }

    def export_provenance(self) -> Dict[str, Any]:
        """Export full provenance data for compliance evidence."""
        return {
            "documents": [d.to_dict() for d in self._documents.values()],
            "write_chain": [e.to_dict() for e in self._write_chain],
            "stats": self.get_stats(),
            "exported_at": time.time(),
        }

    def _append_event(self, event: WriteEvent) -> None:
        event.sign(self._hmac_key, self._last_signature)
        self._last_signature = event.signature
        self._write_chain.append(event)
