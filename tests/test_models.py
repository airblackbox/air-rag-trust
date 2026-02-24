"""Tests for core data models."""
import pytest
from air_rag_trust.models import (
    TrustLevel, WriteAction, AlertSeverity,
    DocumentRecord, WriteEvent, RetrievalEvent, DriftAlert,
)


class TestTrustLevel:
    def test_values(self):
        assert TrustLevel.VERIFIED.value == "verified"
        assert TrustLevel.QUARANTINED.value == "quarantined"

    def test_all_levels(self):
        assert len(TrustLevel) == 5


class TestDocumentRecord:
    def test_from_content(self):
        rec = DocumentRecord.from_content("hello world", source="test://doc1")
        assert rec.content_hash == DocumentRecord.hash_content("hello world")
        assert rec.source == "test://doc1"
        assert rec.trust_level == TrustLevel.STANDARD
        assert rec.size_bytes == len("hello world".encode())

    def test_hash_deterministic(self):
        h1 = DocumentRecord.hash_content("same content")
        h2 = DocumentRecord.hash_content("same content")
        assert h1 == h2

    def test_hash_different(self):
        h1 = DocumentRecord.hash_content("content a")
        h2 = DocumentRecord.hash_content("content b")
        assert h1 != h2

    def test_to_dict(self):
        rec = DocumentRecord.from_content("test", source="s", trust_level=TrustLevel.VERIFIED)
        d = rec.to_dict()
        assert d["trust_level"] == "verified"
        assert "content_hash" in d

    def test_custom_metadata(self):
        rec = DocumentRecord.from_content(
            "test", source="s",
            metadata={"version": "1.0"},
            tags=["policy", "internal"],
        )
        assert rec.metadata["version"] == "1.0"
        assert "policy" in rec.tags


class TestWriteEvent:
    def test_sign(self):
        event = WriteEvent(action=WriteAction.ADD, doc_id="d1", actor="user1")
        sig = event.sign(b"testkey", prev_hash="")
        assert sig
        assert event.signature == sig

    def test_chain(self):
        e1 = WriteEvent(action=WriteAction.ADD, doc_id="d1")
        sig1 = e1.sign(b"key", "")
        e2 = WriteEvent(action=WriteAction.ADD, doc_id="d2")
        sig2 = e2.sign(b"key", sig1)
        assert sig1 != sig2
        assert e2.prev_hash == sig1

    def test_to_dict(self):
        event = WriteEvent(action=WriteAction.DELETE, trust_level=TrustLevel.UNTRUSTED)
        d = event.to_dict()
        assert d["action"] == "delete"
        assert d["trust_level"] == "untrusted"


class TestRetrievalEvent:
    def test_hash_query(self):
        h = RetrievalEvent.hash_query("test query")
        assert len(h) == 64  # SHA-256 hex


class TestDriftAlert:
    def test_to_dict(self):
        alert = DriftAlert(severity=AlertSeverity.CRITICAL, alert_type="test", message="msg")
        d = alert.to_dict()
        assert d["severity"] == "critical"
        assert d["alert_type"] == "test"
