"""Tests for ProvenanceTracker."""
import pytest
from air_rag_trust.provenance import ProvenanceTracker
from air_rag_trust.models import TrustLevel, WriteAction


class TestProvenanceTracker:
    def setup_method(self):
        self.tracker = ProvenanceTracker(hmac_key=b"test-key-123")

    def test_register(self):
        rec = self.tracker.register("doc content", source="test://doc1")
        assert rec.doc_id
        assert rec.content_hash
        assert self.tracker.document_count == 1
        assert self.tracker.chain_length == 1

    def test_register_duplicate_returns_existing(self):
        rec1 = self.tracker.register("same content", source="test://doc1")
        rec2 = self.tracker.register("same content", source="test://doc2")
        assert rec1.doc_id == rec2.doc_id
        assert self.tracker.document_count == 1
        # Chain has 2 entries (add + denied duplicate)
        assert self.tracker.chain_length == 2

    def test_register_different_content(self):
        self.tracker.register("content a", source="test://a")
        self.tracker.register("content b", source="test://b")
        assert self.tracker.document_count == 2

    def test_update(self):
        rec = self.tracker.register("original content here", source="test://doc1")
        old_hash = rec.content_hash
        updated = self.tracker.update(rec.doc_id, "modified content here", updated_by="editor")
        assert updated is not None
        assert updated.content_hash != old_hash
        assert updated.metadata["last_updated_by"] == "editor"

    def test_update_nonexistent(self):
        result = self.tracker.update("fake-id", "content")
        assert result is None

    def test_remove(self):
        rec = self.tracker.register("to delete", source="test://del")
        assert self.tracker.remove(rec.doc_id)
        assert self.tracker.document_count == 0
        assert self.tracker.get_document(rec.doc_id) is None

    def test_remove_nonexistent(self):
        assert not self.tracker.remove("fake-id")

    def test_quarantine(self):
        rec = self.tracker.register("suspicious", source="test://sus")
        assert self.tracker.quarantine(rec.doc_id, reason="Potential injection")
        doc = self.tracker.get_document(rec.doc_id)
        assert doc.trust_level == TrustLevel.QUARANTINED
        assert doc.metadata["quarantine_reason"] == "Potential injection"

    def test_quarantine_excludes_from_retrievable(self):
        rec1 = self.tracker.register("good doc", source="test://good")
        rec2 = self.tracker.register("bad doc", source="test://bad")
        self.tracker.quarantine(rec2.doc_id)
        retrievable = self.tracker.get_retrievable_doc_ids()
        assert rec1.doc_id in retrievable
        assert rec2.doc_id not in retrievable

    def test_verify_chain_valid(self):
        self.tracker.register("doc1", source="s1")
        self.tracker.register("doc2", source="s2")
        self.tracker.register("doc3", source="s3")
        assert self.tracker.verify_chain()

    def test_verify_chain_detects_tampering(self):
        self.tracker.register("doc1", source="s1")
        self.tracker.register("doc2", source="s2")
        # Tamper with chain
        self.tracker._write_chain[0].signature = "tampered"
        assert not self.tracker.verify_chain()

    def test_verify_empty_chain(self):
        assert self.tracker.verify_chain()

    def test_get_by_source(self):
        self.tracker.register("first document content", source="internal://kb/doc1.md")
        self.tracker.register("second document content", source="internal://kb/doc1.md")
        self.tracker.register("third document content", source="external://other")
        results = self.tracker.get_by_source("internal://kb/doc1.md")
        assert len(results) == 2  # Both registered (different content, same source)

    def test_get_by_trust_level(self):
        self.tracker.register("trusted doc", source="s1", trust_level=TrustLevel.VERIFIED)
        self.tracker.register("standard doc", source="s2")
        verified = self.tracker.get_by_trust_level(TrustLevel.VERIFIED)
        assert len(verified) == 1

    def test_get_write_history_filtered(self):
        rec = self.tracker.register("doc", source="s")
        self.tracker.register("other", source="s2")
        history = self.tracker.get_write_history(doc_id=rec.doc_id)
        assert len(history) == 1
        assert history[0].doc_id == rec.doc_id

    def test_get_stats(self):
        self.tracker.register("doc1", source="s1", trust_level=TrustLevel.VERIFIED)
        self.tracker.register("doc2", source="s2", trust_level=TrustLevel.UNTRUSTED)
        stats = self.tracker.get_stats()
        assert stats["total_documents"] == 2
        assert stats["chain_valid"]
        assert stats["trust_distribution"]["verified"] == 1
        assert stats["trust_distribution"]["untrusted"] == 1

    def test_export_provenance(self):
        self.tracker.register("doc1", source="s1")
        export = self.tracker.export_provenance()
        assert "documents" in export
        assert "write_chain" in export
        assert "stats" in export
        assert len(export["documents"]) == 1
