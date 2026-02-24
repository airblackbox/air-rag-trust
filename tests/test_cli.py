"""Tests for CLI."""
import json
import os
import tempfile
import pytest
from air_rag_trust.cli import main, scan_knowledge_base, run_audit


class TestScanKnowledgeBase:
    def test_scan_finds_files(self, tmp_path):
        (tmp_path / "doc1.md").write_text("# Doc 1")
        (tmp_path / "doc2.txt").write_text("Plain text doc")
        (tmp_path / "ignore.py").write_text("print('hello')")
        docs = scan_knowledge_base(str(tmp_path), [".md", ".txt"])
        assert len(docs) == 2

    def test_scan_excludes_git(self, tmp_path):
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        (git_dir / "config").write_text("git config")
        (tmp_path / "doc.md").write_text("# Real doc")
        docs = scan_knowledge_base(str(tmp_path), [".md"])
        assert len(docs) == 1

    def test_scan_empty_dir(self, tmp_path):
        docs = scan_knowledge_base(str(tmp_path), [".md"])
        assert len(docs) == 0

    def test_scan_nonexistent(self):
        docs = scan_knowledge_base("/nonexistent/path", [".md"])
        assert len(docs) == 0


class TestRunAudit:
    def test_audit_success(self, tmp_path):
        (tmp_path / "doc1.md").write_text("# First document content")
        (tmp_path / "doc2.md").write_text("# Second document content")
        result = run_audit(str(tmp_path), [".md"])
        assert "stats" in result
        assert result["stats"]["scanned_files"] == 2
        assert result["chain_valid"]

    def test_audit_with_duplicates(self, tmp_path):
        (tmp_path / "doc1.md").write_text("Same content")
        (tmp_path / "doc2.md").write_text("Same content")
        result = run_audit(str(tmp_path), [".md"])
        assert result["stats"]["duplicates_found"] >= 1

    def test_audit_verbose(self, tmp_path):
        (tmp_path / "doc.md").write_text("# Test document content here")
        result = run_audit(str(tmp_path), [".md"], verbose=True)
        assert len(result["documents"]) == 1
        assert "content_hash" in result["documents"][0]

    def test_audit_no_files(self, tmp_path):
        result = run_audit(str(tmp_path), [".md"])
        assert "error" in result


class TestCLI:
    def test_version(self, capsys):
        with pytest.raises(SystemExit) as exc:
            main(["--version"])
        assert exc.value.code == 0

    def test_json_output(self, tmp_path, capsys):
        (tmp_path / "doc.md").write_text("# Test document for JSON output")
        code = main([str(tmp_path), "--json"])
        assert code == 0
        output = capsys.readouterr().out
        data = json.loads(output)
        assert "stats" in data

    def test_no_files_returns_error(self, tmp_path):
        code = main([str(tmp_path)])
        assert code == 1
