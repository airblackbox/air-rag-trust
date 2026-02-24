"""CLI for RAG provenance auditing and knowledge base health checks."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import List

from air_rag_trust import __version__
from air_rag_trust.models import TrustLevel
from air_rag_trust.provenance import ProvenanceTracker


# ANSI colors
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


def scan_knowledge_base(path: str, extensions: List[str]) -> List[dict]:
    """Scan a directory for knowledge base documents."""
    docs = []
    base = Path(path)

    if not base.exists():
        return docs

    exclude_dirs = {".git", "node_modules", "__pycache__", ".venv", "dist", "build", ".tox"}

    for root, dirs, files in os.walk(base):
        dirs[:] = [d for d in dirs if d not in exclude_dirs]
        for f in files:
            if any(f.endswith(ext) for ext in extensions):
                filepath = Path(root) / f
                try:
                    content = filepath.read_text(encoding="utf-8", errors="ignore")
                    rel_path = filepath.relative_to(base)
                    docs.append({
                        "path": str(rel_path),
                        "content": content,
                        "size": len(content.encode("utf-8")),
                    })
                except Exception:
                    pass

    return docs


def run_audit(path: str, extensions: List[str], verbose: bool = False) -> dict:
    """Scan a knowledge base directory and produce a provenance audit."""
    tracker = ProvenanceTracker()

    docs = scan_knowledge_base(path, extensions)
    if not docs:
        return {"error": f"No documents found in {path} with extensions {extensions}"}

    duplicates = 0
    for doc in docs:
        source = f"file://{doc['path']}"
        record = tracker.register(
            content=doc["content"],
            source=source,
            trust_level=TrustLevel.STANDARD,
            added_by="cli-scan",
        )
        # Check if we got back an existing record (duplicate)
        if record.source != source:
            duplicates += 1

    stats = tracker.get_stats()
    stats["scanned_files"] = len(docs)
    stats["duplicates_found"] = duplicates
    stats["path"] = path
    stats["extensions"] = extensions

    return {
        "stats": stats,
        "documents": [
            {
                "doc_id": d.doc_id,
                "source": d.source,
                "content_hash": d.content_hash[:16] + "...",
                "trust_level": d.trust_level.value,
                "size_bytes": d.size_bytes,
            }
            for d in tracker._documents.values()
        ] if verbose else [],
        "chain_valid": tracker.verify_chain(),
    }


def print_report(result: dict) -> None:
    """Print a formatted audit report."""
    if "error" in result:
        print(f"\n{RED}Error:{RESET} {result['error']}")
        return

    stats = result["stats"]

    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}  AIR RAG Trust — Knowledge Base Audit{RESET}")
    print(f"{BOLD}{'='*60}{RESET}\n")

    print(f"  Path:         {stats['path']}")
    print(f"  Extensions:   {', '.join(stats['extensions'])}")
    print(f"  Files scanned: {stats['scanned_files']}")
    print(f"  Unique docs:  {stats['total_documents']}")
    print(f"  Duplicates:   {stats['duplicates_found']}")
    print(f"  Sources:      {stats['unique_sources']}")
    print(f"  Chain length: {stats['write_chain_length']}")

    chain_ok = result["chain_valid"]
    chain_str = f"{GREEN}VALID{RESET}" if chain_ok else f"{RED}BROKEN{RESET}"
    print(f"  Chain status: {chain_str}")

    trust_dist = stats.get("trust_distribution", {})
    if trust_dist:
        print(f"\n  {BOLD}Trust Distribution:{RESET}")
        for level, count in sorted(trust_dist.items()):
            color = GREEN if level in ("verified", "trusted") else YELLOW if level == "standard" else RED
            print(f"    {color}{level:15s}{RESET} {count}")

    if result.get("documents"):
        print(f"\n  {BOLD}Documents:{RESET}")
        for doc in result["documents"]:
            trust = doc["trust_level"]
            color = GREEN if trust in ("verified", "trusted") else YELLOW
            print(f"    {color}[{trust:10s}]{RESET} {doc['source']} ({doc['size_bytes']}B) {CYAN}{doc['content_hash']}{RESET}")

    print(f"\n{BOLD}{'='*60}{RESET}\n")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="air-rag-trust",
        description="RAG knowledge base provenance audit and health check",
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Path to knowledge base directory (default: current directory)",
    )
    parser.add_argument(
        "--extensions", "-e",
        nargs="+",
        default=[".md", ".txt", ".pdf", ".json", ".yaml", ".yml", ".csv"],
        help="File extensions to scan",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Show individual documents")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--version", action="version", version=f"air-rag-trust {__version__}")

    args = parser.parse_args(argv)

    result = run_audit(args.path, args.extensions, verbose=args.verbose)

    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        print_report(result)

    if "error" in result:
        return 1
    if not result.get("chain_valid", True):
        return 2
    return 0
