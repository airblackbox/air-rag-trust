# air-rag-trust

**EU AI Act compliance infrastructure for RAG knowledge bases** — Document provenance tracking, write gating, and drift detection that makes your retrieval-augmented generation pipeline compliant with Articles 10, 11, 12, and 15.

Part of the [AIR Blackbox](https://github.com/airblackbox) ecosystem.

> The EU AI Act enforcement date for high-risk AI systems is **August 2, 2026**. If your agents retrieve documents and take actions based on them, you need provenance and integrity controls. [See full compliance mapping →](docs/eu-ai-act-compliance.md)

## The Problem

RAG poisoning is a persistence attack: an attacker injects malicious documents into your knowledge base, and every future query returns attacker-controlled content. Unlike prompt injection (which is transient), RAG poisoning **persists until the document is removed**.

`air-rag-trust` adds three layers of defense:

1. **Provenance Tracking** — Every document gets a SHA-256 hash, source attribution, trust classification, and tamper-evident audit chain (HMAC-SHA256).
2. **Write Gating** — Policy-based controls on who/what can add or modify documents. Source allowlists, content pattern blocking, rate limits, and actor permissions.
3. **Drift Detection** — Monitors retrieval patterns and alerts on anomalies: new sources, trust level shifts, volume spikes, document dominance, and new document bursts.

## Quick Start

```bash
pip install air-rag-trust
```

```python
from air_rag_trust import AirRagTrust, WritePolicy, TrustLevel

# Create trust layer with write policy
trust = AirRagTrust(
    write_policy=WritePolicy(
        allowed_sources=["internal://*", "https://docs.company.com/*"],
        blocked_content_patterns=[r"ignore previous instructions", r"system prompt"],
    )
)

# Gate-check and register a document
result = trust.ingest(
    "Our refund policy allows returns within 30 days...",
    source="internal://policies/refund.md",
    actor="data-pipeline",
)

if result["allowed"]:
    print(f"Document {result['doc_id']} registered (trust: {result['trust_level']})")

# Record retrievals for drift monitoring
trust.record_retrieval(
    query="What is our refund policy?",
    doc_ids=[result["doc_id"]],
    sources=["internal://policies/refund.md"],
    trust_levels=["standard"],
)

# Check for anomalies
alerts = trust.check_drift()
for alert in alerts:
    print(f"[{alert.severity.value}] {alert.message}")

# Verify audit chain integrity
assert trust.verify_chain()

# Export compliance evidence
evidence = trust.export_evidence()
```

## CLI

Scan a knowledge base directory for provenance auditing:

```bash
# Audit current directory
air-rag-trust .

# Audit specific path with verbose output
air-rag-trust /path/to/knowledge-base --verbose

# JSON output for CI pipelines
air-rag-trust /path/to/kb --json

# Custom file extensions
air-rag-trust /path/to/kb -e .md .txt .pdf
```

## Write Gate Policies

Control what enters your knowledge base:

```python
from air_rag_trust import WritePolicy, TrustLevel

policy = WritePolicy(
    # Source controls
    allowed_sources=["internal://*", "https://docs.company.com/*"],
    blocked_sources=["https://untrusted.com/*"],
    require_source=True,

    # Actor controls
    allowed_actors=["data-pipeline", "admin", "content-team"],

    # Content controls
    max_document_size_bytes=1_000_000,
    blocked_content_patterns=[
        r"ignore previous instructions",
        r"you are now",
        r"system prompt",
        r"<script>",
    ],

    # Rate controls
    max_writes_per_minute=60,
    max_bulk_import_size=100,

    # Trust
    min_trust_for_auto_add=TrustLevel.TRUSTED,
    require_approval_for_untrusted=True,
)
```

## Drift Detection

Monitor retrieval patterns for signs of knowledge base compromise:

```python
from air_rag_trust import DriftConfig

config = DriftConfig(
    baseline_window_size=100,           # Retrievals for baseline
    detection_window_size=20,           # Recent window to compare
    new_source_alert=True,              # Alert on new sources
    untrusted_ratio_threshold=0.3,      # Alert if >30% untrusted
    volume_spike_multiplier=3.0,        # Alert on 3x volume
    single_doc_dominance_threshold=0.5, # Alert if one doc >50%
    new_doc_burst_threshold=5,          # Alert on burst of new docs
)
```

Alert types:

| Alert | Severity | Indicates |
|---|---|---|
| `new_source` | Warning | Previously unseen source in retrievals |
| `trust_shift` | Critical | Untrusted content ratio exceeds threshold |
| `volume_spike` | Warning | Abnormal retrieval volume |
| `doc_dominance` | Warning | Single document dominates retrievals |
| `new_doc_burst` | Critical | Many new documents appear suddenly |

## EU AI Act Compliance Coverage

| Article | Requirement | air-rag-trust Feature |
|---|---|---|
| **Art. 10** — Data Governance | Data quality and governance practices | Write gating, source allowlists, content validation |
| **Art. 11** — Technical Documentation | System documentation and audit trails | Provenance records, tamper-evident chain |
| **Art. 12** — Record-Keeping | Automatic event logging | HMAC-SHA256 audit chain, write event history |
| **Art. 15** — Robustness | Resilience against manipulation | Drift detection, pattern blocking, quarantine |

## API Reference

```python
# Unified plugin
trust = AirRagTrust(write_policy=..., drift_config=...)
trust.ingest(content, source, actor)     # Gate-check + register
trust.ingest_approved(content, source)   # Bypass gate (pre-approved)
trust.bulk_ingest(documents, actor)      # Batch ingestion
trust.record_retrieval(query, doc_ids, sources, trust_levels)
trust.check_drift()                      # Manual drift check
trust.quarantine(doc_id, reason)         # Exclude from retrieval
trust.get_retrievable_ids()              # Safe doc IDs
trust.verify_chain()                     # Audit chain integrity
trust.get_stats()                        # Combined statistics
trust.export_evidence()                  # Compliance evidence bundle
trust.on_alert(callback)                 # Register alert handler

# Individual components also available
from air_rag_trust import ProvenanceTracker, WriteGate, DriftDetector
```

## AIR Blackbox Ecosystem

| Package | Framework | Install |
|---|---|---|
| [air-langchain-trust](https://github.com/airblackbox/air-langchain-trust) | LangChain / LangGraph | `pip install air-langchain-trust` |
| [air-crewai-trust](https://github.com/airblackbox/trust-crewai) | CrewAI | `pip install air-crewai-trust` |
| [air-openai-agents-trust](https://github.com/airblackbox/trust-openai-agents) | OpenAI Agents SDK | `pip install air-openai-agents-trust` |
| [air-autogen-trust](https://github.com/airblackbox/trust-autogen) | AutoGen / AG2 | `pip install air-autogen-trust` |
| [openclaw-air-trust](https://github.com/airblackbox/trust-openclaw) | TypeScript / Node.js | `npm install openclaw-air-trust` |
| **air-rag-trust** | **RAG Knowledge Bases** (this repo) | `pip install air-rag-trust` |
| [air-compliance](https://pypi.org/project/air-compliance/) | Compliance Scanner | `pip install air-compliance` |
| [Gateway](https://github.com/airblackbox/air-blackbox-gateway) | Any HTTP agent | `docker pull ghcr.io/airblackbox/gateway:main` |

## Development

```bash
git clone https://github.com/airblackbox/air-rag-trust.git
cd air-rag-trust
pip install -e ".[dev]"
pytest tests/ -v
```

## License

Apache-2.0
