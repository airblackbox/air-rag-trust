# Contributing to air-rag-trust

Thanks for your interest in contributing! This package adds provenance tracking, write gating, and drift detection to RAG knowledge bases for EU AI Act compliance.

## Quick Setup

```bash
git clone https://github.com/airblackbox/air-rag-trust.git
cd air-rag-trust
pip install -e ".[dev]"
pytest tests/ -v
```

All 75 tests should pass. Zero external dependencies — only Python stdlib.

## How to Contribute

**Bug reports** — Open an issue with a minimal reproduction showing the unexpected behavior.

**Write gate bypasses** — If you find a way to get malicious content past the write gate, that's a security issue — please report it.

**Drift detection** — False positives or missed anomalies in the drift detector are high-value reports.

**New detection patterns** — If you encounter RAG poisoning techniques the write gate doesn't catch, open an issue or PR with examples.

**Documentation** — README improvements, docstring fixes, and usage examples are always welcome.

## Pull Request Process

1. Fork the repo and create a branch from `main`
2. Make your changes
3. Run `ruff check air_rag_trust/ --select E,F --ignore E501,F541` — must pass clean
4. Run `pytest tests/ -v` — all tests must pass
5. Open a PR with a clear description of what changed and why

## Code Style

- We use [ruff](https://github.com/astral-sh/ruff) for linting (rules: E, F)
- Zero external dependencies — keep it that way
- Write tests for any new patterns or features

## License

By contributing, you agree that your contributions will be licensed under the Apache 2.0 License.
