"""Write gate — controls who and what can add or modify documents in the knowledge base.

Enforces policies on document ingestion: source allowlists, trust level requirements,
content scanning, rate limits, and actor permissions.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set

from air_rag_trust.models import TrustLevel, WriteAction


@dataclass
class WritePolicy:
    """Policy configuration for the write gate."""
    # Source controls
    allowed_sources: List[str] = field(default_factory=list)
    blocked_sources: List[str] = field(default_factory=list)
    require_source: bool = True

    # Actor controls
    allowed_actors: List[str] = field(default_factory=list)
    blocked_actors: List[str] = field(default_factory=list)

    # Trust controls
    min_trust_for_auto_add: TrustLevel = TrustLevel.TRUSTED
    default_trust_for_unknown_source: TrustLevel = TrustLevel.UNTRUSTED

    # Content controls
    max_document_size_bytes: int = 1_000_000  # 1MB default
    min_content_length: int = 10
    blocked_content_patterns: List[str] = field(default_factory=list)

    # Rate controls
    max_writes_per_minute: int = 60
    max_bulk_import_size: int = 100

    # Approval
    require_approval_for_untrusted: bool = True
    require_approval_for_bulk: bool = True


@dataclass
class WriteDecision:
    """Result of a write gate evaluation."""
    allowed: bool
    action: WriteAction
    source: str
    actor: str
    trust_level: TrustLevel
    reason: str = ""
    requires_approval: bool = False
    flagged_patterns: List[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)


class WriteGate:
    """Enforces write policies on knowledge base modifications.

    Usage:
        policy = WritePolicy(allowed_sources=["internal://*", "https://docs.company.com/*"])
        gate = WriteGate(policy)

        decision = gate.evaluate(
            content="New document content...",
            source="internal://kb/new-doc.md",
            actor="data-pipeline",
            action=WriteAction.ADD,
        )

        if decision.allowed:
            tracker.register(content, source, ...)
    """

    def __init__(self, policy: Optional[WritePolicy] = None):
        self._policy = policy or WritePolicy()
        self._write_timestamps: List[float] = []
        self._custom_validators: List[Callable] = []

    @property
    def policy(self) -> WritePolicy:
        return self._policy

    def update_policy(self, policy: WritePolicy) -> None:
        self._policy = policy

    def add_validator(self, fn: Callable[[str, str, str], Optional[str]]) -> None:
        """Add a custom validation function.

        fn(content, source, actor) -> None if ok, or str reason if blocked.
        """
        self._custom_validators.append(fn)

    def evaluate(
        self,
        content: str,
        source: str,
        actor: str = "system",
        action: WriteAction = WriteAction.ADD,
        trust_level: Optional[TrustLevel] = None,
        batch_size: int = 1,
    ) -> WriteDecision:
        """Evaluate whether a write operation should be allowed."""
        p = self._policy
        effective_trust = trust_level or self._resolve_trust(source)

        # Check actor
        if p.blocked_actors and actor in p.blocked_actors:
            return WriteDecision(
                allowed=False, action=action, source=source,
                actor=actor, trust_level=effective_trust,
                reason=f"Actor '{actor}' is blocked by policy",
            )

        if p.allowed_actors and actor not in p.allowed_actors:
            return WriteDecision(
                allowed=False, action=action, source=source,
                actor=actor, trust_level=effective_trust,
                reason=f"Actor '{actor}' not in allowed list",
            )

        # Bulk imports are meta-checks — only actor + rate + batch size
        # Individual documents get full content/source checks separately
        if action == WriteAction.BULK_IMPORT:
            if batch_size > p.max_bulk_import_size:
                return WriteDecision(
                    allowed=False, action=action, source=source,
                    actor=actor, trust_level=effective_trust,
                    reason=f"Bulk import size {batch_size} exceeds limit {p.max_bulk_import_size}",
                )
            self._write_timestamps.append(time.time())
            return WriteDecision(
                allowed=True, action=action, source=source,
                actor=actor, trust_level=effective_trust,
                requires_approval=p.require_approval_for_bulk,
            )

        # Check source
        if p.require_source and not source:
            return WriteDecision(
                allowed=False, action=action, source=source,
                actor=actor, trust_level=effective_trust,
                reason="Source is required but not provided",
            )

        if p.blocked_sources and self._match_source(source, p.blocked_sources):
            return WriteDecision(
                allowed=False, action=action, source=source,
                actor=actor, trust_level=effective_trust,
                reason=f"Source '{source}' is blocked by policy",
            )

        if p.allowed_sources and not self._match_source(source, p.allowed_sources):
            return WriteDecision(
                allowed=False, action=action, source=source,
                actor=actor, trust_level=effective_trust,
                reason=f"Source '{source}' not in allowed list",
            )

        # Check content size
        content_bytes = len(content.encode("utf-8"))
        if content_bytes > p.max_document_size_bytes:
            return WriteDecision(
                allowed=False, action=action, source=source,
                actor=actor, trust_level=effective_trust,
                reason=f"Document size {content_bytes}B exceeds limit {p.max_document_size_bytes}B",
            )

        if len(content.strip()) < p.min_content_length:
            return WriteDecision(
                allowed=False, action=action, source=source,
                actor=actor, trust_level=effective_trust,
                reason=f"Content too short ({len(content.strip())} chars, min {p.min_content_length})",
            )

        # Check content patterns
        flagged = []
        for pattern in p.blocked_content_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                flagged.append(pattern)

        if flagged:
            return WriteDecision(
                allowed=False, action=action, source=source,
                actor=actor, trust_level=effective_trust,
                reason="Content matches blocked patterns",
                flagged_patterns=flagged,
            )

        # Check rate limits
        now = time.time()
        self._write_timestamps = [t for t in self._write_timestamps if now - t < 60]
        if len(self._write_timestamps) >= p.max_writes_per_minute:
            return WriteDecision(
                allowed=False, action=action, source=source,
                actor=actor, trust_level=effective_trust,
                reason=f"Rate limit exceeded ({p.max_writes_per_minute}/min)",
            )

        # Run custom validators
        for validator in self._custom_validators:
            result = validator(content, source, actor)
            if result is not None:
                return WriteDecision(
                    allowed=False, action=action, source=source,
                    actor=actor, trust_level=effective_trust,
                    reason=result,
                )

        # Check if approval is needed
        requires_approval = False
        if p.require_approval_for_untrusted and effective_trust == TrustLevel.UNTRUSTED:
            requires_approval = True
        if p.require_approval_for_bulk and action == WriteAction.BULK_IMPORT:
            requires_approval = True

        self._write_timestamps.append(now)

        return WriteDecision(
            allowed=True, action=action, source=source,
            actor=actor, trust_level=effective_trust,
            requires_approval=requires_approval,
        )

    def _resolve_trust(self, source: str) -> TrustLevel:
        """Determine trust level based on source."""
        p = self._policy
        if p.allowed_sources and self._match_source(source, p.allowed_sources):
            return p.min_trust_for_auto_add
        return p.default_trust_for_unknown_source

    @staticmethod
    def _match_source(source: str, patterns: List[str]) -> bool:
        for pattern in patterns:
            regex = pattern.replace("*", ".*")
            if re.match(regex, source, re.IGNORECASE):
                return True
        return False
