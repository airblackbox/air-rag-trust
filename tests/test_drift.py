"""Tests for DriftDetector."""
import pytest
from air_rag_trust.drift import DriftDetector, DriftConfig
from air_rag_trust.models import AlertSeverity


def _build_baseline(detector, n=100):
    """Helper to populate baseline with n normal retrievals."""
    for i in range(n):
        detector.record_retrieval(
            query=f"query {i}",
            retrieved_doc_ids=[f"doc-{i % 10}"],
            retrieved_sources=[f"internal://kb/doc-{i % 10}.md"],
            trust_levels=["verified"],
        )


class TestDriftDetector:
    def test_no_alerts_without_baseline(self):
        detector = DriftDetector()
        detector.record_retrieval("q", ["d1"], ["s1"], ["verified"])
        alerts = detector.check()
        assert alerts == []

    def test_baseline_builds_after_window(self):
        config = DriftConfig(baseline_window_size=10, detection_window_size=5)
        detector = DriftDetector(config)
        for i in range(10):
            detector.record_retrieval(f"q{i}", [f"d{i%3}"], [f"s{i%3}"], ["verified"])
        assert detector.get_baseline() is not None

    def test_new_source_alert(self):
        config = DriftConfig(baseline_window_size=20, detection_window_size=5)
        detector = DriftDetector(config)
        _build_baseline(detector, 20)

        # Introduce a new source
        for i in range(5):
            detector.record_retrieval(
                f"new query {i}",
                [f"new-doc-{i}"],
                ["https://evil.com/payload"],
                ["untrusted"],
            )

        alerts = detector.check()
        source_alerts = [a for a in alerts if a.alert_type == "new_source"]
        assert len(source_alerts) >= 1
        assert "evil.com" in str(source_alerts[0].details)

    def test_untrusted_ratio_alert(self):
        config = DriftConfig(
            baseline_window_size=20,
            detection_window_size=10,
            untrusted_ratio_threshold=0.3,
        )
        detector = DriftDetector(config)
        _build_baseline(detector, 20)

        # Flood with untrusted
        for i in range(10):
            detector.record_retrieval(
                f"q{i}", [f"d{i}"], [f"s{i}"], ["untrusted"],
            )

        alerts = detector.check()
        trust_alerts = [a for a in alerts if a.alert_type == "trust_shift"]
        assert len(trust_alerts) >= 1
        assert trust_alerts[0].severity == AlertSeverity.CRITICAL

    def test_doc_dominance_alert(self):
        config = DriftConfig(
            baseline_window_size=20,
            detection_window_size=10,
            single_doc_dominance_threshold=0.5,
        )
        detector = DriftDetector(config)
        _build_baseline(detector, 20)

        # One doc dominates
        for i in range(10):
            detector.record_retrieval(
                f"q{i}", ["suspicious-doc-99"], ["internal://s"], ["standard"],
            )

        alerts = detector.check()
        dom_alerts = [a for a in alerts if a.alert_type == "doc_dominance"]
        assert len(dom_alerts) >= 1

    def test_new_doc_burst_alert(self):
        config = DriftConfig(
            baseline_window_size=20,
            detection_window_size=10,
            new_doc_burst_threshold=3,
        )
        detector = DriftDetector(config)
        _build_baseline(detector, 20)

        # Burst of new documents
        for i in range(10):
            detector.record_retrieval(
                f"q{i}", [f"brand-new-doc-{i}"], ["internal://s"], ["standard"],
            )

        alerts = detector.check()
        burst_alerts = [a for a in alerts if a.alert_type == "new_doc_burst"]
        assert len(burst_alerts) >= 1
        assert burst_alerts[0].severity == AlertSeverity.CRITICAL

    def test_no_false_positive_normal_usage(self):
        config = DriftConfig(baseline_window_size=50, detection_window_size=10)
        detector = DriftDetector(config)

        # Normal usage with consistent patterns
        for i in range(60):
            detector.record_retrieval(
                f"query {i}",
                [f"doc-{i % 5}"],
                [f"internal://kb/doc-{i % 5}.md"],
                ["verified"],
            )

        alerts = detector.check()
        # Should have no alerts for consistent patterns
        critical = [a for a in alerts if a.severity == AlertSeverity.CRITICAL]
        assert len(critical) == 0

    def test_get_stats(self):
        detector = DriftDetector()
        detector.record_retrieval("q1", ["d1"], ["s1"], ["verified"])
        stats = detector.get_stats()
        assert stats["total_events"] == 1
        assert stats["known_doc_ids"] == 1

    def test_clear_alerts(self):
        config = DriftConfig(baseline_window_size=20, detection_window_size=5)
        detector = DriftDetector(config)
        _build_baseline(detector, 20)

        for i in range(5):
            detector.record_retrieval(f"q{i}", [f"new-{i}"], ["https://evil.com"], ["untrusted"])
        detector.check()

        assert detector.alert_count > 0
        cleared = detector.clear_alerts()
        assert cleared > 0
        assert detector.alert_count == 0

    def test_get_alerts_by_severity(self):
        config = DriftConfig(baseline_window_size=20, detection_window_size=10)
        detector = DriftDetector(config)
        _build_baseline(detector, 20)

        for i in range(10):
            detector.record_retrieval(f"q{i}", [f"new-{i}"], ["https://evil.com"], ["untrusted"])
        detector.check()

        critical = detector.get_alerts(AlertSeverity.CRITICAL)
        warning = detector.get_alerts(AlertSeverity.WARNING)
        assert len(critical) + len(warning) == detector.alert_count
