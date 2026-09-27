"""Tests for Recommendation Engine Integration & Affected Session Linkage."""

import pytest
from analysis.feature_extraction.models import Finding
from analysis.integration.pipeline import build_recommendations
from analysis.rule_engine.severity import Confidence, Severity


def test_empty_findings_returns_positive_guidance():
    recs = build_recommendations([])
    assert len(recs) == 1
    assert recs[0]["priority"] == "LOW"
    assert "hygiene" in recs[0]["title"].lower()
    assert recs[0]["affected_sessions"] == []


def test_plaintext_finding_generates_critical_recommendation():
    finding = Finding(
        finding_id="f1",
        session_id="session-imap-1",
        finding_type="PLAINTEXT",
        severity=Severity.CRITICAL,
        title="Plaintext email traffic",
        description="Traffic observed without encryption",
        confidence=Confidence.OBSERVED,
        evidence={},
    )
    recs = build_recommendations([finding])
    assert len(recs) >= 1
    # Check that affected session is linked
    pt_rec = next((r for r in recs if "plaintext" in r["title"].lower() or "tls" in r["title"].lower()), None)
    assert pt_rec is not None
    assert "session-imap-1" in pt_rec["affected_sessions"]


def test_multi_session_affected_sessions_merged():
    findings = [
        Finding(
            finding_id="f1",
            session_id="smtp-01",
            finding_type="DEPRECATED_TLS",
            severity=Severity.HIGH,
            title="Deprecated TLS",
            description="TLS 1.0 used",
            confidence=Confidence.OBSERVED,
            evidence={"tls_version": "TLS 1.0"},
        ),
        Finding(
            finding_id="f2",
            session_id="smtp-02",
            finding_type="DEPRECATED_TLS",
            severity=Severity.HIGH,
            title="Deprecated TLS",
            description="TLS 1.0 used",
            confidence=Confidence.OBSERVED,
            evidence={"tls_version": "TLS 1.0"},
        ),
    ]
    recs = build_recommendations(findings)
    dep_rec = next((r for r in recs if "tls" in r["title"].lower()), None)
    assert dep_rec is not None
    assert "smtp-01" in dep_rec["affected_sessions"]
    assert "smtp-02" in dep_rec["affected_sessions"]


def test_priority_ordering():
    findings = [
        Finding(
            finding_id="f1",
            session_id="s1",
            finding_type="PFS",
            severity=Severity.INFO,
            title="Forward secrecy",
            description="PFS observed",
            confidence=Confidence.OBSERVED,
            evidence={},
        ),
        Finding(
            finding_id="f2",
            session_id="s2",
            finding_type="PLAINTEXT",
            severity=Severity.CRITICAL,
            title="Plaintext",
            description="Plaintext observed",
            confidence=Confidence.OBSERVED,
            evidence={},
        ),
    ]
    recs = build_recommendations(findings)
    # The critical/high priority must appear before lower priority
    priorities = [r["priority"] for r in recs]
    assert priorities[0] in ["CRITICAL", "HIGH"]
