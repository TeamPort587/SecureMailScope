"""Tests for Isolation Forest Anomaly Detection module."""

import pytest
from analysis.anomaly_detection.feature_schema import (
    ALL_IF_FEATURES,
    IF_FEATURE_COUNT,
    ANOMALY_STATUS_COMPLETE,
    ANOMALY_STATUS_UNAVAILABLE,
    ANOMALY_STATUS_INSUFFICIENT,
    ANOMALY_STATUS_ERROR,
)
from analysis.anomaly_detection.feature_extractor import extract_anomaly_features
from analysis.anomaly_detection.service import (
    analyze_session_anomaly,
    aggregate_anomaly_results,
    _get_predictor,
)
from analysis.feature_extraction.models import (
    Finding,
    SecurityProfile,
    Session,
    PacketRecord,
    TLSInfo,
)


def _make_dummy_session(protocol="SMTP", port=587, completeness="COMPLETE"):
    p1 = PacketRecord(
        frame_number=1,
        timestamp=1000.0,
        src_ip="10.0.0.1",
        src_port=45000,
        dst_ip="10.0.0.2",
        dst_port=port,
        tcp_stream=0,
        protocol="TCP",
        tcp_flags_syn=True,
    )
    p2 = PacketRecord(
        frame_number=2,
        timestamp=1002.5,
        src_ip="10.0.0.1",
        src_port=45000,
        dst_ip="10.0.0.2",
        dst_port=port,
        tcp_stream=0,
        protocol="TCP",
        tcp_flags_fin=True,
    )
    session = Session(
        session_id="test-session-001",
        tcp_stream=0,
        client_ip="10.0.0.1",
        client_port=45000,
        server_ip="10.0.0.2",
        server_port=port,
        protocol=protocol,
        service="submission",
        completeness=completeness,
        first_frame=1,
        last_frame=2,
        packet_count=2,
        packets=[p1, p2],
        client_packets=[p1],
        server_packets=[p2],
    )
    profile = SecurityProfile(
        session_id="test-session-001",
        protocol=protocol,
        service="submission",
        client_ip="10.0.0.1",
        server_ip="10.0.0.2",
        client_port=45000,
        server_port=port,
    )
    profile.security.encryption_mode = "STARTTLS"
    profile.security.upgrade_advertised = "YES"
    profile.security.upgrade_requested = "YES"
    profile.security.upgrade_succeeded = "YES"
    profile.security.authentication_before_tls = "NO"
    profile.security.capture_completeness = completeness
    profile.tls = TLSInfo(version="TLS 1.3", cipher_suite="TLS_AES_256_GCM_SHA384", pfs="YES")

    return session, profile


def test_feature_extractor_returns_all_features():
    session, profile = _make_dummy_session()
    findings = []
    features = extract_anomaly_features(session, profile, findings)

    assert isinstance(features, dict)
    assert len(features) == IF_FEATURE_COUNT
    for name in ALL_IF_FEATURES:
        assert name in features, f"Missing feature {name}"
        assert isinstance(features[name], (int, float)), f"Feature {name} not numeric"


def test_feature_extractor_with_findings():
    session, profile = _make_dummy_session()
    findings = [
        Finding(
            finding_id="f-1",
            session_id=profile.session_id,
            finding_type="DEPRECATED_TLS",
            severity="HIGH",
            title="Deprecated TLS",
            description="TLS 1.0 used",
            confidence="OBSERVED",
            evidence={},
        ),
        Finding(
            finding_id="f-2",
            session_id=profile.session_id,
            finding_type="PLAINTEXT",
            severity="CRITICAL",
            title="Plaintext traffic",
            description="No TLS",
            confidence="OBSERVED",
            evidence={},
        ),
    ]
    features = extract_anomaly_features(session, profile, findings)
    assert features["if_high_sev_count"] >= 1
    assert features["if_finding_count"] == 2


def test_service_analyze_session_anomaly():
    session, profile = _make_dummy_session()
    findings = []

    res = analyze_session_anomaly(session, profile, findings)

    assert "session_id" in res
    assert res["session_id"] == profile.session_id
    assert "anomaly" in res

    anomaly = res["anomaly"]
    assert anomaly["status"] in (ANOMALY_STATUS_COMPLETE, ANOMALY_STATUS_UNAVAILABLE)
    if anomaly["status"] == ANOMALY_STATUS_COMPLETE:
        assert "classification" in anomaly
        assert anomaly["classification"] in ("ANOMALOUS", "WITHIN_BASELINE")
        assert isinstance(anomaly["is_anomalous"], bool)
        assert isinstance(anomaly["raw_score"], float)
        assert isinstance(anomaly["decision_score"], float)
        assert "explanation" in anomaly
        exp = anomaly["explanation"]
        assert "summary" in exp
        assert "deviations" in exp
        assert "related_findings" in exp
        assert "limitations" in exp


def test_service_failure_isolation():
    # Calling analyze_session_anomaly with invalid types should not raise an unhandled exception
    res = analyze_session_anomaly(None, None, [])
    assert res["anomaly"]["status"] in (ANOMALY_STATUS_ERROR, ANOMALY_STATUS_UNAVAILABLE)
    assert "explanation" in res["anomaly"]


def test_aggregate_anomaly_results():
    results = [
        {
            "session_id": "s1",
            "anomaly": {
                "status": "COMPLETE",
                "classification": "WITHIN_BASELINE",
                "is_anomalous": False,
            },
        },
        {
            "session_id": "s2",
            "anomaly": {
                "status": "COMPLETE",
                "classification": "ANOMALOUS",
                "is_anomalous": True,
            },
        },
        {
            "session_id": "s3",
            "anomaly": {
                "status": "INSUFFICIENT_EVIDENCE",
                "classification": None,
                "is_anomalous": None,
            },
        },
    ]

    agg = aggregate_anomaly_results(results)

    assert agg["total_sessions"] == 3
    assert agg["anomalous_count"] == 1
    assert agg["within_baseline_count"] == 1
    assert agg["insufficient_evidence_count"] == 1
    assert agg["overall_status"] == "ANOMALIES_DETECTED"
    assert agg["anomalous_session_ids"] == ["s2"]


def test_explain_anomaly_plaintext_produces_rich_deviations():
    from analysis.anomaly_detection.explanation import explain_anomaly

    # Mock feature vector with plaintext IMAP
    fv = {feat: 0.0 for feat in ALL_IF_FEATURES}
    fv["if_protocol_imap"] = 1.0
    fv["if_encryption_plaintext"] = 1.0
    fv["if_upgrade_succeeded"] = 0.0
    fv["if_cert_visible"] = 0.0
    fv["if_high_sev_count"] = 1.0
    fv["if_finding_count"] = 1.0

    prediction = {
        "status": "COMPLETE",
        "classification": "ANOMALOUS",
        "is_anomalous": True,
        "raw_score": -0.62,
        "decision_score": -0.05,
        "threshold": 0.0,
    }

    baseline_stats = {
        "if_encryption_plaintext": {"median": 0.0, "iqr_scale": 1.0, "q25": -0.5, "q75": 0.5},
        "if_upgrade_succeeded": {"median": 1.0, "iqr_scale": 1.0, "q25": 0.5, "q75": 1.5},
        "if_cert_visible": {"median": 1.0, "iqr_scale": 1.0, "q25": 0.5, "q75": 1.5},
        "if_high_sev_count": {"median": 0.0, "iqr_scale": 1.0, "q25": -0.5, "q75": 0.5},
        "if_finding_count": {"median": 0.0, "iqr_scale": 1.0, "q25": -0.5, "q75": 0.5},
    }

    session_findings = [
        {
            "finding_id": "finding-002",
            "session_id": "imap-002",
            "finding_type": "PLAINTEXT",
            "severity": "CRITICAL",
        }
    ]

    exp = explain_anomaly(fv, prediction, baseline_stats, session_findings)

    assert "plaintext IMAP" in exp["summary"]
    assert len(exp["deviations"]) >= 3

    dev_features = [d["feature"] for d in exp["deviations"]]
    assert "if_encryption_plaintext" in dev_features
    assert "if_upgrade_succeeded" in dev_features

    # Check deviation structure
    pt_dev = next(d for d in exp["deviations"] if d["feature"] == "if_encryption_plaintext")
    assert pt_dev["observed"] == 1.0
    assert pt_dev["baseline_median"] == 0.0
    assert pt_dev["comparison"] == "above expected range"
    assert "diverges sharply" in pt_dev["interpretation"]

    # Check related findings
    assert "finding-002" in exp["related_findings"]


def test_explain_anomaly_auth_before_tls():
    from analysis.anomaly_detection.explanation import explain_anomaly

    fv = {feat: 0.0 for feat in ALL_IF_FEATURES}
    fv["if_protocol_smtp"] = 1.0
    fv["if_auth_before_tls"] = 1.0
    fv["if_upgrade_succeeded"] = 0.0

    prediction = {
        "status": "COMPLETE",
        "classification": "ANOMALOUS",
        "is_anomalous": True,
        "raw_score": -0.7,
        "decision_score": -0.1,
        "threshold": 0.0,
    }

    baseline_stats = {
        "if_auth_before_tls": {"median": 0.0, "iqr_scale": 1.0, "q25": -0.5, "q75": 0.5},
        "if_upgrade_succeeded": {"median": 1.0, "iqr_scale": 1.0, "q25": 0.5, "q75": 1.5},
    }

    session_findings = [
        {
            "finding_id": "f-auth",
            "session_id": "smtp-001",
            "finding_type": "AUTH_BEFORE_TLS",
            "severity": "HIGH",
        }
    ]

    exp = explain_anomaly(fv, prediction, baseline_stats, session_findings)

    assert "plaintext credentials" in exp["summary"]
    assert "f-auth" in exp["related_findings"]

