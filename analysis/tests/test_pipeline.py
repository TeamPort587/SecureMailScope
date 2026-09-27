"""Integration tests for analysis pipeline."""

import json
import os
import tempfile
import pytest

from analysis.feature_extraction.models import PacketRecord
from analysis.integration.pipeline import AnalysisError, analyze_pcap


def test_pipeline_missing_file():
    with pytest.raises(AnalysisError) as exc_info:
        analyze_pcap("non_existent_file.pcap")
    assert exc_info.value.code == "FILE_NOT_FOUND"


def test_pipeline_empty_file():
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        empty_path = f.name
    try:
        with pytest.raises(AnalysisError) as exc_info:
            analyze_pcap(empty_path)
        assert exc_info.value.code == "EMPTY_FILE"
    finally:
        if os.path.exists(empty_path):
            os.remove(empty_path)


def test_pipeline_contract_conformity(monkeypatch):
    """Verify that analyze_pcap output strictly matches django-analysis-response.json structure."""
    # Mock parse_pcap to return 4 multi-protocol sessions:
    # 1. smtp-001 (STARTTLS clean TLS 1.2)
    # 2. smtp-002 (STARTTLS failed, auth before tls)
    # 3. imap-001 (Plaintext IMAP)
    # 4. pop3-001 (Implicit TLS POP3 TLS 1.3)
    mock_packets = [
        # Stream 0: SMTP Clean STARTTLS
        PacketRecord(
            frame_number=1,
            timestamp=1788949800.0,
            src_ip="10.0.1.15",
            src_port=49152,
            dst_ip="203.0.113.25",
            dst_port=587,
            tcp_stream=0,
            tcp_flags_syn=True,
            protocol="TCP",
        ),
        PacketRecord(
            frame_number=2,
            timestamp=1788949800.1,
            src_ip="203.0.113.25",
            src_port=587,
            dst_ip="10.0.1.15",
            dst_port=49152,
            tcp_stream=0,
            protocol="SMTP",
            application_data="250-STARTTLS",
        ),
        PacketRecord(
            frame_number=3,
            timestamp=1788949800.2,
            src_ip="10.0.1.15",
            src_port=49152,
            dst_ip="203.0.113.25",
            dst_port=587,
            tcp_stream=0,
            protocol="SMTP",
            application_data="STARTTLS",
        ),
        PacketRecord(
            frame_number=4,
            timestamp=1788949800.3,
            src_ip="203.0.113.25",
            src_port=587,
            dst_ip="10.0.1.15",
            dst_port=49152,
            tcp_stream=0,
            protocol="TLS",
            tls_handshake_type=2,
            tls_version="TLS 1.2",
            tls_cipher_suite="TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            tls_cert_info={
                "subject": "CN=mail.example.com",
                "issuer": "Example CA",
                "valid_from": "2026-01-01T00:00:00Z",
                "valid_until": "2027-01-01T00:00:00Z",
                "key_type": "RSA",
                "key_size": 2048,
            },
        ),
        PacketRecord(
            frame_number=5,
            timestamp=1788949800.4,
            src_ip="10.0.1.15",
            src_port=49152,
            dst_ip="203.0.113.25",
            dst_port=587,
            tcp_stream=0,
            tcp_flags_fin=True,
            protocol="TCP",
        ),

        # Stream 1: SMTP Auth before TLS & Failed STARTTLS
        PacketRecord(
            frame_number=10,
            timestamp=1788949810.0,
            src_ip="10.0.1.20",
            src_port=49153,
            dst_ip="203.0.113.26",
            dst_port=587,
            tcp_stream=1,
            tcp_flags_syn=True,
            protocol="TCP",
        ),
        PacketRecord(
            frame_number=11,
            timestamp=1788949810.1,
            src_ip="203.0.113.26",
            src_port=587,
            dst_ip="10.0.1.20",
            dst_port=49153,
            tcp_stream=1,
            protocol="SMTP",
            application_data="250-STARTTLS",
        ),
        PacketRecord(
            frame_number=12,
            timestamp=1788949810.15,
            src_ip="10.0.1.20",
            src_port=49153,
            dst_ip="203.0.113.26",
            dst_port=587,
            tcp_stream=1,
            protocol="SMTP",
            application_data="STARTTLS",
        ),
        PacketRecord(
            frame_number=13,
            timestamp=1788949810.2,
            src_ip="10.0.1.20",
            src_port=49153,
            dst_ip="203.0.113.26",
            dst_port=587,
            tcp_stream=1,
            protocol="SMTP",
            application_data="AUTH LOGIN dXNlcg==",
        ),
        PacketRecord(
            frame_number=13,
            timestamp=1788949810.3,
            src_ip="10.0.1.20",
            src_port=49153,
            dst_ip="203.0.113.26",
            dst_port=587,
            tcp_stream=1,
            tcp_flags_fin=True,
            protocol="TCP",
        ),

        # Stream 2: Plaintext IMAP
        PacketRecord(
            frame_number=20,
            timestamp=1788949820.0,
            src_ip="10.0.1.30",
            src_port=49154,
            dst_ip="203.0.113.30",
            dst_port=143,
            tcp_stream=2,
            tcp_flags_syn=True,
            protocol="TCP",
        ),
        PacketRecord(
            frame_number=21,
            timestamp=1788949820.1,
            src_ip="203.0.113.30",
            src_port=143,
            dst_ip="10.0.1.30",
            dst_port=49154,
            tcp_stream=2,
            protocol="IMAP",
            application_data="* OK IMAP4rev1 Ready",
        ),
        PacketRecord(
            frame_number=22,
            timestamp=1788949820.2,
            src_ip="10.0.1.30",
            src_port=49154,
            dst_ip="203.0.113.30",
            dst_port=143,
            tcp_stream=2,
            protocol="IMAP",
            application_data="A001 LOGIN user pass",
        ),
        PacketRecord(
            frame_number=23,
            timestamp=1788949820.3,
            src_ip="10.0.1.30",
            src_port=49154,
            dst_ip="203.0.113.30",
            dst_port=143,
            tcp_stream=2,
            tcp_flags_fin=True,
            protocol="TCP",
        ),

        # Stream 3: POP3 Implicit TLS (Port 995, TLS 1.3)
        PacketRecord(
            frame_number=30,
            timestamp=1788949830.0,
            src_ip="10.0.1.40",
            src_port=49155,
            dst_ip="203.0.113.40",
            dst_port=995,
            tcp_stream=3,
            protocol="TLS",
            tls_handshake_type=1,
            tls_version="TLS 1.3",
        ),
        PacketRecord(
            frame_number=31,
            timestamp=1788949830.1,
            src_ip="203.0.113.40",
            src_port=995,
            dst_ip="10.0.1.40",
            dst_port=49155,
            tcp_stream=3,
            protocol="TLS",
            tls_handshake_type=2,
            tls_version="TLS 1.3",
            tls_cipher_suite="TLS_AES_256_GCM_SHA384",
        ),
    ]

    monkeypatch.setattr(
        "analysis.integration.pipeline.parse_pcap",
        lambda file_path, backend="tshark": mock_packets,
    )

    # Create dummy pcap file to satisfy file existence and size check
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tf:
        tf.write(b"SIMULATED_PCAP_DATA")
        dummy_pcap_path = tf.name

    try:
        res = analyze_pcap(
            file_path=dummy_pcap_path,
            analysis_id="a1b2c3d4-5678-90ab-cdef-1234567890ab",
            filename="smtp_capture.pcap",
        )

        # Check top-level contract schema
        assert res["analysis_version"] == "1.0.0"
        assert "file" in res
        assert res["file"]["analysis_id"] == "a1b2c3d4-5678-90ab-cdef-1234567890ab"
        assert res["file"]["filename"] == "smtp_capture.pcap"
        assert "sha256" in res["file"]

        # Check summary
        summary = res["summary"]
        assert summary["total_sessions"] == 4
        assert summary["smtp_sessions"] == 2
        assert summary["imap_sessions"] == 1
        assert summary["pop3_sessions"] == 1
        assert summary["plaintext_sessions"] == 1
        assert summary["starttls_sessions"] == 2
        assert summary["implicit_tls_sessions"] == 1
        assert summary["vulnerable_sessions"] >= 2
        assert summary["findings_count"] >= 4

        # Check sessions array
        assert len(res["sessions"]) == 4

        # Check findings
        finding_types = [f["finding_type"] for f in res["findings"]]
        assert "AUTH_BEFORE_TLS" in finding_types
        assert "PLAINTEXT" in finding_types
        assert "FAILED_STARTTLS" in finding_types
        assert "PFS" in finding_types

        # Check risk and recommendations
        assert "risk" in res
        assert "score" in res["risk"]
        assert "level" in res["risk"]
        assert "recommendations" in res
        assert len(res["recommendations"]) >= 2

    finally:
        if os.path.exists(dummy_pcap_path):
            os.remove(dummy_pcap_path)
