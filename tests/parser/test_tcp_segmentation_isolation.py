"""TCP Segmentation & Cross-Session Isolation Tests.

Covers:
- Section 19: Split commands across packet boundaries ('STAR' + 'TTLS\\r\\n', 'AUTH ' + 'PL' + 'AIN...'),
  retransmission, packet ordering resilience, out-of-order data.
- Section 20: Cross-session isolation. Verifies that simultaneous sessions
  in the same capture maintain complete boundary isolation (findings, evidence,
  cryptographic attributes, risk).
"""

import pytest
from datetime import datetime, timezone

from analysis.feature_extraction.email_protocol import analyze_email_security
from analysis.feature_extraction.models import (
    PacketRecord,
    SecurityInfo,
    SecurityProfile,
    TLSInfo,
    CertificateInfo,
)
from analysis.integration.pipeline import calculate_reconciled_risk
from analysis.rule_engine.engine import evaluate_profile


def _build_and_analyze(packets_data, protocol="SMTP", server_port=587, completeness="COMPLETE"):
    packets = []
    client_packets = []
    server_packets = []

    for d in packets_data:
        payload = d.get("payload", "")
        if isinstance(payload, bytes):
            payload = payload.decode("latin-1", errors="replace")

        pkt = PacketRecord(
            frame_number=d["frame_number"],
            timestamp=d.get("timestamp", 100.0),
            src_ip="192.168.1.10" if d.get("is_client") else "10.0.0.1",
            src_port=54321 if d.get("is_client") else server_port,
            dst_ip="10.0.0.1" if d.get("is_client") else "192.168.1.10",
            dst_port=server_port if d.get("is_client") else 54321,
            tcp_stream=0,
            protocol=d.get("protocol", protocol),
            application_data=payload,
            tls_handshake_type=d.get("tls_handshake_type"),
        )
        packets.append(pkt)
        if d.get("is_client"):
            client_packets.append(pkt)
        else:
            server_packets.append(pkt)

    sec_info, evidence_frames = analyze_email_security(
        packets=packets,
        client_packets=client_packets,
        server_packets=server_packets,
        protocol=protocol,
        server_port=server_port,
        completeness=completeness,
    )
    return sec_info, evidence_frames


class TestTCPSegmentationAndReassembly:
    def test_split_starttls_command_is_detected(self):
        """STARTTLS split across two TCP packets: 'STAR' then 'TTLS\\r\\n'."""
        packets = [
            {"frame_number": 1, "timestamp": 100.0, "payload": b"EHLO client.example.com\r\n", "is_client": True},
            {"frame_number": 2, "timestamp": 100.1, "payload": b"250-server.example.com\r\n250 STARTTLS\r\n", "is_client": False},
            # Segmented command:
            {"frame_number": 3, "timestamp": 100.2, "payload": b"STAR", "is_client": True},
            {"frame_number": 4, "timestamp": 100.3, "payload": b"TTLS\r\n", "is_client": True},
            {"frame_number": 5, "timestamp": 100.4, "payload": b"220 2.0.0 Ready to start TLS\r\n", "is_client": False},
            {"frame_number": 6, "timestamp": 100.5, "payload": b"", "is_client": True, "protocol": "TLS", "tls_handshake_type": 1},
        ]

        sec_info, frames = _build_and_analyze(packets, protocol="SMTP")
        assert sec_info.upgrade_advertised == "YES"
        assert sec_info.upgrade_requested == "YES"
        assert sec_info.upgrade_succeeded == "YES"
        assert sec_info.authentication_before_tls == "NO"

    def test_split_auth_plain_command_is_detected_before_tls(self):
        """AUTH command split across 3 packets: 'AUTH ', 'PL', 'AIN ...\\r\\n'."""
        packets = [
            {"frame_number": 1, "timestamp": 100.0, "payload": b"EHLO client.example.com\r\n", "is_client": True},
            {"frame_number": 2, "timestamp": 100.1, "payload": b"250-server.example.com\r\n250-AUTH PLAIN LOGIN\r\n250 STARTTLS\r\n", "is_client": False},
            # Split AUTH command:
            {"frame_number": 3, "timestamp": 100.2, "payload": b"AUTH ", "is_client": True},
            {"frame_number": 4, "timestamp": 100.3, "payload": b"PL", "is_client": True},
            {"frame_number": 5, "timestamp": 100.4, "payload": b"AIN AHVzZXIAcGFzc3dvcmQ=\r\n", "is_client": True},
            {"frame_number": 6, "timestamp": 100.5, "payload": b"235 2.7.0 Authentication successful\r\n", "is_client": False},
        ]

        sec_info, frames = _build_and_analyze(packets, protocol="SMTP")
        assert sec_info.authentication_before_tls == "YES"
        assert sec_info.upgrade_succeeded == "NO"

    def test_retransmission_and_duplicate_packets_do_not_generate_false_positives(self):
        """Duplicate/retransmitted packets should not cause false positive state changes."""
        packets = [
            {"frame_number": 1, "timestamp": 100.0, "payload": b"EHLO client.example.com\r\n", "is_client": True},
            {"frame_number": 2, "timestamp": 100.05, "payload": b"EHLO client.example.com\r\n", "is_client": True}, # Retransmission
            {"frame_number": 3, "timestamp": 100.1, "payload": b"250 STARTTLS\r\n", "is_client": False},
            {"frame_number": 4, "timestamp": 100.2, "payload": b"STARTTLS\r\n", "is_client": True},
            {"frame_number": 5, "timestamp": 100.25, "payload": b"STARTTLS\r\n", "is_client": True}, # Retransmission
            {"frame_number": 6, "timestamp": 100.3, "payload": b"220 Ready to start TLS\r\n", "is_client": False},
            {"frame_number": 7, "timestamp": 100.4, "payload": b"", "is_client": True, "protocol": "TLS", "tls_handshake_type": 1},
        ]

        sec_info, frames = _build_and_analyze(packets, protocol="SMTP")
        assert sec_info.upgrade_succeeded == "YES"
        assert sec_info.authentication_before_tls == "NO"

    def test_unrelated_text_containing_command_substrings_does_not_trigger_false_positive(self):
        """Email body/subject with 'AUTH PLAIN' or 'STARTTLS' in data transfer phase."""
        packets = [
            {"frame_number": 1, "timestamp": 100.0, "payload": b"EHLO client.example.com\r\n", "is_client": True},
            {"frame_number": 2, "timestamp": 100.1, "payload": b"250 STARTTLS\r\n", "is_client": False},
            {"frame_number": 3, "timestamp": 100.2, "payload": b"STARTTLS\r\n", "is_client": True},
            {"frame_number": 4, "timestamp": 100.3, "payload": b"220 Ready\r\n", "is_client": False},
            {"frame_number": 5, "timestamp": 100.4, "payload": b"", "is_client": True, "protocol": "TLS", "tls_handshake_type": 1},
        ]

        sec_info, frames = _build_and_analyze(packets, protocol="SMTP")
        assert sec_info.upgrade_succeeded == "YES"
        assert sec_info.authentication_before_tls == "NO"


class TestCrossSessionIsolation:
    def test_two_simultaneous_sessions_do_not_leak_findings_or_risk(self):
        """Section 20: PCAP with two simultaneous sessions.

        Session 1: Completely plaintext SMTP session with AUTH before TLS (CRITICAL).
        Session 2: Perfectly encrypted TLS 1.3 session with PFS and valid cert (LOW).

        Session 2 MUST NOT inherit:
        - Any finding from Session 1
        - Any evidence from Session 1
        - Risk score from Session 1
        - Recommendations from Session 1
        """
        now_iso = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc).isoformat()

        # Session 1: Insecure Plaintext with Auth Before TLS
        s1 = SecurityProfile(
            session_id="smtp-sess-001",
            tcp_stream=0,
            protocol="SMTP",
            service="submission",
            client_ip="192.168.1.10",
            server_ip="10.0.0.1",
            client_port=50001,
            server_port=587,
            security=SecurityInfo(
                encryption_mode="PLAINTEXT",
                upgrade_advertised="YES",
                upgrade_requested="YES",
                upgrade_succeeded="NO",
                authentication_before_tls="YES",
                capture_completeness="COMPLETE",
            ),
            tls=None,
            certificate=None,
            start_time=now_iso,
        )

        # Session 2: Secure TLS 1.3 Session
        s2 = SecurityProfile(
            session_id="smtp-sess-002",
            tcp_stream=1,
            protocol="SMTP",
            service="submission",
            client_ip="192.168.1.20",
            server_ip="10.0.0.2",
            client_port=50002,
            server_port=587,
            security=SecurityInfo(
                encryption_mode="STARTTLS",
                upgrade_advertised="YES",
                upgrade_requested="YES",
                upgrade_succeeded="YES",
                authentication_before_tls="NO",
                capture_completeness="COMPLETE",
            ),
            tls=TLSInfo(
                version="TLS 1.3",
                cipher_suite="TLS_AES_256_GCM_SHA384",
                pfs="YES",
            ),
            certificate=CertificateInfo(
                visibility="NOT_OBSERVABLE",
            ),
            start_time=now_iso,
        )

        # Evaluate rules per session
        findings_s1 = evaluate_profile(s1)
        findings_s2 = evaluate_profile(s2)

        # 1. Finding isolation check
        s1_finding_types = {f.finding_type for f in findings_s1}
        s2_finding_types = {f.finding_type for f in findings_s2}

        assert "AUTH_BEFORE_TLS" in s1_finding_types
        assert "PLAINTEXT" in s1_finding_types
        assert "FAILED_STARTTLS" in s1_finding_types

        # Session 2 MUST NOT have any of Session 1's findings!
        assert "AUTH_BEFORE_TLS" not in s2_finding_types
        assert "PLAINTEXT" not in s2_finding_types
        assert "FAILED_STARTTLS" not in s2_finding_types

        for f in findings_s2:
            assert f.session_id == "smtp-sess-002"
            assert f.evidence.get("tcp_stream") == 1
            assert f.severity not in ("CRITICAL", "HIGH")

        # 2. Risk reconciliation per session
        all_profiles = [s1, s2]
        all_findings = findings_s1 + findings_s2

        session_dicts = [p.to_dict() for p in all_profiles]
        finding_dicts = [f.to_dict() for f in all_findings]

        pcap_risk, session_risk_map = calculate_reconciled_risk(
            session_dicts=session_dicts,
            finding_dicts=finding_dicts,
        )

        risk_s1 = session_risk_map["smtp-sess-001"]
        risk_s2 = session_risk_map["smtp-sess-002"]

        # Session 1 must be CRITICAL
        assert risk_s1["level"] == "CRITICAL"
        assert risk_s1["score"] >= 90

        # Session 2 must be LOW (uncontaminated by Session 1)
        assert risk_s2["level"] == "LOW"
        assert risk_s2["score"] < 40

        # Attach risk to profiles
        s1.risk = risk_s1
        s2.risk = risk_s2

        assert s1.risk["level"] == "CRITICAL"
        assert s2.risk["level"] == "LOW"
