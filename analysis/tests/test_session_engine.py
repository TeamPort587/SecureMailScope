"""Unit tests for TCP session engine and multi-session separation."""

from analysis.feature_extraction.models import PacketRecord
from analysis.session_engine.engine import build_sessions


def test_session_engine_multi_session_separation():
    # Build a synthetic packet list containing 3 distinct email streams + 1 web stream
    packets = [
        # Stream 0: SMTP Submission on port 587
        PacketRecord(
            frame_number=1,
            timestamp=1000.0,
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
            timestamp=1000.1,
            src_ip="203.0.113.25",
            src_port=587,
            dst_ip="10.0.1.15",
            dst_port=49152,
            tcp_stream=0,
            tcp_flags_syn=True,
            tcp_flags_ack=True,
            protocol="TCP",
        ),
        PacketRecord(
            frame_number=3,
            timestamp=1000.2,
            src_ip="10.0.1.15",
            src_port=49152,
            dst_ip="203.0.113.25",
            dst_port=587,
            tcp_stream=0,
            protocol="SMTP",
            application_data="EHLO client.example.com",
        ),
        PacketRecord(
            frame_number=4,
            timestamp=1000.3,
            src_ip="203.0.113.25",
            src_port=587,
            dst_ip="10.0.1.15",
            dst_port=49152,
            tcp_stream=0,
            tcp_flags_fin=True,
            protocol="TCP",
        ),

        # Stream 1: IMAP on port 143
        PacketRecord(
            frame_number=10,
            timestamp=1001.0,
            src_ip="10.0.1.30",
            src_port=49154,
            dst_ip="203.0.113.30",
            dst_port=143,
            tcp_stream=1,
            tcp_flags_syn=True,
            protocol="TCP",
        ),
        PacketRecord(
            frame_number=11,
            timestamp=1001.1,
            src_ip="203.0.113.30",
            src_port=143,
            dst_ip="10.0.1.30",
            dst_port=49154,
            tcp_stream=1,
            protocol="IMAP",
            application_data="* OK IMAP4rev1 Server Ready",
        ),
        PacketRecord(
            frame_number=12,
            timestamp=1001.2,
            src_ip="10.0.1.30",
            src_port=49154,
            dst_ip="203.0.113.30",
            dst_port=143,
            tcp_stream=1,
            tcp_flags_reset=True,
            protocol="TCP",
        ),

        # Stream 2: POP3 on port 995
        PacketRecord(
            frame_number=20,
            timestamp=1002.0,
            src_ip="10.0.1.40",
            src_port=49155,
            dst_ip="203.0.113.40",
            dst_port=995,
            tcp_stream=2,
            protocol="TLS",
            tls_handshake_type=1,
            tls_version="TLS 1.3",
        ),
        PacketRecord(
            frame_number=21,
            timestamp=1002.1,
            src_ip="203.0.113.40",
            src_port=995,
            dst_ip="10.0.1.40",
            dst_port=49155,
            tcp_stream=2,
            protocol="TLS",
            tls_handshake_type=2,
            tls_version="TLS 1.3",
            tls_cipher_suite="TLS_AES_256_GCM_SHA384",
        ),

        # Stream 3: Unrelated HTTP traffic on port 80
        PacketRecord(
            frame_number=30,
            timestamp=1003.0,
            src_ip="10.0.1.99",
            src_port=55555,
            dst_ip="93.184.216.34",
            dst_port=80,
            tcp_stream=3,
            protocol="HTTP",
        ),
    ]

    sessions = build_sessions(packets)

    # 4 distinct streams
    assert len(sessions) == 4

    # Verify stream 0 (SMTP)
    smtp_sess = sessions[0]
    assert smtp_sess.protocol == "SMTP"
    assert smtp_sess.service == "submission"
    assert smtp_sess.client_ip == "10.0.1.15"
    assert smtp_sess.server_port == 587
    assert smtp_sess.completeness == "COMPLETE"
    assert smtp_sess.first_frame == 1
    assert smtp_sess.last_frame == 4
    assert smtp_sess.packet_count == 4

    # Verify stream 1 (IMAP)
    imap_sess = sessions[1]
    assert imap_sess.protocol == "IMAP"
    assert imap_sess.service == "mail-access"
    assert imap_sess.server_port == 143
    assert imap_sess.completeness == "PARTIAL"

    # Verify stream 2 (POP3)
    pop3_sess = sessions[2]
    assert pop3_sess.protocol == "POP3"
    assert pop3_sess.service == "mail-access"
    assert pop3_sess.server_port == 995

    # Verify stream 3 (HTTP -> UNKNOWN protocol for email scope)
    http_sess = sessions[3]
    assert http_sess.protocol == "UNKNOWN"


def test_session_engine_completeness_categories():
    # Complete: SYN + SYN/ACK + FIN + bidirectional
    complete_pkts = [
        PacketRecord(frame_number=1, timestamp=1.0, src_ip="1.1.1.1", src_port=1000, dst_ip="2.2.2.2", dst_port=587, tcp_stream=0, tcp_flags_syn=True),
        PacketRecord(frame_number=2, timestamp=1.1, src_ip="2.2.2.2", src_port=587, dst_ip="1.1.1.1", dst_port=1000, tcp_stream=0, tcp_flags_syn=True, tcp_flags_ack=True),
        PacketRecord(frame_number=3, timestamp=1.2, src_ip="1.1.1.1", src_port=1000, dst_ip="2.2.2.2", dst_port=587, tcp_stream=0, tcp_flags_fin=True),
    ]
    sessions = build_sessions(complete_pkts)
    assert len(sessions) == 1
    assert sessions[0].completeness == "COMPLETE"

    # Unknown: only 1 packet
    single_pkt = [
        PacketRecord(frame_number=1, timestamp=1.0, src_ip="1.1.1.1", src_port=1000, dst_ip="2.2.2.2", dst_port=587, tcp_stream=1),
    ]
    sessions_single = build_sessions(single_pkt)
    assert len(sessions_single) == 1
    assert sessions_single[0].completeness == "UNKNOWN"
