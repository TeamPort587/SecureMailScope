"""Unit and Integration Tests for PCAP Parser Module."""

import os
import tempfile
from pathlib import Path
import pytest

from analysis.pcap_parser.parser import parse_pcap

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
VAL_PCAP_1 = REPO_ROOT / "captures" / "validation" / "validation_01.pcap"
VAL_PCAP_2 = REPO_ROOT / "captures" / "validation" / "validation_02.pcap"
VAL_PCAP_3 = REPO_ROOT / "captures" / "validation" / "validation_03.pcap"


def test_parse_validation_01():
    """Verify parsing validation_01.pcap extracts packets and protocols."""
    assert VAL_PCAP_1.exists(), f"Missing {VAL_PCAP_1}"
    packets = parse_pcap(str(VAL_PCAP_1), backend="tshark")
    assert len(packets) > 0

    protocols = {p.protocol for p in packets}
    assert any(proto in protocols for proto in ["SMTP", "IMAP", "POP3", "TLS", "TCP"])


def test_parse_validation_02_certificates():
    """Verify parsing validation_02.pcap extracts X.509 certificate metadata."""
    assert VAL_PCAP_2.exists(), f"Missing {VAL_PCAP_2}"
    packets = parse_pcap(str(VAL_PCAP_2), backend="tshark")
    assert len(packets) > 0

    cert_packets = [p for p in packets if p.tls_cert_info is not None]
    assert len(cert_packets) > 0, "Expected at least one packet with extracted certificate info in validation_02"
    cert = cert_packets[0].tls_cert_info
    assert "subject" in cert
    assert "CN=mail.lab.local" in cert["subject"] or "issuer" in cert


def test_parse_corrupt_file_fails_gracefully():
    """Verify parsing a corrupt file raises an error and does not hang."""
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        f.write(b"NOT_A_VALID_PCAP_CONTENT_GARBAGE_BYTES_123456789")
        corrupt_path = f.name

    try:
        with pytest.raises(Exception):
            parse_pcap(corrupt_path, backend="tshark")
    finally:
        if os.path.exists(corrupt_path):
            os.remove(corrupt_path)
