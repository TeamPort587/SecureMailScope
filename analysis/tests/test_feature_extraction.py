"""Unit tests for feature extraction layer."""

from analysis.feature_extraction.certificate import extract_certificate_info
from analysis.feature_extraction.email_protocol import analyze_email_security
from analysis.feature_extraction.extractor import extract_security_profile
from analysis.feature_extraction.models import PacketRecord, Session, TLSInfo
from analysis.feature_extraction.tls import (
    determine_pfs,
    extract_tls_info,
    normalize_cipher_suite,
    normalize_tls_version,
)


def test_auth_before_tls_detection():
    # Sequence: AUTH before TLS handshake
    client_auth = PacketRecord(
        frame_number=2,
        timestamp=1.0,
        src_ip="10.0.1.1",
        src_port=50000,
        dst_ip="10.0.1.2",
        dst_port=587,
        tcp_stream=1,
        application_data="AUTH LOGIN dXNlcg==",
    )
    server_tls = PacketRecord(
        frame_number=10,
        timestamp=2.0,
        src_ip="10.0.1.2",
        src_port=587,
        dst_ip="10.0.1.1",
        dst_port=50000,
        tcp_stream=1,
        protocol="TLS",
        tls_handshake_type=2,
    )
    packets = [client_auth, server_tls]
    sec_info, frames = analyze_email_security(
        packets=packets,
        client_packets=[client_auth],
        server_packets=[server_tls],
        protocol="SMTP",
        server_port=587,
        completeness="COMPLETE",
    )
    assert sec_info.authentication_before_tls == "YES"


def test_auth_after_tls_detection():
    # Sequence: TLS handshake occurs before AUTH
    server_tls = PacketRecord(
        frame_number=5,
        timestamp=1.0,
        src_ip="10.0.1.2",
        src_port=587,
        dst_ip="10.0.1.1",
        dst_port=50000,
        tcp_stream=1,
        protocol="TLS",
        tls_handshake_type=2,
    )
    client_auth = PacketRecord(
        frame_number=15,
        timestamp=2.0,
        src_ip="10.0.1.1",
        src_port=50000,
        dst_ip="10.0.1.2",
        dst_port=587,
        tcp_stream=1,
        application_data="AUTH LOGIN dXNlcg==",
    )
    packets = [server_tls, client_auth]
    sec_info, frames = analyze_email_security(
        packets=packets,
        client_packets=[client_auth],
        server_packets=[server_tls],
        protocol="SMTP",
        server_port=587,
        completeness="COMPLETE",
    )
    assert sec_info.authentication_before_tls == "NO"


def test_tls_version_normalization():
    assert normalize_tls_version("0x0303") == "TLS 1.2"
    assert normalize_tls_version("0x0304") == "TLS 1.3"
    assert normalize_tls_version("0x0301") == "TLS 1.0"
    assert normalize_tls_version("TLS 1.2") == "TLS 1.2"


def test_cipher_suite_normalization():
    # Hex string
    assert normalize_cipher_suite("0x002f") == "TLS_RSA_WITH_AES_128_CBC_SHA"
    assert normalize_cipher_suite("0x002F") == "TLS_RSA_WITH_AES_128_CBC_SHA"
    assert normalize_cipher_suite("0x1302") == "TLS_AES_256_GCM_SHA384"
    assert normalize_cipher_suite("0xc030") == "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"

    # Stringified dictionary from TShark JSON
    assert normalize_cipher_suite("{'tls.handshake.ciphersuite': '0x002f'}") == "TLS_RSA_WITH_AES_128_CBC_SHA"

    # Dictionary object
    assert normalize_cipher_suite({"tls.handshake.ciphersuite": "0x002f"}) == "TLS_RSA_WITH_AES_128_CBC_SHA"

    # Integer
    assert normalize_cipher_suite(0x002F) == "TLS_RSA_WITH_AES_128_CBC_SHA"

    # Already canonical name
    assert normalize_cipher_suite("TLS_RSA_WITH_AES_128_CBC_SHA") == "TLS_RSA_WITH_AES_128_CBC_SHA"


def test_extract_tls_info_normalizes_hex_cipher():
    pkt = PacketRecord(
        frame_number=1,
        timestamp=1.0,
        src_ip="1.1.1.1",
        src_port=587,
        dst_ip="2.2.2.2",
        dst_port=50000,
        tcp_stream=1,
        tls_version="0x0303",
        tls_cipher_suite="{'tls.handshake.ciphersuite': '0x002f'}",
    )
    tls_info = extract_tls_info([pkt])
    assert tls_info is not None
    assert tls_info.version == "TLS 1.2"
    assert tls_info.cipher_suite == "TLS_RSA_WITH_AES_128_CBC_SHA"
    assert tls_info.pfs == "NO"


def test_pfs_determination():
    assert determine_pfs("TLS 1.3", None) == "YES"
    assert determine_pfs("TLS 1.2", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384") == "YES"
    assert determine_pfs("TLS 1.2", "TLS_DHE_RSA_WITH_AES_128_CBC_SHA") == "YES"
    assert determine_pfs("TLS 1.2", "TLS_RSA_WITH_AES_128_CBC_SHA") == "NO"
    assert determine_pfs("TLS 1.2", None) == "UNKNOWN"


def test_certificate_extraction_tls13_not_observable():
    tls13 = TLSInfo(version="TLS 1.3", cipher_suite="TLS_AES_256_GCM_SHA384", pfs="YES")
    cert = extract_certificate_info([], tls13)
    assert cert is not None
    assert cert.visibility == "NOT_OBSERVABLE"


def test_certificate_extraction_observable():
    tls12 = TLSInfo(version="TLS 1.2", cipher_suite="TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", pfs="YES")
    pkt = PacketRecord(
        frame_number=1,
        timestamp=1.0,
        src_ip="1.1.1.1",
        src_port=587,
        dst_ip="2.2.2.2",
        dst_port=50000,
        tcp_stream=1,
        tls_cert_info={
            "subject": "CN=mail.example.com",
            "issuer": "CN=mail.example.com",
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_until": "2027-01-01T00:00:00Z",
            "key_type": "RSA",
            "key_size": 2048,
        },
    )
    cert = extract_certificate_info([pkt], tls12)
    assert cert is not None
    assert cert.visibility == "OBSERVED"
    assert cert.self_signed is True
    assert cert.key_size == 2048
