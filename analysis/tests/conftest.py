"""Pytest fixtures and configuration for SecureMailScope Analysis Engine tests."""

import os
import sys
from datetime import datetime, timezone
import pytest

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "analysis.sms_analysis.settings")

from analysis.feature_extraction.models import (
    CertificateInfo,
    PacketRecord,
    SecurityInfo,
    SecurityProfile,
    Session,
    TLSInfo,
)


@pytest.fixture
def base_reference_time():
    return datetime(2026, 9, 9, 10, 30, 0, tzinfo=timezone.utc)


@pytest.fixture
def clean_smtp_tls_profile(base_reference_time):
    """Clean secure SMTP STARTTLS session (TLS 1.2, strong cipher, PFS, valid cert)."""
    return SecurityProfile(
        session_id="smtp-001",
        protocol="SMTP",
        service="submission",
        client_ip="10.0.1.15",
        server_ip="203.0.113.25",
        client_port=49152,
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
            version="TLS 1.2",
            cipher_suite="TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            pfs="YES",
        ),
        certificate=CertificateInfo(
            visibility="OBSERVED",
            subject="CN=mail.example.com",
            issuer="Example CA",
            valid_from="2026-01-01T00:00:00Z",
            valid_until="2027-01-01T00:00:00Z",
            key_type="RSA",
            key_size=2048,
            self_signed=False,
        ),
        tcp_stream=1,
        frame_numbers=[1, 2, 3, 4, 5],
        capture_reference_time=base_reference_time,
    )


@pytest.fixture
def tls10_profile(base_reference_time):
    return SecurityProfile(
        session_id="smtp-tls10",
        protocol="SMTP",
        service="submission",
        client_ip="10.0.1.20",
        server_ip="203.0.113.26",
        client_port=49153,
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
            version="TLS 1.0",
            cipher_suite="TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
            pfs="YES",
        ),
        tcp_stream=2,
        frame_numbers=[10, 12, 14],
        capture_reference_time=base_reference_time,
    )


@pytest.fixture
def weak_cipher_profile(base_reference_time):
    return SecurityProfile(
        session_id="imap-rc4",
        protocol="IMAP",
        service="mail-access",
        client_ip="10.0.1.30",
        server_ip="203.0.113.30",
        client_port=49154,
        server_port=143,
        security=SecurityInfo(
            encryption_mode="STARTTLS",
            upgrade_advertised="YES",
            upgrade_requested="YES",
            upgrade_succeeded="YES",
            authentication_before_tls="NO",
            capture_completeness="COMPLETE",
        ),
        tls=TLSInfo(
            version="TLS 1.2",
            cipher_suite="TLS_RSA_WITH_RC4_128_SHA",
            pfs="NO",
        ),
        tcp_stream=3,
        frame_numbers=[20, 22, 24],
        capture_reference_time=base_reference_time,
    )


@pytest.fixture
def expired_cert_profile(base_reference_time):
    return SecurityProfile(
        session_id="smtp-expired",
        protocol="SMTP",
        service="submission",
        client_ip="10.0.1.35",
        server_ip="203.0.113.35",
        client_port=49155,
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
            version="TLS 1.2",
            cipher_suite="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            pfs="YES",
        ),
        certificate=CertificateInfo(
            visibility="OBSERVED",
            subject="CN=expired.example.com",
            issuer="Example CA",
            valid_from="2020-01-01T00:00:00Z",
            valid_until="2024-01-01T00:00:00Z",  # Expired before 2026 reference time
            key_type="RSA",
            key_size=2048,
            self_signed=False,
        ),
        tcp_stream=4,
        frame_numbers=[30, 32],
        capture_reference_time=base_reference_time,
    )


@pytest.fixture
def not_yet_valid_cert_profile(base_reference_time):
    return SecurityProfile(
        session_id="smtp-future",
        protocol="SMTP",
        service="submission",
        client_ip="10.0.1.36",
        server_ip="203.0.113.36",
        client_port=49156,
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
            version="TLS 1.2",
            cipher_suite="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            pfs="YES",
        ),
        certificate=CertificateInfo(
            visibility="OBSERVED",
            subject="CN=future.example.com",
            issuer="Example CA",
            valid_from="2030-01-01T00:00:00Z",  # In the future relative to 2026
            valid_until="2032-01-01T00:00:00Z",
            key_type="RSA",
            key_size=2048,
            self_signed=False,
        ),
        tcp_stream=5,
        frame_numbers=[40, 42],
        capture_reference_time=base_reference_time,
    )


@pytest.fixture
def weak_key_profile(base_reference_time):
    return SecurityProfile(
        session_id="smtp-weakkey",
        protocol="SMTP",
        service="submission",
        client_ip="10.0.1.37",
        server_ip="203.0.113.37",
        client_port=49157,
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
            version="TLS 1.2",
            cipher_suite="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            pfs="YES",
        ),
        certificate=CertificateInfo(
            visibility="OBSERVED",
            subject="CN=weakkey.example.com",
            issuer="Example CA",
            valid_from="2026-01-01T00:00:00Z",
            valid_until="2027-01-01T00:00:00Z",
            key_type="RSA",
            key_size=1024,  # Below 2048
            self_signed=False,
        ),
        tcp_stream=6,
        frame_numbers=[50, 52],
        capture_reference_time=base_reference_time,
    )


@pytest.fixture
def auth_before_tls_profile(base_reference_time):
    return SecurityProfile(
        session_id="smtp-002",
        protocol="SMTP",
        service="submission",
        client_ip="10.0.1.20",
        server_ip="203.0.113.26",
        client_port=49153,
        server_port=587,
        security=SecurityInfo(
            encryption_mode="STARTTLS",
            upgrade_advertised="YES",
            upgrade_requested="NO",
            upgrade_succeeded="NO",
            authentication_before_tls="YES",
            capture_completeness="COMPLETE",
        ),
        tls=None,
        certificate=None,
        tcp_stream=7,
        frame_numbers=[60, 62],
        capture_reference_time=base_reference_time,
    )


@pytest.fixture
def plaintext_imap_profile(base_reference_time):
    return SecurityProfile(
        session_id="imap-001",
        protocol="IMAP",
        service="mail-access",
        client_ip="10.0.1.30",
        server_ip="203.0.113.30",
        client_port=49154,
        server_port=143,
        security=SecurityInfo(
            encryption_mode="PLAINTEXT",
            upgrade_advertised="NO",
            upgrade_requested="NO",
            upgrade_succeeded="NO",
            authentication_before_tls="YES",
            capture_completeness="COMPLETE",
        ),
        tls=None,
        certificate=None,
        tcp_stream=8,
        frame_numbers=[70, 72],
        capture_reference_time=base_reference_time,
    )


@pytest.fixture
def failed_starttls_profile(base_reference_time):
    return SecurityProfile(
        session_id="smtp-failed",
        protocol="SMTP",
        service="submission",
        client_ip="10.0.1.45",
        server_ip="203.0.113.45",
        client_port=49158,
        server_port=587,
        security=SecurityInfo(
            encryption_mode="STARTTLS",
            upgrade_advertised="YES",
            upgrade_requested="YES",
            upgrade_succeeded="NO",
            authentication_before_tls="NO",
            capture_completeness="PARTIAL",
        ),
        tls=None,
        certificate=None,
        tcp_stream=9,
        frame_numbers=[80, 82],
        capture_reference_time=base_reference_time,
    )


@pytest.fixture
def implicit_tls_profile(base_reference_time):
    return SecurityProfile(
        session_id="pop3-001",
        protocol="POP3",
        service="mail-access",
        client_ip="10.0.1.40",
        server_ip="203.0.113.40",
        client_port=49155,
        server_port=995,
        security=SecurityInfo(
            encryption_mode="IMPLICIT_TLS",
            upgrade_advertised="UNKNOWN",
            upgrade_requested="UNKNOWN",
            upgrade_succeeded="YES",
            authentication_before_tls="NO",
            capture_completeness="PARTIAL",
        ),
        tls=TLSInfo(
            version="TLS 1.3",
            cipher_suite="TLS_AES_256_GCM_SHA384",
            pfs="YES",
        ),
        certificate=CertificateInfo(
            visibility="NOT_OBSERVABLE",
        ),
        tcp_stream=10,
        frame_numbers=[90, 92],
        capture_reference_time=base_reference_time,
    )


@pytest.fixture
def self_signed_profile(base_reference_time):
    return SecurityProfile(
        session_id="smtp-selfsigned",
        protocol="SMTP",
        service="submission",
        client_ip="10.0.1.50",
        server_ip="203.0.113.50",
        client_port=49159,
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
            version="TLS 1.2",
            cipher_suite="TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            pfs="YES",
        ),
        certificate=CertificateInfo(
            visibility="OBSERVED",
            subject="CN=self.example.com",
            issuer="CN=self.example.com",
            valid_from="2026-01-01T00:00:00Z",
            valid_until="2027-01-01T00:00:00Z",
            key_type="RSA",
            key_size=2048,
            self_signed=True,
        ),
        tcp_stream=11,
        frame_numbers=[100, 102],
        capture_reference_time=base_reference_time,
    )
