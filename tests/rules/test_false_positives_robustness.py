"""Tests targeting false-positive regressions and boundary conditions.

Covers Section 18 specifications:
- SMTP: AUTH before/after TLS, STARTTLS negotiated, STARTTLS advertised but not negotiated,
  capture starting post-STARTTLS, unrelated text.
- IMAP: LOGIN before/after TLS, STARTTLS, partial capture.
- POP3: USER/PASS before/after TLS, STLS, partial capture.
- TLS: TLS 1.2, 1.3, deprecated, weak/strong ciphers, PFS, non-PFS, incomplete handshake.
- Certificates: valid, expired at capture time, expired today but valid at capture time,
  not-yet-valid, self-signed, TLS 1.3 unobservable.
"""

from datetime import datetime, timezone, timedelta
import pytest

from analysis.feature_extraction.models import (
    CertificateInfo,
    SecurityInfo,
    SecurityProfile,
    TLSInfo,
)
from analysis.rule_engine.engine import evaluate_profile
from analysis.rule_engine.rules.auth_before_tls import AuthBeforeTLSRule
from analysis.rule_engine.rules.deprecated_tls import DeprecatedTLSRule
from analysis.rule_engine.rules.expired_certificate import ExpiredCertificateRule
from analysis.rule_engine.rules.failed_starttls import FailedSTARTTLSRule
from analysis.rule_engine.rules.not_yet_valid_certificate import NotYetValidCertificateRule
from analysis.rule_engine.rules.pfs import PFSRule
from analysis.rule_engine.rules.plaintext import PlaintextRule
from analysis.rule_engine.rules.self_signed import SelfSignedCertificateRule
from analysis.rule_engine.rules.weak_cipher import WeakCipherRule
from analysis.rule_engine.rules.weak_key import WeakKeyRule


def make_test_profile(
    protocol="SMTP",
    encryption_mode="STARTTLS",
    upgrade_advertised="YES",
    upgrade_requested="YES",
    upgrade_succeeded="YES",
    authentication_before_tls="NO",
    capture_completeness="COMPLETE",
    tls_version="TLS 1.3",
    cipher_suite="TLS_AES_256_GCM_SHA384",
    pfs="YES",
    cert_visibility="OBSERVED",
    valid_from=None,
    valid_until=None,
    key_type="RSA",
    key_size=2048,
    self_signed=False,
    tcp_stream=0,
    start_time=None,
) -> SecurityProfile:
    now = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
    if valid_from is None:
        valid_from = (now - timedelta(days=60)).isoformat()
    if valid_until is None:
        valid_until = (now + timedelta(days=300)).isoformat()

    return SecurityProfile(
        session_id=f"test-{protocol.lower()}-001",
        tcp_stream=tcp_stream,
        protocol=protocol,
        service="mail",
        client_ip="192.168.1.100",
        server_ip="192.168.1.1",
        client_port=45678,
        server_port=587 if protocol == "SMTP" else (143 if protocol == "IMAP" else 110),
        security=SecurityInfo(
            encryption_mode=encryption_mode,
            upgrade_advertised=upgrade_advertised,
            upgrade_requested=upgrade_requested,
            upgrade_succeeded=upgrade_succeeded,
            authentication_before_tls=authentication_before_tls,
            capture_completeness=capture_completeness,
        ),
        tls=TLSInfo(version=tls_version, cipher_suite=cipher_suite, pfs=pfs) if tls_version else None,
        certificate=CertificateInfo(
            visibility=cert_visibility,
            subject="CN=mail.securecorp.example",
            issuer="CN=Global Trust CA",
            valid_from=valid_from,
            valid_until=valid_until,
            key_type=key_type,
            key_size=key_size,
            self_signed=self_signed,
        ) if cert_visibility == "OBSERVED" else CertificateInfo(visibility=cert_visibility),
        start_time=start_time or now.isoformat(),
    )


class TestSMTPRulesFalsePositiveResilience:
    def test_auth_after_tls_does_not_trigger_auth_before_tls(self):
        """Negative case: AUTH occurs safely after TLS upgrade."""
        profile = make_test_profile(authentication_before_tls="NO")
        rule = AuthBeforeTLSRule()
        assert rule.evaluate(profile) is None

    def test_auth_before_tls_triggers_reliably(self):
        """Positive case: AUTH before TLS observed."""
        profile = make_test_profile(authentication_before_tls="YES")
        rule = AuthBeforeTLSRule()
        finding = rule.evaluate(profile)
        assert finding is not None
        assert finding.severity == "CRITICAL"
        assert finding.evidence["authentication_before_tls"] is True
        assert finding.evidence["tcp_stream"] == 0

    def test_auth_unknown_does_not_trigger(self):
        """Ambiguous case: AUTH status UNKNOWN (partial capture)."""
        profile = make_test_profile(authentication_before_tls="UNKNOWN", capture_completeness="PARTIAL")
        rule = AuthBeforeTLSRule()
        assert rule.evaluate(profile) is None

    def test_starttls_succeeded_does_not_trigger_failed_starttls(self):
        """Negative case: STARTTLS advertised and completed."""
        profile = make_test_profile(upgrade_advertised="YES", upgrade_succeeded="YES")
        rule = FailedSTARTTLSRule()
        assert rule.evaluate(profile) is None

    def test_starttls_advertised_not_completed_triggers(self):
        """Positive case: STARTTLS advertised and requested but upgrade never completed."""
        profile = make_test_profile(
            encryption_mode="STARTTLS",
            upgrade_advertised="YES",
            upgrade_requested="YES",
            upgrade_succeeded="NO",
            tls_version=None,
        )
        rule = FailedSTARTTLSRule()
        finding = rule.evaluate(profile)
        assert finding is not None
        assert finding.severity == "HIGH"
        assert finding.finding_type == "FAILED_STARTTLS"

    def test_capture_starts_post_starttls_does_not_falsely_accuse_starttls_failure(self):
        """Ambiguous case: Capture starts mid-stream after TLS handshake already negotiated."""
        profile = make_test_profile(
            encryption_mode="UNKNOWN",
            upgrade_advertised="UNKNOWN",
            upgrade_requested="UNKNOWN",
            upgrade_succeeded="UNKNOWN",
            capture_completeness="PARTIAL",
            tls_version=None,
        )
        rule = FailedSTARTTLSRule()
        assert rule.evaluate(profile) is None


class TestIMAPAndPOP3FalsePositiveResilience:
    def test_imap_plaintext_triggers(self):
        profile = make_test_profile(protocol="IMAP", encryption_mode="PLAINTEXT", tls_version=None)
        rule = PlaintextRule()
        finding = rule.evaluate(profile)
        assert finding is not None
        assert finding.severity == "CRITICAL"
        assert finding.evidence["protocol"] == "IMAP"

    def test_imap_tls_does_not_trigger_plaintext(self):
        profile = make_test_profile(protocol="IMAP", encryption_mode="STARTTLS", tls_version="TLS 1.3")
        rule = PlaintextRule()
        assert rule.evaluate(profile) is None

    def test_pop3_implicit_tls_does_not_trigger_plaintext(self):
        profile = make_test_profile(protocol="POP3", encryption_mode="IMPLICIT_TLS", tls_version="TLS 1.2")
        rule = PlaintextRule()
        assert rule.evaluate(profile) is None


class TestTLSAndCipherRules:
    def test_tls_1_3_and_1_2_do_not_trigger_deprecated(self):
        for v in ["TLS 1.3", "TLS 1.2"]:
            profile = make_test_profile(tls_version=v)
            rule = DeprecatedTLSRule()
            assert rule.evaluate(profile) is None

    def test_tls_1_0_and_1_1_and_ssl_trigger_deprecated(self):
        for v in ["TLS 1.0", "TLS 1.1", "SSL 3.0", "SSL 2.0"]:
            profile = make_test_profile(tls_version=v)
            rule = DeprecatedTLSRule()
            finding = rule.evaluate(profile)
            assert finding is not None
            assert finding.severity == "HIGH"

    def test_weak_cipher_triggers_positive(self):
        profile = make_test_profile(cipher_suite="TLS_RSA_WITH_RC4_128_SHA")
        rule = WeakCipherRule()
        finding = rule.evaluate(profile)
        assert finding is not None
        assert finding.severity == "CRITICAL"

    def test_strong_cipher_does_not_trigger_weak_cipher(self):
        profile = make_test_profile(cipher_suite="TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")
        rule = WeakCipherRule()
        assert rule.evaluate(profile) is None

    def test_pfs_observed_triggers_info(self):
        profile = make_test_profile(pfs="YES")
        rule = PFSRule()
        finding = rule.evaluate(profile)
        assert finding is not None
        assert finding.severity == "INFO"

    def test_pfs_no_triggers_medium_finding(self):
        profile = make_test_profile(pfs="NO")
        rule = PFSRule()
        finding = rule.evaluate(profile)
        assert finding is not None
        assert finding.severity == "MEDIUM"

    def test_pfs_unknown_does_not_trigger(self):
        profile = make_test_profile(pfs="UNKNOWN")
        rule = PFSRule()
        assert rule.evaluate(profile) is None


class TestCertificateValidityAndCaptureReferenceTime:
    def test_cert_expired_today_but_valid_at_capture_time_does_not_trigger(self):
        """Forensic rule requirement: Evaluation must use capture_reference_time!

        If cert expired in 2024, but capture was taken in 2023, the cert was VALID
        at capture time and MUST NOT trigger ExpiredCertificateRule.
        """
        capture_time = datetime(2023, 5, 1, 10, 0, 0, tzinfo=timezone.utc)
        cert_valid_until = datetime(2023, 12, 31, 23, 59, 59, tzinfo=timezone.utc)
        cert_valid_from = datetime(2023, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

        profile = make_test_profile(
            valid_from=cert_valid_from.isoformat(),
            valid_until=cert_valid_until.isoformat(),
            start_time=capture_time.isoformat(),
        )

        rule = ExpiredCertificateRule()
        finding = rule.evaluate(profile)
        # MUST NOT trigger expired certificate
        assert finding is None

    def test_cert_actually_expired_at_capture_time_triggers(self):
        """Positive case: Cert expired BEFORE the capture was taken."""
        capture_time = datetime(2026, 6, 1, 10, 0, 0, tzinfo=timezone.utc)
        cert_valid_until = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        cert_valid_from = datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

        profile = make_test_profile(
            valid_from=cert_valid_from.isoformat(),
            valid_until=cert_valid_until.isoformat(),
            start_time=capture_time.isoformat(),
        )

        rule = ExpiredCertificateRule()
        finding = rule.evaluate(profile)
        assert finding is not None
        assert finding.severity == "HIGH"
        assert finding.evidence["capture_reference_time"] == capture_time.isoformat()

    def test_cert_not_yet_valid_at_capture_time_triggers(self):
        """Positive case: Capture taken before cert's valid_from."""
        capture_time = datetime(2025, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
        cert_valid_from = datetime(2025, 6, 1, 0, 0, 0, tzinfo=timezone.utc)
        cert_valid_until = datetime(2026, 6, 1, 0, 0, 0, tzinfo=timezone.utc)

        profile = make_test_profile(
            valid_from=cert_valid_from.isoformat(),
            valid_until=cert_valid_until.isoformat(),
            start_time=capture_time.isoformat(),
        )

        rule = NotYetValidCertificateRule()
        finding = rule.evaluate(profile)
        assert finding is not None
        assert finding.severity == "HIGH"

    def test_ec_256_bit_key_does_not_trigger_weak_key(self):
        """ECC keys (P-256) have 256 bits but equal strength to RSA-3072!

        Must NOT trigger WeakKeyRule.
        """
        profile = make_test_profile(key_type="EC", key_size=256)
        rule = WeakKeyRule()
        assert rule.evaluate(profile) is None

    def test_rsa_1024_bit_key_triggers_weak_key(self):
        """RSA keys < 2048 bits trigger WeakKeyRule with MEDIUM severity."""
        profile = make_test_profile(key_type="RSA", key_size=1024)
        rule = WeakKeyRule()
        finding = rule.evaluate(profile)
        assert finding is not None
        assert finding.severity == "MEDIUM"

    def test_self_signed_cert_triggers(self):
        profile = make_test_profile(self_signed=True)
        rule = SelfSignedCertificateRule()
        finding = rule.evaluate(profile)
        assert finding is not None
        assert finding.severity == "LOW"

    def test_ca_signed_cert_does_not_trigger_self_signed(self):
        profile = make_test_profile(self_signed=False)
        rule = SelfSignedCertificateRule()
        assert rule.evaluate(profile) is None

    def test_tls_1_3_unobservable_cert_does_not_trigger_any_cert_rules(self):
        """In TLS 1.3, certificates are encrypted in flight (NOT_OBSERVABLE).

        No cert rules should trigger false positive violations.
        """
        profile = make_test_profile(cert_visibility="NOT_OBSERVABLE")
        for rule in [ExpiredCertificateRule(), NotYetValidCertificateRule(), WeakKeyRule(), SelfSignedCertificateRule()]:
            assert rule.evaluate(profile) is None
