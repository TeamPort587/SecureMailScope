"""Comprehensive Deterministic Rule Engine Test Suite.

Verifies:
- Positive test
- Negative test
- UNKNOWN / unobservable test
- Evidence verification
- STARTTLS regression cases (1, 2, 3, 4)
- Certificate validity and key size rules
"""

from datetime import datetime, timezone, timedelta
import pytest

from analysis.feature_extraction.models import (
    CertificateInfo,
    Finding,
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


def make_profile(**kwargs) -> SecurityProfile:
    sec_kwargs = {}
    for k in ["encryption_mode", "upgrade_advertised", "upgrade_requested", "upgrade_succeeded", "authentication_before_tls", "capture_completeness"]:
        if k in kwargs:
            sec_kwargs[k] = kwargs.pop(k)

    defaults = {
        "session_id": "test-session-001",
        "protocol": "SMTP",
        "service": "submission",
        "client_ip": "192.168.1.10",
        "server_ip": "192.168.1.25",
        "client_port": 54321,
        "server_port": 587,
        "security": SecurityInfo(**sec_kwargs),
        "tls": TLSInfo(version="TLS 1.3", cipher_suite="TLS_AES_256_GCM_SHA384", pfs="YES"),
        "certificate": CertificateInfo(
            visibility="OBSERVED",
            subject="CN=mail.example.com",
            issuer="CN=Example CA",
            valid_from=(datetime.now(timezone.utc) - timedelta(days=30)).isoformat(),
            valid_until=(datetime.now(timezone.utc) + timedelta(days=335)).isoformat(),
            key_type="RSA",
            key_size=2048,
            self_signed=False,
        ),
    }
    defaults.update(kwargs)
    return SecurityProfile(**defaults)


# ---------------------------------------------------------------------------
# DEPRECATED_TLS
# ---------------------------------------------------------------------------
class TestDeprecatedTLSRule:
    rule = DeprecatedTLSRule()

    def test_positive(self):
        profile = make_profile(tls=TLSInfo(version="TLS 1.0", cipher_suite="TLS_RSA_WITH_AES_128_CBC_SHA"))
        finding = self.rule.evaluate(profile, "finding-001")
        assert finding is not None
        assert finding.finding_type == "DEPRECATED_TLS"
        assert finding.severity == "HIGH"
        assert finding.evidence["tls_version"] == "TLS 1.0"

    def test_negative_tls13(self):
        profile = make_profile(tls=TLSInfo(version="TLS 1.3"))
        assert self.rule.evaluate(profile, "finding-001") is None

    def test_negative_tls12(self):
        profile = make_profile(tls=TLSInfo(version="TLS 1.2"))
        assert self.rule.evaluate(profile, "finding-001") is None

    def test_unknown(self):
        profile = make_profile(tls=None)
        assert self.rule.evaluate(profile, "finding-001") is None


# ---------------------------------------------------------------------------
# WEAK_CIPHER
# ---------------------------------------------------------------------------
class TestWeakCipherRule:
    rule = WeakCipherRule()

    def test_positive_rc4(self):
        profile = make_profile(tls=TLSInfo(version="TLS 1.2", cipher_suite="TLS_RSA_WITH_RC4_128_SHA"))
        finding = self.rule.evaluate(profile, "finding-001")
        assert finding is not None
        assert finding.finding_type == "WEAK_CIPHER"
        assert "RC4" in finding.evidence["cipher_suite"]

    def test_positive_3des(self):
        profile = make_profile(tls=TLSInfo(version="TLS 1.2", cipher_suite="TLS_RSA_WITH_3DES_EDE_CBC_SHA"))
        finding = self.rule.evaluate(profile, "finding-001")
        assert finding is not None

    def test_negative_gcm(self):
        profile = make_profile(tls=TLSInfo(version="TLS 1.2", cipher_suite="TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"))
        assert self.rule.evaluate(profile, "finding-001") is None


# ---------------------------------------------------------------------------
# CERTIFICATE RULES: EXPIRED, NOT_YET_VALID, WEAK_KEY, SELF_SIGNED
# ---------------------------------------------------------------------------
class TestCertificateRules:
    def test_expired_certificate_positive(self):
        past = datetime.now(timezone.utc) - timedelta(days=10)
        profile = make_profile(
            certificate=CertificateInfo(
                visibility="OBSERVED",
                valid_from=(past - timedelta(days=365)).isoformat(),
                valid_until=past.isoformat(),
            )
        )
        finding = ExpiredCertificateRule().evaluate(profile, "finding-001")
        assert finding is not None
        assert finding.finding_type == "EXPIRED_CERTIFICATE"
        assert finding.severity == "HIGH"

    def test_not_yet_valid_certificate_positive(self):
        future = datetime.now(timezone.utc) + timedelta(days=10)
        profile = make_profile(
            certificate=CertificateInfo(
                visibility="OBSERVED",
                valid_from=future.isoformat(),
                valid_until=(future + timedelta(days=365)).isoformat(),
            )
        )
        finding = NotYetValidCertificateRule().evaluate(profile, "finding-001")
        assert finding is not None
        assert finding.finding_type == "NOT_YET_VALID_CERTIFICATE"

    def test_weak_key_positive(self):
        profile = make_profile(
            certificate=CertificateInfo(
                visibility="OBSERVED",
                key_type="RSA",
                key_size=1024,
            )
        )
        finding = WeakKeyRule().evaluate(profile, "finding-001")
        assert finding is not None
        assert finding.finding_type == "WEAK_KEY"
        assert finding.evidence["key_size"] == 1024

    def test_self_signed_positive(self):
        profile = make_profile(
            certificate=CertificateInfo(
                visibility="OBSERVED",
                subject="CN=Self",
                issuer="CN=Self",
                self_signed=True,
            )
        )
        finding = SelfSignedCertificateRule().evaluate(profile, "finding-001")
        assert finding is not None
        assert finding.finding_type == "SELF_SIGNED"

    def test_not_observable_does_not_create_false_alarms(self):
        profile = make_profile(
            certificate=CertificateInfo(visibility="NOT_OBSERVABLE")
        )
        assert ExpiredCertificateRule().evaluate(profile, "f1") is None
        assert NotYetValidCertificateRule().evaluate(profile, "f2") is None
        assert WeakKeyRule().evaluate(profile, "f3") is None
        assert SelfSignedCertificateRule().evaluate(profile, "f4") is None


# ---------------------------------------------------------------------------
# STARTTLS REGRESSION CASES (Section 18)
# ---------------------------------------------------------------------------
class TestSTARTTLSRegression:
    def test_case_1_successful_starttls(self):
        """Case 1: EHLO -> STARTTLS -> TLS handshake -> encrypted traffic => successful upgrade, no FAILED_STARTTLS."""
        profile = make_profile(
            encryption_mode="STARTTLS",
            upgrade_advertised="YES",
            upgrade_requested="YES",
            upgrade_succeeded="YES",
            authentication_before_tls="NO",
        )
        findings = evaluate_profile(profile)
        failed_findings = [f for f in findings if f.finding_type == "FAILED_STARTTLS"]
        assert len(failed_findings) == 0

    def test_case_2_advertised_not_requested(self):
        """Case 2: EHLO -> STARTTLS advertised -> client does not request it => DO NOT classify as FAILED_STARTTLS."""
        profile = make_profile(
            encryption_mode="PLAINTEXT",
            upgrade_advertised="YES",
            upgrade_requested="NO",
            upgrade_succeeded="NO",
        )
        finding = FailedSTARTTLSRule().evaluate(profile, "finding-001")
        assert finding is None

    def test_case_3_server_rejects_starttls(self):
        """Case 3: EHLO -> STARTTLS requested -> server rejects => FAILED_STARTTLS."""
        profile = make_profile(
            encryption_mode="PLAINTEXT",
            upgrade_advertised="YES",
            upgrade_requested="YES",
            upgrade_succeeded="NO",
        )
        finding = FailedSTARTTLSRule().evaluate(profile, "finding-001")
        assert finding is not None
        assert finding.finding_type == "FAILED_STARTTLS"
        assert finding.severity == "HIGH"

    def test_case_4_auth_before_tls(self):
        """Case 4: AUTH before TLS observed => AUTH_BEFORE_TLS finding."""
        profile = make_profile(
            authentication_before_tls="YES",
        )
        finding = AuthBeforeTLSRule().evaluate(profile, "finding-001")
        assert finding is not None
        assert finding.finding_type == "AUTH_BEFORE_TLS"
        assert finding.severity == "CRITICAL"


# ---------------------------------------------------------------------------
# PLAINTEXT & PFS RULES
# ---------------------------------------------------------------------------
class TestPlaintextAndPFSRules:
    def test_plaintext_positive(self):
        profile = make_profile(encryption_mode="PLAINTEXT")
        finding = PlaintextRule().evaluate(profile, "finding-001")
        assert finding is not None
        assert finding.finding_type == "PLAINTEXT"
        assert finding.severity == "CRITICAL"

    def test_pfs_observed_positive(self):
        profile = make_profile(tls=TLSInfo(version="TLS 1.3", pfs="YES"))
        finding = PFSRule().evaluate(profile, "finding-001")
        assert finding is not None
        assert finding.finding_type == "PFS"
        assert finding.severity == "INFO"

    def test_pfs_missing_positive(self):
        profile = make_profile(tls=TLSInfo(version="TLS 1.2", cipher_suite="TLS_RSA_WITH_AES_128_CBC_SHA", pfs="NO"))
        finding = PFSRule().evaluate(profile, "finding-001")
        assert finding is not None
        assert finding.finding_type == "PFS"
        assert finding.severity == "MEDIUM"

    def test_pfs_unknown_negative(self):
        profile = make_profile(tls=TLSInfo(version="TLS 1.2", cipher_suite="UNKNOWN_CIPHER", pfs="UNKNOWN"))
        finding = PFSRule().evaluate(profile, "finding-001")
        assert finding is None
