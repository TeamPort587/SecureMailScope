"""Data models for SecureMailScope Analysis Engine.

These typed data models represent the internal structures passed between
parser, session engine, feature extraction, and rule engine.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass
class PacketRecord:
    """Represents an observable packet extracted from a PCAP/PCAPNG capture."""

    frame_number: int
    timestamp: float  # Epoch timestamp in seconds
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    tcp_stream: int
    tcp_flags_syn: bool = False
    tcp_flags_ack: bool = False
    tcp_flags_fin: bool = False
    tcp_flags_reset: bool = False
    protocol: str = "TCP"  # e.g. "SMTP", "IMAP", "POP3", "TLS", "TCP"
    application_data: str = ""  # Raw text or extracted lines
    tls_handshake_type: Optional[int] = None
    tls_version: Optional[str] = None
    tls_cipher_suite: Optional[str] = None
    tls_cipher_suites_offered: List[str] = field(default_factory=list)
    tls_server_name: Optional[str] = None
    tls_cert_bytes: Optional[bytes] = None
    tls_cert_info: Optional[Dict[str, Any]] = None
    raw_layer_info: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Session:
    """Represents a reconstructed TCP stream/session."""

    session_id: str
    tcp_stream: int
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    protocol: str = "UNKNOWN"  # SMTP, IMAP, POP3, UNKNOWN
    service: str = "unknown"  # submission, mail-access, relay, etc.
    completeness: str = "UNKNOWN"  # COMPLETE, PARTIAL, UNKNOWN
    first_frame: int = 0
    last_frame: int = 0
    packet_count: int = 0
    packets: List[PacketRecord] = field(default_factory=list)
    client_packets: List[PacketRecord] = field(default_factory=list)
    server_packets: List[PacketRecord] = field(default_factory=list)


@dataclass
class SecurityInfo:
    """Security status for a session."""

    encryption_mode: str = "UNKNOWN"  # STARTTLS, PLAINTEXT, IMPLICIT_TLS, UNKNOWN
    upgrade_advertised: str = "UNKNOWN"  # YES, NO, UNKNOWN, NOT_APPLICABLE
    upgrade_requested: str = "UNKNOWN"  # YES, NO, UNKNOWN, NOT_APPLICABLE
    upgrade_succeeded: str = "UNKNOWN"  # YES, NO, UNKNOWN, NOT_APPLICABLE
    authentication_before_tls: str = "UNKNOWN"  # YES, NO, UNKNOWN
    capture_completeness: str = "UNKNOWN"  # COMPLETE, PARTIAL, UNKNOWN

    def to_dict(self) -> Dict[str, str]:
        return {
            "encryption_mode": self.encryption_mode,
            "upgrade_advertised": self.upgrade_advertised,
            "upgrade_requested": self.upgrade_requested,
            "upgrade_succeeded": self.upgrade_succeeded,
            "authentication_before_tls": self.authentication_before_tls,
            "capture_completeness": self.capture_completeness,
        }


@dataclass
class TLSInfo:
    """TLS metadata extracted from handshake."""

    version: Optional[str] = None  # e.g. "TLS 1.2", "TLS 1.3", "TLS 1.0"
    cipher_suite: Optional[str] = None
    pfs: str = "UNKNOWN"  # YES, NO, UNKNOWN

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "cipher_suite": self.cipher_suite,
            "pfs": self.pfs,
        }


@dataclass
class CertificateInfo:
    """X.509 Certificate metadata where observable."""

    visibility: str = "OBSERVED"  # OBSERVED, NOT_OBSERVABLE
    subject: Optional[str] = None
    issuer: Optional[str] = None
    valid_from: Optional[str] = None  # ISO 8601 UTC string
    valid_until: Optional[str] = None  # ISO 8601 UTC string
    key_type: Optional[str] = None  # RSA, EC, etc.
    key_size: Optional[int] = None
    signature_algorithm: Optional[str] = None
    self_signed: Optional[bool] = None

    def to_dict(self) -> Dict[str, Any]:
        if self.visibility == "NOT_OBSERVABLE":
            return {"visibility": "NOT_OBSERVABLE"}
        res: Dict[str, Any] = {"visibility": "OBSERVED"}
        if self.subject is not None:
            res["subject"] = self.subject
        if self.issuer is not None:
            res["issuer"] = self.issuer
        if self.valid_from is not None:
            res["valid_from"] = self.valid_from
        if self.valid_until is not None:
            res["valid_until"] = self.valid_until
        if self.key_type is not None:
            res["key_type"] = self.key_type
        if self.key_size is not None:
            res["key_size"] = self.key_size
        if self.self_signed is not None:
            res["self_signed"] = self.self_signed
        return res


@dataclass
class SecurityProfile:
    """Normalized security profile for an email protocol session.

    Matches docs/contracts/django-analysis-response.json sessions array element.
    """

    session_id: str
    protocol: str  # SMTP, IMAP, POP3
    service: str  # submission, mail-access, relay, etc.
    client_ip: str
    server_ip: str
    client_port: int
    server_port: int
    security: SecurityInfo = field(default_factory=SecurityInfo)
    tls: Optional[TLSInfo] = None
    certificate: Optional[CertificateInfo] = None
    tcp_stream: int = 0
    frame_numbers: List[int] = field(default_factory=list)
    capture_reference_time: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        res: Dict[str, Any] = {
            "session_id": self.session_id,
            "protocol": self.protocol,
            "service": self.service,
            "client_ip": self.client_ip,
            "server_ip": self.server_ip,
            "client_port": self.client_port,
            "server_port": self.server_port,
            "security": self.security.to_dict(),
            "tls": self.tls.to_dict() if self.tls else None,
            "certificate": self.certificate.to_dict() if self.certificate else None,
        }
        return res


@dataclass
class Finding:
    """Deterministic security finding with concrete evidence."""

    finding_id: str
    session_id: str
    finding_type: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    title: str
    description: str
    confidence: str  # OBSERVED, INFERRED
    evidence: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "session_id": self.session_id,
            "finding_type": self.finding_type,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "confidence": self.confidence,
            "evidence": self.evidence,
        }
