"""X.509 Certificate extraction and normalization for SecureMailScope."""

from typing import List, Optional
from analysis.feature_extraction.models import CertificateInfo, PacketRecord, TLSInfo


def extract_certificate_info(
    packets: List[PacketRecord],
    tls_info: Optional[TLSInfo],
) -> Optional[CertificateInfo]:
    """Extract X.509 Certificate information from session packets where observable."""
    if not tls_info:
        return None

    # In TLS 1.3, certificates are encrypted in the handshake and not observable passively
    if tls_info.version == "TLS 1.3":
        return CertificateInfo(visibility="NOT_OBSERVABLE")

    # Search for extracted certificate info across packets
    cert_info_dict = None
    for pkt in packets:
        if pkt.tls_cert_info:
            cert_info_dict = pkt.tls_cert_info
            break

    if not cert_info_dict:
        # If TLS was used but no certificate handshake was observed in the capture
        return CertificateInfo(visibility="NOT_OBSERVABLE")

    subject = cert_info_dict.get("subject")
    issuer = cert_info_dict.get("issuer")
    valid_from = cert_info_dict.get("valid_from")
    valid_until = cert_info_dict.get("valid_until")
    key_type = cert_info_dict.get("key_type") or "RSA"
    key_size = cert_info_dict.get("key_size") or 2048

    self_signed = None
    if subject and issuer:
        self_signed = bool(subject.strip() == issuer.strip())

    return CertificateInfo(
        visibility="OBSERVED",
        subject=subject,
        issuer=issuer,
        valid_from=valid_from,
        valid_until=valid_until,
        key_type=key_type,
        key_size=key_size,
        self_signed=self_signed,
    )
