"""TLS metadata extraction and normalization for SecureMailScope."""

from typing import List, Optional
from analysis.feature_extraction.models import PacketRecord, TLSInfo

TLS_VERSION_MAP = {
    "0x0300": "SSLv3",
    "0x0301": "TLS 1.0",
    "0x0302": "TLS 1.1",
    "0x0303": "TLS 1.2",
    "0x0304": "TLS 1.3",
    "768": "SSLv3",
    "769": "TLS 1.0",
    "770": "TLS 1.1",
    "771": "TLS 1.2",
    "772": "TLS 1.3",
}


def normalize_tls_version(raw_version: Optional[str]) -> Optional[str]:
    """Normalize raw version string or hex code to canonical TLS version."""
    if not raw_version:
        return None
    raw = str(raw_version).strip()
    if raw in ("TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3", "SSLv3"):
        return raw
    if raw in TLS_VERSION_MAP:
        return TLS_VERSION_MAP[raw]
    raw_lower = raw.lower()
    if "1.3" in raw_lower:
        return "TLS 1.3"
    if "1.2" in raw_lower:
        return "TLS 1.2"
    if "1.1" in raw_lower:
        return "TLS 1.1"
    if "1.0" in raw_lower:
        return "TLS 1.0"
    if "sslv3" in raw_lower:
        return "SSLv3"
    return raw


def determine_pfs(version: Optional[str], cipher_suite: Optional[str]) -> str:
    """Assess whether Perfect Forward Secrecy (PFS) is provided."""
    if version == "TLS 1.3":
        return "YES"
    if not cipher_suite:
        return "UNKNOWN"

    cipher_upper = cipher_suite.upper()
    if any(k in cipher_upper for k in ("ECDHE", "DHE", "EDH", "CHACHA20_POLY1305")):
        return "YES"
    if "RSA" in cipher_upper and not any(k in cipher_upper for k in ("ECDHE", "DHE")):
        return "NO"

    return "UNKNOWN"


def extract_tls_info(packets: List[PacketRecord]) -> Optional[TLSInfo]:
    """Extract negotiated TLS metadata from session packets."""
    negotiated_version = None
    negotiated_cipher = None

    for pkt in packets:
        # Check server hello or handshake fields
        if pkt.tls_version:
            norm_ver = normalize_tls_version(pkt.tls_version)
            if norm_ver:
                # Prefer TLS 1.3 / 1.2 if multiple records exist
                if not negotiated_version or norm_ver in ("TLS 1.3", "TLS 1.2"):
                    negotiated_version = norm_ver

        if pkt.tls_cipher_suite:
            negotiated_cipher = pkt.tls_cipher_suite

    if not negotiated_version and not negotiated_cipher:
        # Check if any packet was classified as TLS protocol
        has_tls_pkt = any(p.protocol == "TLS" for p in packets)
        if not has_tls_pkt:
            return None
        # Defaults to unknown TLS info
        return TLSInfo(version=None, cipher_suite=None, pfs="UNKNOWN")

    pfs = determine_pfs(negotiated_version, negotiated_cipher)
    return TLSInfo(
        version=negotiated_version,
        cipher_suite=negotiated_cipher,
        pfs=pfs,
    )
