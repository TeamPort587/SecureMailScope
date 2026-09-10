"""TLS metadata extraction and normalization for SecureMailScope."""

import re
from typing import Any, List, Optional
from analysis.feature_extraction.models import PacketRecord, TLSInfo

CIPHER_SUITE_MAP = {
    # TLS 1.3
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0x1304: "TLS_AES_128_CCM_SHA256",
    0x1305: "TLS_AES_128_CCM_8_SHA256",

    # TLS 1.2 / 1.1 / 1.0 ECDHE
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    0xCCAA: "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xC009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    0xC00A: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    0xC023: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    0xC024: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
    0xC027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    0xC028: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",

    # DHE
    0x009E: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    0x009F: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    0x0067: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
    0x006B: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
    0x0033: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
    0x0039: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",

    # RSA Static
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256",
    0x003D: "TLS_RSA_WITH_AES_256_CBC_SHA256",

    # Legacy / Weak
    0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    0x0005: "TLS_RSA_WITH_RC4_128_SHA",
    0x0004: "TLS_RSA_WITH_RC4_128_MD5",
    0x0001: "TLS_RSA_WITH_NULL_MD5",
    0x0002: "TLS_RSA_WITH_NULL_SHA",
    0x003B: "TLS_RSA_WITH_NULL_SHA256",
}


def normalize_cipher_suite(raw_cipher: Any) -> Optional[str]:
    """Normalize raw cipher suite hex code, dict, or string to canonical IANA name."""
    if not raw_cipher:
        return None

    # Handle dictionary or nested structures
    if isinstance(raw_cipher, dict):
        sub_val = raw_cipher.get("tls.handshake.ciphersuite")
        if not sub_val:
            sub_val = next((v for v in raw_cipher.values() if isinstance(v, (str, int))), None)
        return normalize_cipher_suite(sub_val) if sub_val else None

    # Handle integer representation
    if isinstance(raw_cipher, int):
        return CIPHER_SUITE_MAP.get(raw_cipher, f"0x{raw_cipher:04X}")

    raw = str(raw_cipher).strip()
    if not raw:
        return None

    # Already canonical name
    if raw.startswith("TLS_") or raw.startswith("SSL_"):
        return raw

    # Handle stringified dictionary e.g. "{'tls.handshake.ciphersuite': '0x002f'}"
    if "0x" in raw or "0X" in raw:
        match = re.search(r"0[xX][0-9a-fA-F]+", raw)
        if match:
            hex_str = match.group(0)
            try:
                int_val = int(hex_str, 16)
                return CIPHER_SUITE_MAP.get(int_val, hex_str.upper())
            except ValueError:
                return hex_str

    # Decimal string (e.g. "4866")
    if raw.isdigit():
        try:
            int_val = int(raw)
            if int_val in CIPHER_SUITE_MAP:
                return CIPHER_SUITE_MAP[int_val]
        except ValueError:
            pass

    return raw

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
            norm_cipher = normalize_cipher_suite(pkt.tls_cipher_suite)
            if norm_cipher:
                negotiated_cipher = norm_cipher

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
