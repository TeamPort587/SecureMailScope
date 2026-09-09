"""Email protocol command inspection and encryption mode detection for SecureMailScope."""

from typing import List, Tuple
from analysis.feature_extraction.models import PacketRecord, SecurityInfo


def analyze_email_security(
    packets: List[PacketRecord],
    client_packets: List[PacketRecord],
    server_packets: List[PacketRecord],
    protocol: str,
    server_port: int,
    completeness: str,
) -> Tuple[SecurityInfo, List[int]]:
    """Analyze application-layer commands and TLS presence to classify security posture.

    Returns:
        (SecurityInfo, list_of_evidence_frame_numbers)
    """
    evidence_frames: List[int] = []

    # Identify if TLS handshake occurs and in which frame
    tls_handshake_frames = [p.frame_number for p in packets if p.tls_handshake_type is not None or p.protocol == "TLS"]
    has_tls = len(tls_handshake_frames) > 0
    first_tls_frame = tls_handshake_frames[0] if has_tls else None

    # Track upgrade advertising, requesting, and succeeding
    upgrade_advertised = "NO"
    upgrade_requested = "NO"
    upgrade_succeeded = "NO"
    auth_before_tls = "NO"

    # Implicit TLS check: standard ports 465 (SMTPS), 993 (IMAPS), 995 (POP3S)
    # or packets start directly with TLS ClientHello without cleartext commands
    implicit_ports = {465, 993, 995}
    is_implicit_tls = server_port in implicit_ports

    # Look for command keywords
    auth_observed = False
    auth_frames = []

    for pkt in packets:
        text = pkt.application_data.upper()
        if not text:
            continue

        # Check for STARTTLS advertisement by server
        if any(w in text for w in ("250-STARTTLS", "250 STARTTLS", "STARTTLS", "STLS")):
            if pkt in server_packets:
                upgrade_advertised = "YES"
                evidence_frames.append(pkt.frame_number)

        # Check for STARTTLS requested by client
        if any(w in text for w in ("STARTTLS", "STLS")):
            if pkt in client_packets:
                upgrade_requested = "YES"
                evidence_frames.append(pkt.frame_number)

        # Check for authentication commands
        # SMTP: AUTH, AUTH LOGIN, AUTH PLAIN
        # IMAP: AUTHENTICATE, LOGIN
        # POP3: USER, PASS, AUTH
        is_auth_pkt = False
        if protocol == "SMTP" and any(cmd in text for cmd in ("AUTH LOGIN", "AUTH PLAIN", "AUTH ")):
            is_auth_pkt = True
        elif protocol == "IMAP" and any(cmd in text for cmd in ("AUTHENTICATE", " LOGIN ")):
            is_auth_pkt = True
        elif protocol == "POP3" and any(cmd in text for cmd in ("USER ", "PASS ", "AUTH ")):
            is_auth_pkt = True

        if is_auth_pkt and pkt in client_packets:
            auth_observed = True
            auth_frames.append(pkt.frame_number)
            evidence_frames.append(pkt.frame_number)

    # Determine encryption mode and upgrade success
    if is_implicit_tls:
        encryption_mode = "IMPLICIT_TLS"
        upgrade_advertised = "UNKNOWN"
        upgrade_requested = "UNKNOWN"
        upgrade_succeeded = "YES" if has_tls else "NO"
    elif upgrade_advertised == "YES" or upgrade_requested == "YES":
        encryption_mode = "STARTTLS"
        if has_tls and upgrade_requested == "YES":
            upgrade_succeeded = "YES"
        else:
            upgrade_succeeded = "NO"
    elif has_tls:
        encryption_mode = "IMPLICIT_TLS"
        upgrade_succeeded = "YES"
    elif len(packets) >= 2 and protocol in ("SMTP", "IMAP", "POP3"):
        encryption_mode = "PLAINTEXT"
        upgrade_advertised = "NO"
        upgrade_requested = "NO"
        upgrade_succeeded = "NO"
    else:
        encryption_mode = "UNKNOWN"

    # Evaluate auth_before_tls
    if auth_observed:
        if not has_tls:
            auth_before_tls = "YES"
        elif first_tls_frame is not None:
            # If any auth command occurred before first TLS frame
            if any(f < first_tls_frame for f in auth_frames):
                auth_before_tls = "YES"
            else:
                auth_before_tls = "NO"
        else:
            auth_before_tls = "YES"
    else:
        auth_before_tls = "NO"

    sec_info = SecurityInfo(
        encryption_mode=encryption_mode,
        upgrade_advertised=upgrade_advertised,
        upgrade_requested=upgrade_requested,
        upgrade_succeeded=upgrade_succeeded,
        authentication_before_tls=auth_before_tls,
        capture_completeness=completeness,
    )
    return sec_info, evidence_frames
