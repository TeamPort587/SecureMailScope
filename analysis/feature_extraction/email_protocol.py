"""Email protocol command inspection and encryption mode detection for SecureMailScope."""

from typing import List, Tuple
from analysis.feature_extraction.models import PacketRecord, SecurityInfo


def _scan_for_keywords(
    packet_list: List[PacketRecord],
    keywords: Tuple[str, ...],
) -> Tuple[bool, List[int]]:
    """Scan for keywords across packets, handling commands segmented across packets."""
    matched_frames: List[int] = []

    # 1. Direct packet inspection
    for p in packet_list:
        text = p.application_data.upper()
        if not text:
            continue
        if any(w in text for w in keywords):
            matched_frames.append(p.frame_number)

    if matched_frames:
        return True, matched_frames

    # 2. Segmented stream inspection
    # Sort packets chronologically by timestamp / frame_number
    sorted_pkts = sorted(packet_list, key=lambda p: (p.timestamp, p.frame_number))
    char_frames: List[int] = []
    stream_chars: List[str] = []

    for p in sorted_pkts:
        txt = p.application_data.upper()
        for ch in txt:
            stream_chars.append(ch)
            char_frames.append(p.frame_number)

    stream_text = "".join(stream_chars)
    for kw in keywords:
        pos = 0
        while True:
            idx = stream_text.find(kw, pos)
            if idx == -1:
                break
            span = set(char_frames[idx : idx + len(kw)])
            matched_frames.extend(span)
            pos = idx + len(kw)

    if matched_frames:
        return True, sorted(set(matched_frames))

    return False, []


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

    # Implicit TLS check: standard ports 465 (SMTPS), 993 (IMAPS), 995 (POP3S)
    implicit_ports = {465, 993, 995}
    is_implicit_tls = server_port in implicit_ports

    # 1. Check for STARTTLS advertisement by server
    adv_found, adv_frames = _scan_for_keywords(
        server_packets,
        ("250-STARTTLS", "250 STARTTLS", "STARTTLS", "STLS"),
    )
    upgrade_advertised = "YES" if adv_found else "NO"
    evidence_frames.extend(adv_frames)

    # 2. Check for STARTTLS requested by client
    req_found, req_frames = _scan_for_keywords(
        client_packets,
        ("STARTTLS", "STLS"),
    )
    upgrade_requested = "YES" if req_found else "NO"
    evidence_frames.extend(req_frames)

    # 3. Check for authentication commands
    auth_observed = False
    auth_frames: List[int] = []

    auth_keywords: Tuple[str, ...] = ()
    if protocol == "SMTP":
        auth_keywords = ("AUTH LOGIN", "AUTH PLAIN", "AUTH ")
    elif protocol == "IMAP":
        auth_keywords = ("AUTHENTICATE", " LOGIN ", "\nLOGIN ")
    elif protocol == "POP3":
        auth_keywords = ("USER ", "PASS ", "AUTH ")

    if auth_keywords:
        auth_found, a_frames = _scan_for_keywords(client_packets, auth_keywords)
        if auth_found:
            auth_observed = True
            auth_frames.extend(a_frames)
            evidence_frames.extend(a_frames)

    # Determine encryption mode and upgrade success
    if is_implicit_tls:
        encryption_mode = "IMPLICIT_TLS"
        upgrade_advertised = "UNKNOWN"
        upgrade_requested = "UNKNOWN"
        upgrade_succeeded = "YES" if has_tls else "NO"
    elif upgrade_requested == "YES":
        encryption_mode = "STARTTLS"
        upgrade_succeeded = "YES" if has_tls else "NO"
    elif has_tls:
        encryption_mode = "STARTTLS" if upgrade_advertised == "YES" else "IMPLICIT_TLS"
        upgrade_succeeded = "YES"
    elif len(packets) >= 2 and protocol in ("SMTP", "IMAP", "POP3"):
        encryption_mode = "PLAINTEXT"
        upgrade_succeeded = "NO"
    else:
        encryption_mode = "UNKNOWN"

    # Evaluate auth_before_tls
    if auth_observed:
        if not has_tls:
            auth_before_tls = "YES"
        elif first_tls_frame is not None:
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
    return sec_info, sorted(set(evidence_frames))
