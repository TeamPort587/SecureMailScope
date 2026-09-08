"""TShark JSON backend parser for SecureMailScope.

Passively extracts observable packet metadata from PCAP / PCAPNG captures
via TShark CLI without active probing or packet fabrication.
"""

import json
import logging
import os
import shutil
import subprocess
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone

from analysis.feature_extraction.models import PacketRecord

logger = logging.getLogger(__name__)

# Max file size limit: 50MB for defensive processing
MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024


class PCAPParserError(Exception):
    """Base exception for parser errors."""
    pass


class FileTooLargeError(PCAPParserError):
    """Raised when capture exceeds maximum allowed size."""
    pass


class CorruptPCAPError(PCAPParserError):
    """Raised when capture is corrupted or cannot be read."""
    pass


def find_tshark_path() -> str:
    """Locate tshark binary or raise an informative error."""
    tshark = shutil.which("tshark")
    if not tshark:
        # Common default on Windows
        win_path = r"C:\Program Files\Wireshark\tshark.exe"
        if os.path.exists(win_path):
            return win_path
        raise FileNotFoundError(
            "TShark executable not found. Please ensure Wireshark/TShark is installed and in PATH."
        )
    return tshark


def parse_packet_json(pkt_data: Dict[str, Any]) -> Optional[PacketRecord]:
    """Extract a PacketRecord from a TShark JSON packet dictionary."""
    source = pkt_data.get("_source", {})
    layers = source.get("layers", {})
    if not layers:
        return None

    # Frame layer
    frame = layers.get("frame", {})
    frame_num_str = frame.get("frame.number", "0")
    try:
        frame_number = int(frame_num_str)
    except (ValueError, TypeError):
        frame_number = 0

    time_epoch_str = frame.get("frame.time_epoch", "0")
    try:
        timestamp = float(time_epoch_str)
    except (ValueError, TypeError):
        timestamp = 0.0

    # IP / IPv6 layer
    ip_layer = layers.get("ip", {}) or layers.get("ipv6", {})
    src_ip = ip_layer.get("ip.src") or ip_layer.get("ipv6.src") or "0.0.0.0"
    dst_ip = ip_layer.get("ip.dst") or ip_layer.get("ipv6.dst") or "0.0.0.0"

    # TCP layer
    tcp_layer = layers.get("tcp", {})
    if not tcp_layer:
        # We only analyze TCP traffic for email protocols (SMTP, IMAP, POP3)
        return None

    try:
        src_port = int(tcp_layer.get("tcp.srcport", 0))
        dst_port = int(tcp_layer.get("tcp.dstport", 0))
        tcp_stream = int(tcp_layer.get("tcp.stream", 0))
    except (ValueError, TypeError):
        return None

    # TCP flags
    flags_tree = tcp_layer.get("tcp.flags_tree", {})
    syn_flag = bool(int(flags_tree.get("tcp.flags.syn", 0) or tcp_layer.get("tcp.flags.syn", 0) or 0))
    ack_flag = bool(int(flags_tree.get("tcp.flags.ack", 0) or tcp_layer.get("tcp.flags.ack", 0) or 0))
    fin_flag = bool(int(flags_tree.get("tcp.flags.fin", 0) or tcp_layer.get("tcp.flags.fin", 0) or 0))
    rst_flag = bool(int(flags_tree.get("tcp.flags.reset", 0) or tcp_layer.get("tcp.flags.reset", 0) or 0))

    # Application protocol identification
    protocol = "TCP"
    app_data_chunks = []

    # SMTP layer
    if "smtp" in layers:
        protocol = "SMTP"
        smtp_layer = layers["smtp"]
        # Extract commands and responses
        for k, v in smtp_layer.items():
            if "req.command" in k or "req.parameter" in k or "response.code" in k or "rsp.parameter" in k:
                app_data_chunks.append(str(v))
            elif isinstance(v, dict):
                for sub_k, sub_v in v.items():
                    if "line" in sub_k or "command" in sub_k or "parameter" in sub_k:
                        app_data_chunks.append(str(sub_v))

    # IMAP layer
    elif "imap" in layers:
        protocol = "IMAP"
        imap_layer = layers["imap"]
        for k, v in imap_layer.items():
            if "request" in k or "response" in k or "line" in k:
                app_data_chunks.append(str(v))

    # POP layer
    elif "pop" in layers:
        protocol = "POP3"
        pop_layer = layers["pop"]
        for k, v in pop_layer.items():
            if "request" in k or "response" in k or "line" in k:
                app_data_chunks.append(str(v))

    # TLS layer
    tls_handshake_type = None
    tls_version = None
    tls_cipher_suite = None
    tls_ciphers_offered = []
    tls_server_name = None
    tls_cert_info: Optional[Dict[str, Any]] = None

    if "tls" in layers:
        protocol = "TLS" if protocol == "TCP" else protocol
        tls_layer = layers["tls"]

        # Helper recursive search for TLS fields
        def _extract_tls_fields(obj: Any):
            nonlocal tls_handshake_type, tls_version, tls_cipher_suite, tls_server_name, tls_cert_info
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if "handshake.type" in k and tls_handshake_type is None:
                        try:
                            tls_handshake_type = int(v)
                        except (ValueError, TypeError):
                            pass
                    elif "handshake.version" in k or "record.version" in k:
                        if not tls_version:
                            tls_version = str(v)
                    elif "handshake.ciphersuite" in k and tls_cipher_suite is None:
                        tls_cipher_suite = str(v)
                    elif "handshake.ciphersuites" in k:
                        if isinstance(v, list):
                            tls_ciphers_offered.extend(str(c) for c in v)
                        else:
                            tls_ciphers_offered.append(str(v))
                    elif "server_name" in k and tls_server_name is None:
                        tls_server_name = str(v)
                    _extract_tls_fields(v)
            elif isinstance(obj, list):
                for item in obj:
                    _extract_tls_fields(item)

        _extract_tls_fields(tls_layer)

    # Certificate information from x509 layers if present
    x509_layer = layers.get("x509af") or layers.get("x509sat") or layers.get("x509ce")
    if x509_layer or "tls" in layers:
        # Scan for certificate subject / issuer / validity
        cert_data: Dict[str, Any] = {}

        def _extract_cert_fields(obj: Any):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    k_lower = k.lower()
                    if "notbefore" in k_lower or "valid_from" in k_lower or "not_before" in k_lower:
                        cert_data["valid_from"] = str(v)
                    elif "notafter" in k_lower or "valid_until" in k_lower or "not_after" in k_lower:
                        cert_data["valid_until"] = str(v)
                    elif "subject" in k_lower and "id" not in k_lower:
                        if isinstance(v, str) and "=" in v:
                            cert_data["subject"] = v
                    elif "issuer" in k_lower and "id" not in k_lower:
                        if isinstance(v, str) and "=" in v:
                            cert_data["issuer"] = v
                    elif "keysize" in k_lower or "public_key_size" in k_lower or "rsa.n" in k_lower:
                        try:
                            cert_data["key_size"] = int(v)
                        except (ValueError, TypeError):
                            pass
                    elif "algorithm" in k_lower and "public" in k_lower:
                        cert_data["key_type"] = str(v)
                    _extract_cert_fields(v)
            elif isinstance(obj, list):
                for item in obj:
                    _extract_cert_fields(item)

        _extract_cert_fields(layers)
        if cert_data:
            tls_cert_info = cert_data

    # Raw payload data if available
    payload = layers.get("data", {}).get("data.data", "")
    if payload and not app_data_chunks:
        try:
            # Decode hex payload to ascii where readable
            ascii_text = bytes.fromhex(payload.replace(":", "")).decode("latin-1", errors="ignore")
            # Filter non-printable
            printable = "".join(c for c in ascii_text if 32 <= ord(c) <= 126 or c in "\r\n")
            if printable.strip():
                app_data_chunks.append(printable)
        except Exception:
            pass

    return PacketRecord(
        frame_number=frame_number,
        timestamp=timestamp,
        src_ip=src_ip,
        src_port=src_port,
        dst_ip=dst_ip,
        dst_port=dst_port,
        tcp_stream=tcp_stream,
        tcp_flags_syn=syn_flag,
        tcp_flags_ack=ack_flag,
        tcp_flags_fin=fin_flag,
        tcp_flags_reset=rst_flag,
        protocol=protocol,
        application_data=" \n ".join(app_data_chunks),
        tls_handshake_type=tls_handshake_type,
        tls_version=tls_version,
        tls_cipher_suite=tls_cipher_suite,
        tls_cipher_suites_offered=tls_ciphers_offered,
        tls_server_name=tls_server_name,
        tls_cert_info=tls_cert_info,
        raw_layer_info=layers,
    )


def parse_pcap_with_tshark(file_path: str, timeout_sec: int = 60) -> List[PacketRecord]:
    """Parse PCAP/PCAPNG capture using TShark JSON output.

    Args:
        file_path: Absolute or relative path to capture file.
        timeout_sec: Timeout in seconds for TShark execution.

    Returns:
        List of PacketRecord objects.
    """
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"PCAP file not found: {file_path}")

    file_size = os.path.getsize(file_path)
    if file_size == 0:
        raise CorruptPCAPError("PCAP file is empty (0 bytes).")
    if file_size > MAX_FILE_SIZE_BYTES:
        raise FileTooLargeError(
            f"PCAP file size ({file_size} bytes) exceeds limit of {MAX_FILE_SIZE_BYTES} bytes."
        )

    tshark_bin = find_tshark_path()

    # Run TShark to dissect TCP and email protocols into JSON
    cmd = [
        tshark_bin,
        "-r", file_path,
        "-T", "json",
        "-o", "tcp.desegment_tcp_streams:TRUE",
    ]

    try:
        process = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_sec,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise PCAPParserError(f"TShark execution timed out after {timeout_sec} seconds.")
    except Exception as exc:
        raise PCAPParserError(f"Failed to execute TShark: {exc}")

    if process.returncode != 0 and not process.stdout.strip():
        raise CorruptPCAPError(
            f"TShark failed to parse capture (exit code {process.returncode}): {process.stderr.strip()}"
        )

    output = process.stdout.strip()
    if not output:
        return []

    try:
        packets_data = json.loads(output)
    except json.JSONDecodeError as err:
        raise CorruptPCAPError(f"Corrupt or invalid JSON emitted by TShark: {err}")

    if not isinstance(packets_data, list):
        return []

    packet_records: List[PacketRecord] = []
    for pkt in packets_data:
        record = parse_packet_json(pkt)
        if record:
            packet_records.append(record)

    return packet_records
