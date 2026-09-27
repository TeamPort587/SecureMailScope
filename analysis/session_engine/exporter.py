"""Session PCAP Extractor for SecureMailScope.

Extracts exact packets belonging to a single TCP stream from a source PCAP/PCAPNG capture,
preserving original packet bytes, timestamps, headers, and ordering for independent Wireshark verification.
"""

import hashlib
import logging
import os
import shutil
import struct
import subprocess
import sys
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


class SessionExportError(Exception):
    """Raised when session PCAP extraction fails."""
    pass


def find_tshark_binary() -> Optional[str]:
    """Locate tshark binary or return None."""
    tshark = shutil.which("tshark")
    if tshark:
        return tshark
    win_path = r"C:\Program Files\Wireshark\tshark.exe"
    if os.path.exists(win_path):
        return win_path
    return None


def compute_file_sha256(path: str) -> str:
    """Compute SHA-256 hash of a file."""
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def count_pcap_packets(pcap_path: str) -> int:
    """Count packets in a standard PCAP file."""
    try:
        with open(pcap_path, "rb") as f:
            magic = f.read(4)
            if magic not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
                return 0
            endian = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
            f.seek(24)  # Skip global header
            count = 0
            while True:
                hdr = f.read(16)
                if len(hdr) < 16:
                    break
                _, _, incl_len, _ = struct.unpack(endian + "IIII", hdr)
                f.seek(incl_len, os.SEEK_CUR)
                count += 1
            return count
    except Exception:
        return 0


def _extract_pure_python(
    source_pcap_path: str,
    target_pcap_path: str,
    tcp_stream: int,
) -> int:
    """Extract packets belonging to a stream from a standard PCAP using pure Python."""
    with open(source_pcap_path, "rb") as src:
        magic = src.read(4)
        if magic not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
            raise SessionExportError("Pure Python extraction only supports standard PCAP format.")

        endian = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
        gh_data = src.read(20)
        global_header = magic + gh_data

        stream_map: Dict[tuple, int] = {}
        matching_packets = []

        while True:
            ph_data = src.read(16)
            if len(ph_data) < 16:
                break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian + "IIII", ph_data)
            packet_data = src.read(incl_len)
            if len(packet_data) < incl_len:
                break

            # Parse Ethernet and IPv4/TCP
            if len(packet_data) >= 34:
                eth_type = struct.unpack("!H", packet_data[12:14])[0]
                ip_offset = 14
                if eth_type == 0x8100 and len(packet_data) >= 38:
                    eth_type = struct.unpack("!H", packet_data[16:18])[0]
                    ip_offset = 18

                if eth_type == 0x0800 and len(packet_data) >= ip_offset + 20:
                    ip_hdr = packet_data[ip_offset:ip_offset + 20]
                    proto = ip_hdr[9]
                    ihl = (ip_hdr[0] & 0x0F) * 4
                    if proto == 6 and len(packet_data) >= ip_offset + ihl + 4:
                        src_ip = ip_hdr[12:16]
                        dst_ip = ip_hdr[16:20]
                        tcp_hdr = packet_data[ip_offset + ihl:ip_offset + ihl + 4]
                        src_port, dst_port = struct.unpack("!HH", tcp_hdr)
                        key = (
                            min(src_ip, dst_ip), min(src_port, dst_port),
                            max(src_ip, dst_ip), max(src_port, dst_port)
                        )
                        if key not in stream_map:
                            stream_map[key] = len(stream_map)
                        if stream_map[key] == tcp_stream:
                            matching_packets.append((ph_data, packet_data))

    if not matching_packets:
        raise SessionExportError(f"No packets found for TCP stream {tcp_stream} in capture.")

    os.makedirs(os.path.dirname(os.path.abspath(target_pcap_path)), exist_ok=True)
    with open(target_pcap_path, "wb") as dst:
        dst.write(global_header)
        for ph, pdata in matching_packets:
            dst.write(ph)
            dst.write(pdata)

    return len(matching_packets)


def extract_session_pcap(
    source_pcap_path: str,
    target_pcap_path: str,
    tcp_stream: int,
    backend: str = "auto",
) -> Dict[str, Any]:
    """Extract all packets belonging to a TCP stream into a standalone PCAP file.

    Args:
        source_pcap_path: Path to original capture file (.pcap or .pcapng).
        target_pcap_path: Destination path for extracted session PCAP.
        tcp_stream: The integer TCP stream index to extract.
        backend: "auto", "tshark", or "python".

    Returns:
        Metadata dictionary including packet_count, file_size_bytes, sha256, and wireshark_filter.
    """
    if not os.path.isfile(source_pcap_path):
        raise FileNotFoundError(f"Source PCAP not found: {source_pcap_path}")

    os.makedirs(os.path.dirname(os.path.abspath(target_pcap_path)), exist_ok=True)
    tshark_bin = find_tshark_binary()

    use_tshark = (backend in ("auto", "tshark")) and (tshark_bin is not None)

    packet_count = 0
    if use_tshark:
        cmd = [
            tshark_bin,
            "-r", source_pcap_path,
            "-Y", f"tcp.stream == {tcp_stream}",
            "-w", target_pcap_path,
        ]
        try:
            res = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=30,
                check=False,
            )
            if res.returncode != 0 or not os.path.exists(target_pcap_path) or os.path.getsize(target_pcap_path) == 0:
                raise SessionExportError(f"TShark extraction returned code {res.returncode}: {res.stderr.strip()}")
            
            # Count packets via tshark
            cnt_cmd = [tshark_bin, "-r", target_pcap_path, "-T", "fields", "-e", "frame.number"]
            cnt_res = subprocess.run(cnt_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=15)
            packet_count = len([line for line in cnt_res.stdout.splitlines() if line.strip()])
        except Exception as exc:
            if backend == "tshark":
                raise SessionExportError(f"TShark session export failed: {exc}")
            logger.warning(f"TShark export failed ({exc}), attempting pure Python fallback...")
            use_tshark = False

    if not use_tshark:
        packet_count = _extract_pure_python(source_pcap_path, target_pcap_path, tcp_stream)

    if not os.path.exists(target_pcap_path) or os.path.getsize(target_pcap_path) == 0:
        raise SessionExportError(f"Failed to generate valid session PCAP for stream {tcp_stream}.")

    file_size = os.path.getsize(target_pcap_path)
    file_sha256 = compute_file_sha256(target_pcap_path)
    source_sha256 = compute_file_sha256(source_pcap_path)

    return {
        "analysis_id": None,
        "session_id": None,
        "tcp_stream": tcp_stream,
        "packet_count": packet_count,
        "file_size_bytes": file_size,
        "source_pcap_sha256": source_sha256,
        "extracted_pcap_sha256": file_sha256,
        "wireshark_filter": f"tcp.stream == {tcp_stream}",
        "target_pcap_path": target_pcap_path,
    }


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python -m analysis.session_engine.exporter <source_pcap> <target_pcap> <tcp_stream>")
        sys.exit(1)

    src = sys.argv[1]
    tgt = sys.argv[2]
    stream = int(sys.argv[3])
    info = extract_session_pcap(src, tgt, stream)
    print(f"Extracted TCP stream {stream} ({info['packet_count']} packets, {info['file_size_bytes']} bytes) -> {tgt}")
