"""Generate realistic sample PCAP files for SecureMailScope security inspection."""

import struct
import socket
from pathlib import Path


def create_pcap(packets: list, output_path: str):
    """Write binary PCAP file."""
    # Global header (24 bytes)
    # Magic (0xa1b2c3d4), v2.4, thiszone=0, sigfigs=0, snaplen=65535, network=1 (Ethernet)
    global_hdr = struct.pack("=IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)

    with open(output_path, "wb") as f:
        f.write(global_hdr)

        for ts, src_ip, src_port, dst_ip, dst_port, flags, payload in packets:
            # IP Header (20 bytes)
            ip_total_len = 20 + 20 + len(payload)
            ip_hdr = struct.pack(
                "!BBHHHBBH4s4s",
                0x45,  # Version 4, IHL 5
                0,     # DSCP / ECN
                ip_total_len,
                12345, # Identification
                0x4000,# Flags (Don't fragment)
                64,    # TTL
                6,     # Protocol (TCP)
                0,     # Header checksum (0 for simulated)
                socket.inet_aton(src_ip),
                socket.inet_aton(dst_ip),
            )

            # TCP Header (20 bytes)
            data_offset = (5 << 4)  # 20 bytes header
            tcp_hdr = struct.pack(
                "!HHIIBBHHH",
                src_port,
                dst_port,
                1000, # Sequence number
                1000, # Ack number
                data_offset,
                flags,
                8192, # Window size
                0,    # Checksum
                0,    # Urgent pointer
            )

            frame_data = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00" + ip_hdr + tcp_hdr + payload

            # Packet header (16 bytes): ts_sec, ts_usec, incl_len, orig_len
            ts_sec = int(ts)
            ts_usec = int((ts - ts_sec) * 1_000_000)
            pkt_hdr = struct.pack("=IIII", ts_sec, ts_usec, len(frame_data), len(frame_data))

            f.write(pkt_hdr)
            f.write(frame_data)


def main():
    target_dir = Path(__file__).resolve().parent / "sample_captures"
    target_dir.mkdir(parents=True, exist_ok=True)

    # 1. Critical capture (Plaintext IMAP + Early Auth SMTP)
    crit_packets = [
        # Stream 0: SMTP with Auth before TLS
        (1700000000.0, "203.0.113.25", 587, "10.0.1.15", 49152, 0x12, b"220 mail.example.com ESMTP\r\n"),
        (1700000000.1, "10.0.1.15", 49152, "203.0.113.25", 587, 0x18, b"EHLO client.example.com\r\n"),
        (1700000000.2, "203.0.113.25", 587, "10.0.1.15", 49152, 0x18, b"250-mail.example.com\r\n250-STARTTLS\r\n250 AUTH LOGIN\r\n"),
        (1700000000.3, "10.0.1.15", 49152, "203.0.113.25", 587, 0x18, b"AUTH LOGIN dXNlcm5hbWU=\r\n"),
        (1700000000.4, "203.0.113.25", 587, "10.0.1.15", 49152, 0x18, b"334 UGFzc3dvcmQ6\r\n"),
        (1700000000.5, "10.0.1.15", 49152, "203.0.113.25", 587, 0x18, b"c2VjcmV0MTIz\r\n"),
        # Stream 1: Plaintext IMAP
        (1700000010.0, "203.0.113.30", 143, "10.0.1.30", 49154, 0x12, b"* OK IMAP4rev1 Ready\r\n"),
        (1700000010.1, "10.0.1.30", 49154, "203.0.113.30", 143, 0x18, b"a001 LOGIN user password123\r\n"),
        (1700000010.2, "203.0.113.30", 143, "10.0.1.30", 49154, 0x18, b"a001 OK LOGIN completed\r\n"),
    ]
    crit_path = target_dir / "sample_critical_mail.pcap"
    create_pcap(crit_packets, str(crit_path))
    print(f"Generated {crit_path} (size: {crit_path.stat().st_size} bytes)")

    # 2. Modern Secure capture (STARTTLS Clean TLS 1.3)
    secure_packets = [
        (1700000100.0, "203.0.113.25", 587, "10.0.1.15", 49160, 0x12, b"220 secure.example.com ESMTP\r\n"),
        (1700000100.1, "10.0.1.15", 49160, "203.0.113.25", 587, 0x18, b"EHLO secure.example.com\r\n"),
        (1700000100.2, "203.0.113.25", 587, "10.0.1.15", 49160, 0x18, b"250-STARTTLS\r\n250 HELP\r\n"),
        (1700000100.3, "10.0.1.15", 49160, "203.0.113.25", 587, 0x18, b"STARTTLS\r\n"),
        (1700000100.4, "203.0.113.25", 587, "10.0.1.15", 49160, 0x18, b"220 2.0.0 Ready to start TLS\r\n"),
        # Simulated TLS 1.3 Server Hello record: \x16\x03\x03 ...
        (1700000100.5, "203.0.113.25", 587, "10.0.1.15", 49160, 0x18, b"\x16\x03\x03\x00\x38\x02\x00\x00\x34\x03\x04" + b"\x00"*32 + b"\x00\x13\x02\x00"),
    ]
    secure_path = target_dir / "sample_secure_mail.pcap"
    create_pcap(secure_packets, str(secure_path))
    print(f"Generated {secure_path} (size: {secure_path.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
