"""Helper script to create a sample SMTP PCAP for testing with Postman or curl."""

import struct
import time

def create_pcap(filename="data/sample_smtp.pcap"):
    # PCAP Global Header (24 bytes)
    # Magic (0xa1b2c3d4), Major (2), Minor (4), Zone (0), SigFigs (0), SnapLen (65535), LinkType (1 = Ethernet)
    global_header = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)

    packets_data = []

    # IP addresses: Client = 10.0.1.15, Server = 203.0.113.25
    src_ip = bytes([10, 0, 1, 15])
    dst_ip = bytes([203, 0, 113, 25])
    client_port = 49152
    server_port = 587

    def make_eth_ip_tcp(src, dst, sport, dport, seq, ack, flags, payload=b""):
        # Ethernet Header (14 bytes)
        eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
        # IPv4 Header (20 bytes)
        total_len = 20 + 20 + len(payload)
        ip = struct.pack(
            "!BBHHHBBH4s4s",
            0x45, 0, total_len, 1234, 0x4000, 64, 6, 0, src, dst
        )
        # TCP Header (20 bytes)
        data_offset = (5 << 4)
        tcp = struct.pack(
            "!HHIIBBHHH",
            sport, dport, seq, ack, data_offset, flags, 65535, 0, 0
        )
        return eth + ip + tcp + payload

    # Frame 1: SYN (Client -> Server)
    p1 = make_eth_ip_tcp(src_ip, dst_ip, client_port, server_port, 1000, 0, 0x02)
    # Frame 2: SYN+ACK (Server -> Client)
    p2 = make_eth_ip_tcp(dst_ip, src_ip, server_port, client_port, 2000, 1001, 0x12)
    # Frame 3: ACK (Client -> Server)
    p3 = make_eth_ip_tcp(src_ip, dst_ip, client_port, server_port, 1001, 2001, 0x10)
    # Frame 4: Server Greeting (Server -> Client)
    p4 = make_eth_ip_tcp(dst_ip, src_ip, server_port, client_port, 2001, 1001, 0x18, b"220 mail.example.com ESMTP Service Ready\r\n")
    # Frame 5: Client EHLO (Client -> Server)
    p5 = make_eth_ip_tcp(src_ip, dst_ip, client_port, server_port, 1001, 2043, 0x18, b"EHLO mail.client.com\r\n")
    # Frame 6: Server 250-STARTTLS (Server -> Client)
    p6 = make_eth_ip_tcp(dst_ip, src_ip, server_port, client_port, 2043, 1023, 0x18, b"250-mail.example.com\r\n250-STARTTLS\r\n250 OK\r\n")
    # Frame 7: Client STARTTLS (Client -> Server)
    p7 = make_eth_ip_tcp(src_ip, dst_ip, client_port, server_port, 1023, 2095, 0x18, b"STARTTLS\r\n")
    # Frame 8: Server 220 Ready (Server -> Client)
    p8 = make_eth_ip_tcp(dst_ip, src_ip, server_port, client_port, 2095, 1033, 0x18, b"220 2.0.0 Ready to start TLS\r\n")
    # Frame 9: FIN (Client -> Server)
    p9 = make_eth_ip_tcp(src_ip, dst_ip, client_port, server_port, 1033, 2125, 0x11)
    # Frame 10: FIN (Server -> Client)
    p10 = make_eth_ip_tcp(dst_ip, src_ip, server_port, client_port, 2125, 1034, 0x11)

    all_frames = [p1, p2, p3, p4, p5, p6, p7, p8, p9, p10]

    with open(filename, "wb") as f:
        f.write(global_header)
        base_ts = 1788949800
        for i, frame in enumerate(all_frames):
            pkt_hdr = struct.pack("<IIII", base_ts + i, i * 1000, len(frame), len(frame))
            f.write(pkt_hdr)
            f.write(frame)

    print(f"Created sample PCAP: {filename}")

if __name__ == "__main__":
    create_pcap()
