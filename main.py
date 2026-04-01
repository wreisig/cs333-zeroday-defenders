# NAME_OF_FILE = "test.bin"
#
# def wr_to_bin(binary_content):
#     wr_file = open(binary_content, "wb")
#     try:
#         wr_file.write(binary_content)
#     finally:
#         wr_file.close()
#     print(wr_file)
#
# def read_from_bin(filename):
#     file = open(filename, "rb")
#     file_contents = file.read()
#     return file_contents
#
#
# if __name__ == "__main__":
#     binary_content = read_from_bin(NAME_OF_FILE)
#     # fix
#     wr_to_bin(binary_content)


#!/usr/bin/env python3
"""
CS333 — Network Packet Builder

Shows how binary network packets are built by hand, layer by layer:
    Ethernet frame  →  IPv4 header  →  TCP / UDP / ICMP segment

Run:  python main.py
"""
import socket
import struct

# ── Protocol constants ──────────────────────────────────────────────────────────
ETHERTYPE_IPV4 = 0x0800
PROTO_ICMP     = 1
PROTO_TCP      = 6
PROTO_UDP      = 17


# ── Checksum (RFC 1071) ─────────────────────────────────────────────────────────
def inet_checksum(data: bytes) -> int:
    """Sum all 16-bit words, fold the carry bits, return the one's complement."""
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack_from("!H", data, i)[0] for i in range(0, len(data), 2))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


# ── Layer 2 — Ethernet header (14 bytes) ────────────────────────────────────────
def make_ethernet_header(dst_mac: str, src_mac: str) -> bytes:
    """
    Ethernet II header layout:
      6 bytes  destination MAC
      6 bytes  source MAC
      2 bytes  EtherType  (0x0800 = IPv4)
    """
    dst = bytes(int(h, 16) for h in dst_mac.split(":"))
    src = bytes(int(h, 16) for h in src_mac.split(":"))
    return struct.pack("!6s6sH", dst, src, ETHERTYPE_IPV4)


# ── Layer 3 — IPv4 header (20 bytes) ────────────────────────────────────────────
def make_ipv4_header(src_ip: str, dst_ip: str, protocol: int, payload_len: int) -> bytes:
    """
    IPv4 header layout (no options):
      1 byte   version (4) + IHL (5 → 20-byte header)
      1 byte   DSCP / ECN
      2 bytes  total length  (header + payload)
      2 bytes  identification
      2 bytes  flags + fragment offset
      1 byte   TTL
      1 byte   protocol  (TCP=6, UDP=17, ICMP=1)
      2 bytes  checksum  (computed over header bytes)
      4 bytes  source IP
      4 bytes  destination IP
    """
    total_len = 20 + payload_len
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,                        # version=4, IHL=5
        0,                           # DSCP/ECN
        total_len,
        0x1234,                      # identification
        0x4000,                      # DF flag set, no fragmentation
        64,                          # TTL
        protocol,
        0,                           # checksum placeholder
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )
    checksum = inet_checksum(header)
    return header[:10] + struct.pack("!H", checksum) + header[12:]


# ── Layer 4 — TCP segment ───────────────────────────────────────────────────────
def make_tcp_segment(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    seq: int = 1000,
    ack: int = 0,
    flags: int = 0x002,     # SYN by default
    payload: bytes = b"",
) -> bytes:
    """
    TCP header layout (20 bytes, no options):
      2 bytes  source port
      2 bytes  destination port
      4 bytes  sequence number
      4 bytes  acknowledgment number
      2 bytes  data offset (high 4 bits) + flags (low 9 bits)
      2 bytes  window size
      2 bytes  checksum  (computed over pseudo-header + segment)
      2 bytes  urgent pointer

    Common flags:  SYN=0x002  ACK=0x010  PSH=0x008  FIN=0x001  RST=0x004
    """
    data_off_flags = (5 << 12) | (flags & 0x1FF)   # data offset = 5 (20 bytes)
    header = struct.pack(
        "!HHIIHHHH",
        src_port, dst_port,
        seq, ack,
        data_off_flags, 65535,   # window size
        0, 0,                     # checksum placeholder, urgent pointer
    )
    # TCP checksum covers a pseudo-header + the full segment
    pseudo = struct.pack(
        "!4s4sBBH",
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
        0, PROTO_TCP, len(header) + len(payload),
    )
    checksum = inet_checksum(pseudo + header + payload)
    header = header[:16] + struct.pack("!H", checksum) + header[18:]
    return header + payload


# ── Layer 4 — UDP datagram ──────────────────────────────────────────────────────
def make_udp_datagram(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    payload: bytes = b"",
) -> bytes:
    """
    UDP header layout (8 bytes):
      2 bytes  source port
      2 bytes  destination port
      2 bytes  length  (header + payload)
      2 bytes  checksum
    """
    length = 8 + len(payload)
    header = struct.pack("!HHHH", src_port, dst_port, length, 0)
    pseudo = struct.pack(
        "!4s4sBBH",
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
        0, PROTO_UDP, length,
    )
    checksum = inet_checksum(pseudo + header + payload)
    header = header[:6] + struct.pack("!H", checksum)
    return header + payload


# ── Layer 4 — ICMP Echo Request (ping) ─────────────────────────────────────────
def make_icmp_echo(
    identifier: int = 1,
    sequence: int = 1,
    payload: bytes = b"Hello CS333!",
) -> bytes:
    """
    ICMP Echo Request layout (type 8, code 0):
      1 byte   type        (8 = echo request)
      1 byte   code        (0)
      2 bytes  checksum    (computed over header + payload)
      2 bytes  identifier
      2 bytes  sequence number
    """
    header = struct.pack("!BBHHH", 8, 0, 0, identifier, sequence)
    checksum = inet_checksum(header + payload)
    header = header[:2] + struct.pack("!H", checksum) + header[4:]
    return header + payload


# ── Assemble a full frame ───────────────────────────────────────────────────────
def build_frame(eth: bytes, ip: bytes, transport: bytes) -> bytes:
    """Stack the three layers into one Ethernet frame."""
    return eth + ip + transport


# ── Hex dump helper ─────────────────────────────────────────────────────────────
def hexdump(data: bytes, width: int = 16) -> None:
    """Print bytes as: offset | hex | ASCII."""
    for i in range(0, len(data), width):
        chunk = data[i : i + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        asc_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"  {i:04x}  {hex_part:<{width * 3}}  {asc_part}")


# ── Demo ────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    SRC_IP  = "192.168.1.100"
    DST_IP  = "10.0.0.1"
    SRC_MAC = "aa:bb:cc:dd:ee:ff"
    DST_MAC = "ff:ee:dd:cc:bb:aa"

    # TCP SYN
    print("=== TCP SYN packet ===")
    tcp_seg = make_tcp_segment(SRC_IP, DST_IP, src_port=54321, dst_port=80, flags=0x002)
    tcp_frame = build_frame(
        make_ethernet_header(DST_MAC, SRC_MAC),
        make_ipv4_header(SRC_IP, DST_IP, PROTO_TCP, len(tcp_seg)),
        tcp_seg,
    )
    print(f"  {len(tcp_frame)} bytes  (14 Ethernet + 20 IPv4 + 20 TCP)")
    hexdump(tcp_frame)

    # UDP
    print("\n=== UDP packet ===")
    payload = b"Hello, CS333!"
    udp_seg = make_udp_datagram(SRC_IP, DST_IP, src_port=54321, dst_port=53, payload=payload)
    udp_frame = build_frame(
        make_ethernet_header(DST_MAC, SRC_MAC),
        make_ipv4_header(SRC_IP, DST_IP, PROTO_UDP, len(udp_seg)),
        udp_seg,
    )
    print(f"  {len(udp_frame)} bytes  (14 Ethernet + 20 IPv4 + 8 UDP + {len(payload)} payload)")
    hexdump(udp_frame)

    # ICMP Echo Request (ping)
    print("\n=== ICMP Echo Request (ping) ===")
    icmp_msg = make_icmp_echo()
    icmp_frame = build_frame(
        make_ethernet_header(DST_MAC, SRC_MAC),
        make_ipv4_header(SRC_IP, DST_IP, PROTO_ICMP, len(icmp_msg)),
        icmp_msg,
    )
    print(f"  {len(icmp_frame)} bytes  (14 Ethernet + 20 IPv4 + 8 ICMP + 12 payload)")
    hexdump(icmp_frame)
