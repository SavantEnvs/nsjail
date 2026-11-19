#!/usr/bin/env python3
"""Writes seed inputs for fuzz_nstun_frames: <mode byte> then (u16 BE length, raw IP frame)*.
Guest is 10.255.255.2 / fc00::2 (nsjail's user_net defaults). Usage: gen_nstun_seeds.py <outdir>"""
import os, socket, struct, sys

G4, D4 = socket.inet_aton("10.255.255.2"), socket.inet_aton("93.184.216.34")
G6, D6 = socket.inet_pton(socket.AF_INET6, "fc00::2"), socket.inet_pton(socket.AF_INET6, "2001:db8::10")

def csum(b):
    if len(b) % 2: b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def ip4(proto, payload, src=G4, dst=D4):
    h = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0x4000, 64, proto, 0, src, dst)
    h = h[:10] + struct.pack("!H", csum(h)) + h[12:]
    return h + payload

def ip6(nh, payload, src=G6, dst=D6):
    return struct.pack("!IHBB16s16s", 0x60000000, len(payload), nh, 64, src, dst) + payload

def l4(proto, seg, v6):
    if v6:
        ph = G6 + D6 + struct.pack("!IxxxB", len(seg), proto)
    else:
        ph = G4 + D4 + struct.pack("!BBH", 0, proto, len(seg))
    off = {6: 16, 17: 6, 58: 2}[proto]
    c = csum(ph + seg)
    return seg[:off] + struct.pack("!H", c) + seg[off + 2:]

def tcp(sport, dport, seq, ack, flags, data=b"", opts=b"", v6=False):
    hl = (20 + len(opts)) // 4
    seg = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, hl << 4, flags, 65535, 0, 0) + opts + data
    seg = l4(6, seg, v6)
    return ip6(6, seg) if v6 else ip4(6, seg)

def udp(sport, dport, data, v6=False):
    seg = struct.pack("!HHHH", sport, dport, 8 + len(data), 0) + data
    seg = l4(17, seg, v6)
    return ip6(17, seg) if v6 else ip4(17, seg)

def icmp4_echo():
    m = struct.pack("!BBHHH", 8, 0, 0, 0x1234, 1) + b"pingpong"
    m = m[:2] + struct.pack("!H", csum(m)) + m[4:]
    return ip4(1, m)

def icmp6_echo():
    m = struct.pack("!BBHHH", 128, 0, 0, 0x1234, 1) + b"pingpong"
    return ip6(58, l4(58, m, True))

SYN, ACK, PSH, FIN, RST = 0x02, 0x10, 0x08, 0x01, 0x04
MSS = struct.pack("!BBH", 2, 4, 1460) + b"\x01\x03\x03\x07"  # MSS, NOP, wscale 7
DNS = bytes.fromhex("12340100000100000000000003777777076578616d706c6503636f6d0000010001")
HTTP = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"

def tcp_session(v6):
    return [tcp(40000, 80, 1000, 0, SYN, opts=MSS, v6=v6),
            tcp(40000, 80, 1001, 1, ACK, v6=v6),
            tcp(40000, 80, 1001, 1, ACK | PSH, HTTP, v6=v6),
            tcp(40000, 80, 1001 + len(HTTP), 1, ACK | FIN, v6=v6),
            tcp(40000, 80, 1002 + len(HTTP), 2, RST, v6=v6)]

def seed(mode, frames):
    return bytes([mode]) + b"".join(struct.pack("!H", len(f)) + f for f in frames)

out = sys.argv[1]
os.makedirs(out, exist_ok=True)
seeds = {
    "tcp4_redirect": seed(0, tcp_session(False)),
    "tcp6_redirect": seed(0, tcp_session(True)),
    "tcp4_socks5": seed(1, tcp_session(False)),
    "tcp4_connect": seed(2, tcp_session(False)),
    "tcp6_socks5": seed(1, tcp_session(True)),
    "udp4_dns_redirect": seed(0, [udp(5353, 53, DNS), udp(5353, 53, DNS)]),
    "udp6_dns_redirect": seed(0, [udp(5353, 53, DNS, True)]),
    "udp4_dns_socks5": seed(1, [udp(5353, 53, DNS)]),
    "icmp_echo": seed(0, [icmp4_echo(), icmp6_echo()]),
    "reject_mixed": seed(3, [tcp(40000, 443, 1, 0, SYN, v6=False), udp(1, 53, DNS), icmp4_echo(), tcp(40000, 443, 1, 0, SYN, v6=True)]),
    "drop_mixed": seed(4, tcp_session(False) + [udp(5353, 53, DNS, True), icmp6_echo()]),
}
for name, data in seeds.items():
    with open(os.path.join(out, name), "wb") as f:
        f.write(data)
