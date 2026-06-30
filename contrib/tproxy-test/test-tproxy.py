#!/usr/bin/env python3
"""Smoke test for i2pd transparent proxy + .i2p DNS resolver.

Pure stdlib (no dnspython/curl needed). Verifies the pipeline:
  1. DNS resolver returns an A record inside transproxy.virtualnet
  2. the transparent-proxy listener is accepting connections
  3. a TCP connect to the virtual IP is REDIRECTed by iptables to the listener
  4. i2pd recovers the original destination and maps it back to the .i2p name
     (visible as a "TransProxy: <name>:<port>" line in the log)

Stage 4 (and thus a full pass) requires the iptables REDIRECT rule to be in
place; without it, stage 3 will time out and stage 4 will not see the line.
"""
import argparse
import os
import socket
import struct
import sys
import time


def skip_name(data, pos):
    """Skip a (possibly compressed) DNS name; return offset just past it."""
    while True:
        if pos >= len(data):
            return pos
        length = data[pos]
        if length == 0:
            return pos + 1
        if (length & 0xC0) == 0xC0:  # compression pointer
            return pos + 2
        pos += 1 + length


def dns_a(name, server, port, timeout=3):
    """Return the list of A-record IPs for `name` (type A, class IN)."""
    header = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)  # id, RD, qd=1
    question = b"".join(bytes([len(lbl)]) + lbl.encode() for lbl in name.split(".")) + b"\x00"
    question += struct.pack(">HH", 1, 1)  # QTYPE=A, QCLASS=IN
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(header + question, (server, port))
        data, _ = sock.recvfrom(4096)
    finally:
        sock.close()
    ancount = struct.unpack(">H", data[6:8])[0]
    pos = skip_name(data, 12) + 4  # past question name + qtype/qclass
    ips = []
    for _ in range(ancount):
        pos = skip_name(data, pos)
        rtype, _rclass, _ttl, rdlen = struct.unpack(">HHIH", data[pos:pos + 10])
        pos += 10
        rdata = data[pos:pos + rdlen]
        pos += rdlen
        if rtype == 1 and rdlen == 4:
            ips.append(".".join(str(b) for b in rdata))
    return ips


def in_cidr(ip, cidr):
    net, prefix = cidr.split("/")
    prefix = int(prefix)

    def to_u32(s):
        parts = s.split(".")
        if len(parts) != 4:
            return None
        val = 0
        for i, p in enumerate(parts):
            v = int(p)
            if v < 0 or v > 255:
                return None
            val |= v << (8 * (3 - i))
        return val

    ip_u = to_u32(ip)
    net_u = to_u32(net)
    if ip_u is None or net_u is None:
        return False
    mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    return (ip_u & mask) == (net_u & mask)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dns", default="127.0.0.1:5353", help="DNS resolver host:port")
    ap.add_argument("--listener", default="127.0.0.1:9041", help="transproxy listener host:port")
    ap.add_argument("--virtualnet", default="10.108.0.0/16", help="expected transproxy.virtualnet CIDR")
    ap.add_argument("--name", default="test.i2p", help=".i2p name to resolve & connect")
    ap.add_argument("--port", type=int, default=80, help="destination port to connect to on the VIP")
    ap.add_argument("--log", default="", help="i2pd log file to scan for the TransProxy line")
    ap.add_argument("--connect-timeout", type=float, default=5.0, help="seconds to wait for the VIP connect")
    args = ap.parse_args()

    failures = 0

    # ---- Stage 1: DNS -------------------------------------------------------
    print(f"[1/4] DNS A {args.name} @ {args.dns}")
    dhost, _, dport = args.dns.partition(":")
    try:
        ips = dns_a(args.name, dhost, int(dport))
    except Exception as e:
        print(f"  FAIL: DNS query failed: {e}")
        print("       -> is dnsresolver.enabled=true and reachable?")
        return 1
    if not ips:
        print("  FAIL: no A record returned")
        return 1
    vip = ips[0]
    print(f"  ok : {args.name} -> {vip}")
    if not in_cidr(vip, args.virtualnet):
        print(f"  FAIL: {vip} is NOT inside transproxy.virtualnet {args.virtualnet}")
        print(f"       -> set transproxy.virtualnet = {args.virtualnet} (must match your iptables -d range)")
        return 1
    print(f"  ok : {vip} is inside {args.virtualnet}")

    # ---- Stage 2: listener --------------------------------------------------
    print(f"[2/4] transproxy listener @ {args.listener}")
    lhost, _, lport = args.listener.partition(":")
    try:
        probe = socket.create_connection((lhost, int(lport)), timeout=3)
        probe.close()
        print("  ok : listener accepts connections")
    except Exception as e:
        print(f"  FAIL: cannot connect to listener: {e}")
        print("       -> is transproxy.enabled=true and transproxy.port correct?")
        return 1

    # ---- Stage 3: connect to the VIP (iptables should REDIRECT it) ----------
    print(f"[3/4] connect to {vip}:{args.port}  (iptables REDIRECT -> {lport})")
    redirected = False
    try:
        s = socket.create_connection((vip, args.port), timeout=args.connect_timeout)
        s.settimeout(args.connect_timeout)
        try:
            s.sendall(f"GET / HTTP/1.0\r\nHost: {args.name}\r\n\r\n".encode())
        except OSError:
            pass  # i2pd may close the socket quickly; the connect itself is the signal
        time.sleep(min(args.connect_timeout, 3.0))
        s.close()
        redirected = True
        print("  ok : connected — iptables REDIRECT is in place")
    except socket.timeout:
        print("  WARN: connect timed out — iptables REDIRECT rule likely missing")
        print("        iptables -t nat -A OUTPUT -p tcp -d 10.108.0.0/16 -j REDIRECT --to-ports 9041")
    except OSError as e:
        print(f"  WARN: connect failed ({e}) — iptables REDIRECT rule likely missing")
        print("        iptables -t nat -A OUTPUT -p tcp -d 10.108.0.0/16 -j REDIRECT --to-ports 9041")

    # ---- Stage 4: i2pd recovered the original dst ---------------------------
    needle = f"TransProxy: {args.name}:{args.port}"
    print(f"[4/4] scan i2pd log for '{needle}'")
    if not args.log:
        print("  skip: no --log file given")
    elif not os.path.exists(args.log):
        print("  skip: log file not found")
    else:
        deadline = time.time() + 6
        seen = False
        while time.time() < deadline:
            with open(args.log, "rb") as f:
                txt = f.read().decode("utf-8", "replace")
            if needle in txt:
                seen = True
                break
            time.sleep(0.5)
        if seen:
            print("  ok : i2pd recovered original dst and mapped it back to the .i2p name")
            print()
            print("RESULT: transparent-proxy pipeline WORKS")
            print("        DNS -> VIP -> REDIRECT -> recover original dst -> map -> CreateStream")
            print("        (the I2P stream itself only completes if the .i2p name is real & reachable)")
            return 0
        else:
            print("  FAIL: no TransProxy log line — the connection did not arrive as a redirect")
            failures += 1

    print()
    if redirected:
        print("RESULT: listener + DNS OK; connect reached the listener. Re-run with --log to confirm stage 4.")
        return 0
    print("RESULT: DNS + listener OK, but the VIP connect was not redirected (iptables rule missing?).")
    return 1 if not redirected else 0


if __name__ == "__main__":
    sys.exit(main())
