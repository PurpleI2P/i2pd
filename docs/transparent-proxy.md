# Transparent proxy (TPROXY) + .i2p DNS resolver

i2pd can act like Tor's `TransPort` + `DNSPort`: applications resolve a
`.i2p` name to a **virtual IPv4** and connect to it normally; the kernel
diverts those connections to i2pd, which maps the virtual IP back to the
`.i2p` name and bridges the TCP connection to an I2P stream. No SOCKS/HTTP
proxy needs to be configured in the application.

This is the I2P analogue of Tor's transparent proxying. Two services work
together, sharing one virtual-IP table (`AddressMapper`):

1. **DNS resolver** (`dnsresolver.*`) — answers A/AAAA/PTR for `.i2p` by
   allocating a virtual IPv4 from `transproxy.virtualnet`.
2. **Transparent proxy** (`transproxy.*`) — a TCP listener that recovers the
   *original* destination of a diverted connection (Linux `TPROXY` or NAT
   `REDIRECT`), maps the destination IP back to the `.i2p` name, and opens
   an I2P stream.

```
  app does getaddrinfo "foo.i2p"
   │
   ├──► DNS resolver (:5353)  ── allocates virtual IP 10.192.a.b ──► A record
   │
  app connects TCP to 10.192.a.b:port
   │  (routed to the i2pd box, then TPROXY-intercepted)
   ▼
  Transparent proxy (:7654)
   │  getsockname()/SO_ORIGINAL_DST  -> 10.192.a.b
   │  AddressMapper -> "foo.i2p"
   ▼
  I2P stream  <->  app socket
```

## Choosing the virtual network

`transproxy.virtualnet` (default `10.192.0.0/10`) is the **routable** network
that `.i2p` names are mapped into. Unlike the SOCKS torsocks automap
(`255.0.0.0/8`, which is reserved/unroutable and only works because the IP is
rewritten locally and never put on the wire), this range must be **routable**
so real TCP packets can travel across a LAN to the i2pd gateway.

Requirements for the range:

- **Routable** — the kernel and any intermediate routers will forward it.
- **Disjoint** from your real networks (no collisions with hosts the gateway
  also needs to reach normally).
- **Large enough** that collisions are a non-issue. The default
  `10.192.0.0/10` (~4M addresses) avoids the low `10.0.0.0/8` and
  `192.168.0.0/16` commonly used on home/office LANs. `100.64.0.0/10`
  (RFC 6598 CGNAT) is another good choice.

At startup i2pd validates the range and rejects malformed CIDRs and
unroutable/reserved blocks (`0.0.0.0/8`, `127.0.0.0/8`, `169.254.0.0/16`,
multicast `224.0.0.0/4+`, and the SOCKS `255.0.0.0/8` torsocks range), and
warns if a configured listener sits inside the virtual range.

## Configuration

```ini
[transproxy]
enabled = true
# tproxy (IP_TRANSPARENT, gateway-capable) or redirect (NAT REDIRECT, localhost only)
type = tproxy
address = 127.0.0.1     # set to a LAN IP to act as a gateway
port = 7654
virtualnet = 10.192.0.0/10
keys = transient-proxy    # or shareddest, or a key file
# plus the usual inbound.*/outbound.*/i2cp.*/streaming.* tuning options

[dnsresolver]
enabled = true
address = 127.0.0.1       # set to a LAN IP to act as a gateway
port = 5353
tcp = false               # also serve DNS over TCP
```

Defaults bind to `127.0.0.1` (loopback only). To act as a **gateway** for
other hosts, set the addresses to a LAN IP (or `0.0.0.0`) — this is an
explicit opt-in to bind publicly.

## Permissions

`TPROXY` mode sets `IP_TRANSPARENT` on the listening socket, which requires
`CAP_NET_ADMIN` (or root). `REDIRECT` mode does not need `IP_TRANSPARENT` but
still needs the firewall rule below. To act as a gateway, the box must have
IP forwarding enabled:

```
sysctl -w net.ipv4.ip_forward=1
```

Grant the capability to the binary (instead of running i2pd as root):

```
setcap 'cap_net_admin,cap_net_bind_service=+ep' /usr/bin/i2pd
```

## Gateway case (LAN clients route through the i2pd box)

Let `VNET=10.192.0.0/10` be `transproxy.virtualnet`. The i2pd box advertises
a route for `VNET` to itself; LAN clients use the gateway as their DNS
resolver and route `VNET` to it.

On the i2pd gateway, intercept routed packets to `VNET` with TPROXY:

```
# Mark traffic to divert via a separate routing table
ip rule add fwmark 1 lookup 100
ip route add local 0.0.0.0/0 dev lo table 100

# Intercept TCP destined to the virtual range
iptables -t mangle -A PREROUTING -p tcp -d 10.192.0.0/10 \
    -j TPROXY --on-port 7654 --tproxy-mark 1
```

On clients: use the gateway as the DNS server for `.i2p` (push it via
DHCP/dnsmasq), and ensure `VNET` is routed to the gateway (it is the
gateway's own subnet, or add a static route on the LAN router):

```
ip route add 10.192.0.0/10 via <gateway>
```

Nothing I2P-specific needs to be installed on the clients.

## Local / host-only case (same box originates the traffic)

Route DNS for `.i2p` to the local resolver and intercept locally-originated
traffic to `VNET`:

```
# Send .i2p DNS queries to the local resolver
iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-ports 5353

# Intercept locally-originated TCP to the virtual range (OUTPUT + TPROXY)
iptables -t mangle -A OUTPUT -p tcp -d 10.192.0.0/10 -j MARK --set-mark 1
ip rule add fwmark 1 lookup 100
ip route add local 0.0.0.0/0 dev lo table 100
iptables -t mangle -A PREROUTING -p tcp -d 10.192.0.0/10 -j TPROXY \
    --on-port 7654 --tproxy-mark 1
```

## Simpler REDIRECT mode (localhost only)

`transproxy.type = redirect` uses NAT `REDIRECT` instead of `TPROXY`. It
needs no `fwmark`/routing-table setup, but only works for
locally-originated traffic on the same host:

```
iptables -t nat -A OUTPUT -p tcp -d 10.192.0.0/10 -j REDIRECT --to-ports 7654
```

With `REDIRECT`, i2pd recovers the original destination via `SO_ORIGINAL_DST`.

## Safety

- The transparent proxy **only** accepts connections whose original
  destination is inside `transproxy.virtualnet` **and** has a live mapping.
  Anything else is closed, so i2pd cannot be used as an open relay to
  arbitrary IPs.
- The DNS resolver **only** answers `.i2p` (plus in-range `PTR`); other
  queries are refused. Nothing is forwarded upstream by default, so no DNS
  leaks occur.
- Virtual-IP mappings expire after a period of inactivity (default 30 min)
  so the finite virtual range is reclaimed.

## Platform support

`TPROXY`/`IP_TRANSPARENT` is Linux-only. On other platforms the transparent
proxy compiles to a stub that logs "not supported" and does not bind; the DNS
resolver is portable.
