# Implementation Plan: Transparent Proxy (TPROXY) + .i2p DNS Resolver for i2pd

This document describes how to add Tor-style transparent proxying (Linux
`TPROXY`) and a DNS resolver for `.i2p` (the I2P analogue of Tor's `.onion`
`DNSPort`) to i2pd.

---

## 1. Background: how Tor does it

Tor's relevant pieces (in `../tor`):

- **`TransPort` listener** (`src/core/mainloop/connection.c`): when
  `TransProxyType tproxy` is set and the listener is a `TransPort`, Tor sets
  `setsockopt(s, SOL_IP, IP_TRANSPARENT, 1)` on the listening socket. This lets
  the socket accept connections whose *original* destination IP is not the
  local machine (packets redirected by `iptables -j TPROXY`).
- **Recovering the original destination** (`connection_edge.c`,
  `destination_from_socket()`): for `TPT_TPROXY`, Tor calls `getsockname()` on
  the accepted socket — with TPROXY the kernel reports the *original* foreign
  destination address/port rather than the local listener address. For
  non-TPROXY redirect (NAT/`REDIRECT`) it instead uses
  `getsockopt(SO_ORIGINAL_DST)`.
- **Treating the trans-connection like a SOCKS CONNECT**
  (`connection_ap_process_transparent()`): it fakes a completed SOCKS handshake
  (`socks->command = SOCKS_COMMAND_CONNECT; has_finished = 1`), fills the
  destination from the socket, then routes it through the normal
  rewrite/attach path.
- **DNS server** (`src/feature/client/dnsserv.c`): a `DNSPort` listener answers
  A/AAAA/PTR queries. For names that should be anonymised, Tor *automaps* them:
  `addressmap_register_virtual_address()` allocates a virtual IP out of
  `VirtualAddrNetwork` and returns it as the DNS answer. A later transparent
  connection to that virtual IP is mapped back to the original hostname before
  the circuit is built (`addressmap`).
- **The glue is automapping**: DNS returns a fake/virtual IP; the transparent
  proxy receives a connection to that fake IP and reverses the mapping to get
  the real `.onion` host. Without it, an app that resolves a name and then
  connects to the resulting IP could not be routed.

### What maps onto i2pd

i2pd **already has the automap primitive** in the SOCKS proxy
(`libi2pd_client/SOCKS.cpp` / `SOCKS.h`):

- `SOCKSServer::ResolveAddress(name)` allocates a virtual IPv4 in the
  `255.0.0.0/8` range (`0xFF000000 | (hash & 0xFFFFFF)`) and stores
  `vip -> (i2p-name, timestamp)` in `m_Resolved`.
- `SOCKSServer::GetResolvedAddress(vip)` reverses it.
- The SOCKS handler already substitutes a `255.x.x.x` request back to the stored
  `.i2p` name (the "torsocks" path).

**Important caveat — why we cannot reuse `255.0.0.0/8` for the gateway.**
The existing SOCKS scheme works *only* because the virtual IP never travels
over the network: the SOCKS client and i2pd are on the same host, and the
handler substitutes the `255.x.x.x` value back to the `.i2p` name *before any
packet is sent*. `255.0.0.0/8` is reserved space (`240.0.0.0/4` "future use" +
`255.255.255.255` limited broadcast) and is **not routable** — the Linux
stack, routers, and most NICs will refuse to forward it. For a **gateway**,
where other hosts on a LAN resolve via our DNS and then send real TCP packets
that must be *routed* to the i2pd box and TPROXY-intercepted, the virtual range
must be a genuinely routable address block that operators can plumb through
their infrastructure. So the gateway uses a **separate, configurable, routable
range** (see Step 0), distinct from the SOCKS `255.0.0.0/8` torsocks range.

So the design below **reuses the automap *mechanism*** (allocate a virtual IPv4,
store `vip -> name`, reverse on connect) but with a configurable routable range,
and adds (a) a DNS responder that allocates from it, and (b) a TPROXY TCP
listener that reads the original destination IP, reverses it, and
opens an I2P stream.

---

## 2. i2pd architecture facts relevant to this work

- **Service base classes** (`libi2pd_client/I2PService.h`):
  - `I2PService` — owns a `ClientDestination`, manages handlers, `CreateStream()`.
  - `ServiceAcceptor<Protocol>` — generic async-accept loop; subclasses
    implement `CreateHandler(socket)`.
  - `TCPIPAcceptor` — `ServiceAcceptor<boost::asio::ip::tcp>` binding to
    `address:port`.
  - `I2PServiceHandler` — per-connection handler; `SocketsPipe` /
    `CreateSocketsPipe()` and `I2PTunnelConnection` bridge a local socket to an
    I2P stream.
  - `I2PService::CreateStream(complete, name, port)` resolves a `.i2p` name via
    the address book and builds a stream (`I2PService.cpp:183`).
- **SOCKS proxy** (`SOCKS.cpp`): existing automap (`m_Resolved`,
  `ResolveAddress`, `GetResolvedAddress`), `CMD_RESOLVE` returns a virtual IP.
- **Address book** (`AddressBook.h/.cpp`): `GetAddress(name)` /
  `FindAddress(name)` resolve `.i2p`, `.b32.i2p`, and base64 to an `Address`.
  This is i2pd's name system; the DNS responder validates names against it.
- **ClientContext** (`ClientContext.cpp`): constructs services from config
  (`ReadSocksProxy()`, `ReadHttpProxy()`, `ReadTunnels()`), and from the tunnels
  config file by `type` (`I2P_TUNNELS_SECTION_TYPE_*` in `ClientContext.h`).
  Has `Start()`/`Stop()`/`ReloadConfig()` lifecycle and per-service members
  (e.g. `m_SocksProxy`).
- **Config** (`libi2pd/Config.cpp`): boost.program_options groups, e.g.
  `socksproxy.*`, `httpproxy.*`. New `transproxy.*` / `dnsresolver.*` groups go
  here.
- **Build**: `filelist.mk` globs `libi2pd_client/*.cpp`, so new `.cpp` files in
  that directory are picked up automatically by the Makefiles. The CMake build
  (`build/CMakeLists.txt`) lists sources explicitly — check and update it too.
- **Platform**: TPROXY is Linux-only. All new socket code must be guarded by
  `#if defined(__linux__)` (and feature macros `IP_TRANSPARENT`,
  `IP_RECVORIGDSTADDR`, `SO_ORIGINAL_DST`) with graceful fallback/disable
  elsewhere.

---

## 3. High-level design

Let `V/p` be the configured **routable** virtual network (e.g. `10.192.0.0/10`).

```
  LAN host (or local app) does getaddrinfo "foo.i2p"
   client ──────────────────────────────────────►  DNS resolver (UDP/TCP :5353)
                                                     │  validate name, allocate
                                                     │  virtual IP from V/p
            ◄──── A 10.192.a.b (in V/p) ─────────────┘
   client connects TCP to 10.192.a.b:port
            │  packet is ROUTED across the LAN to the i2pd gateway,
            │  then TPROXY (mangle/PREROUTING) intercepts it ─► trans listener
            ▼
        TPROXY listener (IP_TRANSPARENT, :7654)
            │ getsockname() -> original dst 10.192.a.b:port
            │ AddressMapper::GetName(10.192.a.b) -> "foo.i2p"
            ▼
        I2PService::CreateStream("foo.i2p", port) -> I2P stream
            │
        SocketsPipe(client socket  <->  i2p stream)
```

Because the virtual IP is now *routed over the wire* (not substituted locally
like the SOCKS path), the range must be routable and the operator must point a
route for `V/p` at the gateway box.

Shared component: a single **automap table** keyed by virtual IPv4, used by the
DNS resolver and the TPROXY listener (and optionally SOCKS). The gateway table
uses the configured routable range `V/p`; the legacy SOCKS torsocks table keeps
`255.0.0.0/8`. Factor the *mechanism* out of `SOCKSServer` into a reusable
`AddressMapper` parameterised by its range, so each consumer gets an instance
bound to the appropriate network.

---

## 4. Step-by-step implementation

### Step 0 — Choose the virtual address range (gateway-routable)
This is a **gateway**, so the virtual range must be a genuinely **routable**
private network that operators can plumb through their infrastructure — *not*
the SOCKS `255.0.0.0/8` torsocks range (reserved/unroutable; the SOCKS path
only works because the IP is rewritten locally and never put on the wire).

- **Make the range a config option**, `transproxy.virtualnet` (CIDR), with a
  sensible routable default. Suggested default: a slice of RFC 1918 / shared
  CGNAT space that is rarely used on small LANs, e.g. **`10.192.0.0/10`**
  (~4M addresses) or `100.64.0.0/10` (RFC 6598 CGNAT). Avoid `192.168.0.0/16`
  and the low `10.0.0.0/8` which collide with common home/office LANs. Let the
  operator override it to fit their topology.
- Requirements the chosen range must satisfy:
  - Routable: the kernel and any intermediate routers will forward it.
  - Disjoint from the operator's real networks (no collisions with hosts the
    gateway also needs to reach normally).
  - Large enough to make collisions a non-issue (see allocation below).
- **Allocation strategy** (replaces the 24-bit `255.x` hash): allocate
  **sequentially** within `V/p` (next free address, wrapping with LRU eviction)
  rather than by hashing the name. Sequential allocation eliminates collisions
  entirely and keeps the mapping stable for the lifetime of an entry. Keep a
  forward map `name -> vip` too so repeated lookups of the same name return the
  same vip while it is live. (Hashing is acceptable only as a fallback for very
  large ranges; sequential + LRU is simpler and collision-free.)
- The DNS resolver and TPROXY listener **share one `AddressMapper` instance**
  bound to `V/p`, so a name resolved via DNS and later connected via TPROXY
  resolves to the same vip.
- Keep the legacy SOCKS automap on `255.0.0.0/8` unchanged (its own
  `AddressMapper` instance) to preserve torsocks behaviour.

### Step 1 — Extract a shared AutoMap helper
**New file:** `libi2pd_client/AddressResolver.h` (+ `.cpp` if needed; can be
header-only).

- Define `class AddressMapper` **parameterised by its virtual network**
  (constructor takes a base address + prefix length, e.g. `V/p`). It holds:
  - reverse map `std::map<address_v4, std::pair<std::string,uint64_t>>`
    (vip -> (name, ts)),
  - forward map `std::map<std::string, address_v4>` (name -> vip) so repeat
    lookups return the same vip,
  - the next-free cursor for sequential allocation,
  - a mutex (DNS and TPROXY run on different services / threads, so it must be
    thread-safe — the current SOCKS-only version is not).
- Methods:
  - `address_v4 Resolve(std::string_view name)` — return existing vip or
    allocate the next free address in `V/p` (LRU-evict the oldest when the range
    is exhausted); refresh timestamp.
  - `std::string GetName(const address_v4&) const` — reverse lookup.
  - `bool IsVirtual(const address_v4&) const` — test membership in `V/p`
    (mask compare), **not** a hardcoded `255.0.0.0/8`.
  - `void Cleanup(uint64_t olderThanMs)` — evict stale entries from both maps.
- Refactor `SOCKSServer` to delegate to an `AddressMapper` constructed with the
  legacy `255.0.0.0/8` range (keep `ResolveAddress`/`GetResolvedAddress` as thin
  wrappers so the SOCKS handler logic is untouched; the 24-bit hash becomes a
  detail internal to that instance, or switch it to sequential too).
- The gateway (DNS + TPROXY) uses a **separate** `AddressMapper` instance
  constructed with the configured `transproxy.virtualnet`. Own it in
  `ClientContext` and pass it by `shared_ptr` to both services so they share one
  table — this is what makes resolve-then-connect work across DNS and TPROXY.

### Step 2 — DNS resolver service
**New files:** `libi2pd_client/I2PDNSResolver.h` / `.cpp`.

- Implement a minimal DNS server over **UDP** (and optionally TCP) using
  `boost::asio::ip::udp::socket`. Don't pull in a new dependency; parse the DNS
  wire format directly (header + a single question is enough; mirror id, set QR,
  RA, RCODE).
- Supported query types:
  - `A` for a `*.i2p` name → if the name resolves/looks like a valid I2P address
    (`b32`/hostname known to the address book, or syntactically `.i2p`), call
    `AddressMapper::Resolve(name)` and answer with the allocated virtual IP
    (from the configured `transproxy.virtualnet`, e.g. `10.192.a.b`) and a short
    TTL.
  - `AAAA` → return empty NOERROR (no IPv6 mapping) or NXDOMAIN.
  - `PTR` for an in-range reverse name → `AddressMapper::GetName()` to answer
    with the original `.i2p` host (mirrors Tor's reverse automap).
  - Non-`.i2p` names → `REFUSED` (or NXDOMAIN). Do **not** forward upstream
    (that would leak DNS); optionally add a `dnsresolver.upstream` later, off by
    default.
- Lifecycle: subclass nothing heavy — model it on the proxy services. Bind
  address/port from config. Provide `Start()`/`Stop()`.
- Decide whether name validation is synchronous (treat any syntactic `.i2p` as
  resolvable and let the later stream attempt fail) or asynchronous (trigger
  `AddressBook::LookupAddress` and defer the DNS answer). **Start synchronous**:
  allocate a virtual IP for any well-formed `.i2p`/`.b32.i2p` name; this matches
  how the SOCKS automap already behaves and avoids blocking the DNS reply on a
  netDb lookup.

### Step 3 — TPROXY transparent listener service
**New files:** `libi2pd_client/TransparentProxy.h` / `.cpp`.

- `class TransparentProxyServer : public TCPIPAcceptor` (or a thin subclass of
  `ServiceAcceptor<tcp>`), constructed with listen address/port and a
  `ClientDestination` (own key or shared), plus a `shared_ptr<AddressMapper>`.
- **Set `IP_TRANSPARENT` on the listening socket.** `ServiceAcceptor::Start()`
  creates the acceptor with the endpoint in its constructor, so to inject the
  sockopt either:
  - Override `Start()` to create the `tcp::acceptor` in steps:
    `open()` → `set_option(reuse_address)` → set `IP_TRANSPARENT` via
    `setsockopt(acceptor.native_handle(), SOL_IP, IP_TRANSPARENT, &1)` →
    `bind()` → `listen()` → `Accept()`; **or**
  - Add a virtual hook (e.g. `ConfigureAcceptorSocket()`) to `ServiceAcceptor`
    called after `m_Acceptor` is constructed but before `listen()`, and override
    it here. (Cleaner; touches the template once.)
  - Guard all of this with `#if defined(__linux__) && defined(IP_TRANSPARENT)`.
- **Per-connection handler** (`TransparentProxyHandler : I2PServiceHandler`):
  1. On `Handle()`, call `getsockname()` on the accepted socket
     (`socket->local_endpoint()` returns the original destination under TPROXY —
     verify; if not, fall back to `getsockopt(SO_ORIGINAL_DST)` for the
     `REDIRECT`/NAT case).
  2. Extract original dst IPv4 + port.
  3. If `AddressMapper::IsVirtual(ip)`, `name = GetName(ip)`. If empty → close
     (unknown/expired mapping).
  4. `GetOwner()->CreateStream(handleComplete, name, port)`.
  5. On completion, bridge with `I2PTunnelConnection` /
     `CreateSocketsPipe(owner, sock, stream)` exactly as the SOCKS handler does
     after `SocksRequestSuccess()` (see `SOCKS.cpp` `HandleStreamRequestComplete`
     → `I2PTunnelConnection`).
- Also support the **NAT/REDIRECT** mode (no `IP_TRANSPARENT`, uses
  `SO_ORIGINAL_DST`) as a second mode selected by config
  (`transproxy.type = tproxy|redirect`), since `REDIRECT` doesn't require the
  routing-table/`fwmark` setup that `TPROXY` does. Mirror Tor's
  `TransProxyType`.

### Step 4 — Config options
**Edit:** `libi2pd/Config.cpp` — add two option groups (model on
`socksproxy`/`httpproxy`):

```
transproxy.enabled        bool   default false
transproxy.type           string default "tproxy"      # tproxy | redirect
transproxy.address        string default "127.0.0.1"   # set to a LAN IP for a gateway
transproxy.port           uint16 default 7654
transproxy.virtualnet     string default "10.192.0.0/10"  # ROUTABLE range to map names into
transproxy.keys           string default "transient-proxy"
transproxy.signaturetype  ...    (as proxies)
transproxy.inbound.*/outbound.* tunnel params (copy proxy set)
transproxy.i2cp.*               (copy proxy set)

dnsresolver.enabled       bool   default false
dnsresolver.address       string default "127.0.0.1"   # set to a LAN IP for a gateway
dnsresolver.port          uint16 default 5353
dnsresolver.tcp           bool   default false          # also serve DNS over TCP
```

`transproxy.virtualnet` is the routable virtual network from Step 0 and is
shared by the DNS resolver and the TPROXY listener (via the shared
`AddressMapper`). Validate it at startup: parse the CIDR, reject the
unroutable/reserved blocks (e.g. `255.0.0.0/8`, multicast, `0.0.0.0/8`), and
warn if it overlaps the listen address or obvious local networks.

Register both groups in the combined options description where the others are
added. Update the example/docs config (`contrib/i2pd.conf`, `docs/`).

### Step 5 — Wire into ClientContext
**Edit:** `libi2pd_client/ClientContext.h` / `ClientContext.cpp`:

- Add members `i2p::client::TransparentProxyServer* m_TransProxy = nullptr;`
  and `i2p::client::I2PDNSResolver* m_DNSResolver = nullptr;` (and the shared
  `std::shared_ptr<AddressMapper> m_AddressMapper;`).
- Add `ReadTransProxy()` and `ReadDNSResolver()` modeled on `ReadSocksProxy()`:
  read config, pick/create a `ClientDestination` (own keys or shared), construct
  the service with the shared `m_AddressMapper`, `Start()` it.
- Call them from `ClientContext::Start()` next to `ReadSocksProxy()`, and stop +
  delete them in `Stop()` and `ReloadConfig()` (follow the exact
  start/stop/reload pattern already used for `m_SocksProxy`).
- Decide destination sharing: by default the trans proxy and DNS resolver can
  share the SOCKS/HTTP proxy destination or `m_SharedLocalDestination`. The DNS
  resolver itself needs a destination only if it must do live address-book
  lookups; for the synchronous design it does not strictly need one.
- (Optional) Add tunnels-file section types `transproxy` / `dnsresolver` in
  `ClientContext.h` and the `ReadTunnels()` switch, so they can also be declared
  in `tunnels.conf`.

### Step 6 — Build system
- Makefiles: nothing to do — `filelist.mk` globs `libi2pd_client/*.cpp`.
- **CMake**: add the new `.cpp` files to the client library source list in
  `build/CMakeLists.txt` (it enumerates sources explicitly). Verify both build
  paths compile.
- Ensure non-Linux builds still compile: the TPROXY listener compiles to a
  stub that logs "not supported" when `IP_TRANSPARENT` is unavailable; the DNS
  resolver is portable.

### Step 7 — Operational/runtime setup (document, don't code)
Provide a docs section (mirror Tor's `TransPort`/`DNSPort` + iptables recipe).
Throughout, `VNET=10.192.0.0/10` is `transproxy.virtualnet` — the routable
range chosen in Step 0. As a **gateway**, the i2pd box advertises a route for
`VNET` to itself and LAN clients point their resolver at the gateway.

**Gateway case (LAN clients route through the i2pd box):**
```
# On clients: use the gateway as DNS for .i2p (e.g. push via DHCP/dnsmasq),
# and ensure VNET is routed to the gateway (it is the gateway's own subnet,
# or add a static route on the LAN router:  ip route add 10.192.0.0/10 via <gw>)

# On the i2pd gateway, intercept routed packets to VNET with TPROXY:
ip rule add fwmark 1 lookup 100
ip route add local 0.0.0.0/0 dev lo table 100
iptables -t mangle -A PREROUTING -p tcp -d 10.192.0.0/10 \
    -j TPROXY --on-port 7654 --tproxy-mark 1
```

**Local/host-only case (same box originates the traffic):**
```
# Route DNS for .i2p to the local resolver
iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-ports 5353
# Intercept locally-originated traffic to VNET (OUTPUT chain + divert),
# matching Tor's documented TransPort setup.
```

Also document the simpler `REDIRECT` mode (`transproxy.type=redirect`), which
needs no routing-table/`fwmark` setup but only works for locally-originated
traffic on the same host:
```
iptables -t nat -A OUTPUT -p tcp -d 10.192.0.0/10 -j REDIRECT --to-ports 7654
```
Note that i2pd needs `CAP_NET_ADMIN`/root (or the `IP_TRANSPARENT` capability)
to set the sockopt and that the box must have IP forwarding enabled
(`net.ipv4.ip_forward=1`) to act as a gateway, exactly like Tor.

### Step 8 — Cleanup, timeouts, safety
- Periodically `Cleanup()` the automap table (reuse the `ClientContext` cleanup
  timer machinery — see `ScheduleCleanupUDP()` for the pattern).
- Reject/close TPROXY connections whose original dst is **not** in the virtual
  range or has no mapping (prevents using i2pd as an open relay to arbitrary
  IPs).
- Only answer `.i2p` (+ in-range PTR) in the DNS resolver; never forward
  other queries upstream by default (DNS-leak safety).
- Bind defaults to `127.0.0.1`; require explicit opt-in to bind publicly.

---

## 5. Testing plan
1. **Unit-ish**: `AddressMapper` round-trip (`Resolve` then `GetName`),
   in-range checks, cleanup eviction.
2. **DNS**: `dig @127.0.0.1 -p 5353 example.i2p A` returns an address inside the
   configured `transproxy.virtualnet` (e.g. `10.192.x.x`); a non-`.i2p` name
   returns REFUSED; PTR of the returned IP returns the original name. Repeating
   the query returns the *same* vip; resolving N distinct names returns N
   distinct vips (no collisions).
3. **TPROXY (Linux, root)**: apply iptables rules; `getsockname()` returns the
   virtual dst; verify a TCP connect to the DNS-returned IP opens an I2P stream
   to the right destination and pipes data (test against a known b32 service).
4. **REDIRECT mode**: same but via `SO_ORIGINAL_DST` and nat `REDIRECT`.
5. **End-to-end (host)**: configure an app to use only the local resolver + the
   TPROXY range; confirm `curl http://something.i2p` works with no SOCKS/HTTP
   proxy configured in the app.
6. **End-to-end (gateway)**: from a *separate* LAN host using the i2pd box as
   DNS and default route for `transproxy.virtualnet`, confirm `.i2p` resolves to
   a routable vip and `curl http://something.i2p` is carried over the wire to
   the gateway, TPROXY-intercepted, and served — with nothing I2P-specific
   installed on the client.
7. **Reload/stop**: `ReloadConfig()` cleanly restarts/stops both services; no
   leaked sockets or handlers.
8. **Non-Linux build**: confirm it still compiles and the trans proxy logs
   "unsupported".

---

## 6. File-by-file change summary

| File | Change |
|------|--------|
| `libi2pd_client/AddressResolver.h` (new) | Shared thread-safe `AddressMapper` (virtual-IP automap). |
| `libi2pd_client/SOCKS.h/.cpp` | Delegate `ResolveAddress`/`GetResolvedAddress` to shared `AddressMapper`. |
| `libi2pd_client/I2PDNSResolver.h/.cpp` (new) | UDP/TCP DNS server answering A/PTR for `.i2p` via automap. |
| `libi2pd_client/TransparentProxy.h/.cpp` (new) | TPROXY/REDIRECT TCP listener; original-dst recovery; stream bridging. |
| `libi2pd_client/I2PService.h` | (Optional) add `ConfigureAcceptorSocket()` hook in `ServiceAcceptor`. |
| `libi2pd/Config.cpp` | Add `transproxy.*` and `dnsresolver.*` option groups. |
| `libi2pd_client/ClientContext.h/.cpp` | Members, `ReadTransProxy()`, `ReadDNSResolver()`, start/stop/reload, shared mapper, cleanup. |
| `build/CMakeLists.txt` | Add new client sources. |
| `contrib/i2pd.conf`, `docs/` | Document options + iptables setup. |

---

## 7. Suggested implementation order
1. Step 1 (AddressMapper) — refactor + tests; nothing user-visible breaks.
2. Step 2 (DNS resolver) — independently testable with `dig`.
3. Step 4 + Step 5 partial (config + wire DNS only).
4. Step 3 (TPROXY listener) — the privileged, platform-specific part.
5. Step 5 remainder (wire trans proxy) + Step 6 (CMake).
6. Step 7/8 docs, cleanup timers, safety, full E2E tests.
