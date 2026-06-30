# Transparent-proxy smoke test

End-to-end test for the transparent proxy (TPROXY/REDIRECT) + `.i2p` DNS
resolver. It verifies the full pipeline against a real iptables REDIRECT rule:

```
DNS resolve .i2p  ->  virtual IP in transproxy.virtualnet
connect to VIP     ->  iptables REDIRECT -> transproxy listener (:9041)
                  ->  i2pd recovers original dst, maps VIP -> .i2p name
                  ->  CreateStream(.i2p name) -> I2P stream
```

See `docs/transparent-proxy.md` for the feature design and full iptables
recipes (gateway TPROXY, host-only, REDIRECT).

## Files

- `i2pd.conf` — minimal config: enables `transproxy` (redirect, `0.0.0.0:9041`,
  `virtualnet = 10.108.0.0/16`) and `dnsresolver` (`127.0.0.1:5353`), disables
  the default HTTP/SOCKS/SAM proxies to keep the test isolated.
- `test-tproxy.py` — pure-stdlib (no `dig`/`dnspython`/`curl`) smoke test.
- `run-test.sh` — launches i2pd with `i2pd.conf`, waits for the listener,
  prints the matching iptables rule, and runs the test.

## Prerequisites

You need an iptables REDIRECT rule on the box that *originates* the traffic
(REDIRECT in `OUTPUT` only catches locally-originated traffic):

```
iptables -t nat -A OUTPUT -p tcp -d 10.108.0.0/16 -j REDIRECT --to-ports 9041
```

Adjust the CIDR / port to match `transproxy.virtualnet` / `transproxy.port`
in `i2pd.conf` if you change them. Applying the rule needs root; the i2pd
listener in `redirect` mode does **not** need `CAP_NET_ADMIN` (unlike
`type = tproxy`).

## Usage

```
# from the repo root, after building (make i2pd):
./contrib/tproxy-test/run-test.sh

# or with an installed/alternate binary:
BIN=/usr/bin/i2pd ./contrib/tproxy-test/run-test.sh

# test a specific .i2p name / port (defaults: test.i2p / 80):
./contrib/tproxy-test/run-test.sh --name stats.i2p --port 80
```

The script starts i2pd in `contrib/tproxy-test/data/` and writes its log to
`contrib/tproxy-test/i2pd.log`. It leaves i2pd running; stop it with
`kill $(cat contrib/tproxy-test/i2pd.pid)`.

## What "passes"

Stages 1–4 of `test-tproxy.py`:

1. DNS returns an A record **inside** `transproxy.virtualnet`.
2. The transproxy listener accepts connections.
3. A TCP connect to the virtual IP is REDIRECTed by iptables to the listener.
4. i2pd's log contains a `TransProxy: <name>:<port>` line — proof it recovered
   the original destination and mapped it back to the `.i2p` name.

Getting an actual HTTP body back additionally requires the router to be
bootstrapped and able to look up the destination's LeaseSet (i.e. a
well-connected, ideally non-firewalled router). A fresh/firewalled router
will pass stages 1–4 but fail the final stream build with
`TransProxy: stream creation failed` — that is a router/netDb limitation,
not a transparent-proxy bug; the same destination fails identically through
i2pd's own SOCKS proxy.
