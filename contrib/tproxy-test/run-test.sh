#!/usr/bin/env bash
# Launches i2pd with i2pd.conf and runs the transparent-proxy smoke test.
#
# Prereqs on YOUR box (this script does NOT manage iptables):
#   iptables -t nat -A OUTPUT -p tcp -d 10.108.0.0/16 -j REDIRECT --to-ports 9041
# (REDIRECT in the OUTPUT chain only catches traffic originated on THIS box.)
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
# Use $BIN if set, else the freshly-built binary at ../../i2pd, else i2pd on PATH.
if [ -z "${BIN:-}" ]; then
  REPO_BIN="$(cd "$HERE/../.." && pwd)/i2pd"
  if [ -x "$REPO_BIN" ]; then BIN="$REPO_BIN"; else BIN="i2pd"; fi
fi
DATADIR="$HERE/data"
LOG="$HERE/i2pd.log"
CONF="$HERE/i2pd.conf"
PIDFILE="$HERE/i2pd.pid"

mkdir -p "$DATADIR"

# Start i2pd if it's not already running for this config.
if ! pgrep -f -- "--conf=$CONF" >/dev/null 2>&1; then
  echo ">> starting i2pd: $BIN --conf=$CONF --datadir=$DATADIR"
  "$BIN" --conf="$CONF" --datadir="$DATADIR" >"$LOG" 2>&1 &
  echo $! >"$PIDFILE"
else
  echo ">> i2pd already running for this config"
fi

# Wait for the transparent-proxy listener to come up.
echo ">> waiting for services..."
for _ in $(seq 1 40); do
  grep -q "TransProxy:.*listening" "$LOG" 2>/dev/null && break
  sleep 0.5
done

echo ">> i2pd startup (relevant lines):"
grep -E "virtual .*i2p network|DNS resolver|Transparent Proxy at|TransProxy.*listening|Failed to|refusing|disabled" "$LOG" \
  | sed 's/\x1b\[[0-9;]*m//g'

echo
echo ">> iptables REDIRECT rule (look for 'redir ports 9041' and 10.108.0.0/16):"
if iptables -t nat -L OUTPUT -n -v >/dev/null 2>&1; then
  iptables -t nat -L OUTPUT -n -v | grep -E "9041|10\.108" || echo "  (no matching rule found)"
else
  echo "  (cannot read iptables — run this script as root, or check the rule manually)"
fi

echo
python3 "$HERE/test-tproxy.py" --log "$LOG" "$@"
rc=$?

echo
echo ">> i2pd is still running (pid $(cat "$PIDFILE" 2>/dev/null))."
echo "   stop:  kill \$(cat \"$PIDFILE\")"
echo "   logs:  less \"$LOG\""
exit $rc
