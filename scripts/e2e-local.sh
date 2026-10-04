#!/usr/bin/env bash
# End-to-end check of the whole relay path, on one host, with no VPS involved.
#
#   mockadbd  <-  ard-agent  --mTLS/yamux-->  ard-server  <-unix-  ard-proxy  <-  stock adb
#
# The mock stands in for a device's adbd, so this exercises the real transport,
# the real registry and the real loopback bridge, and validates them with the real
# adb binary. What it cannot cover is the network: that needs the acceptance run
# against the gateway over the internet.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="${WORK:-/tmp/ard-e2e}"
ADB_SERVER_PORT="${ADB_SERVER_PORT:-5099}"
LOOPBACK_PORT="${LOOPBACK_PORT:-15000}"
ADB_BIN="$(command -v adb || true)"
# Every adb invocation is bounded. Without this a single stuck command turns a
# broken run into a silent multi-minute hang with no indication of where.
ADB_TIMEOUT="${ADB_TIMEOUT:-20}"

RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; DIM=$'\033[2m'; OFF=$'\033[0m'
step() { printf '%s==>%s %s\n' "$YELLOW" "$OFF" "$*"; }
ok()   { printf '  %sPASS%s %s\n' "$GREEN" "$OFF" "$*"; }
fail() { printf '  %sFAIL%s %s\n' "$RED" "$OFF" "$*"; FAILURES=$((FAILURES+1)); }
dim()  { printf '  %s%s%s\n' "$DIM" "$*" "$OFF"; }
FAILURES=0

cleanup() {
  set +e
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null; done
  "$ADB_BIN" -P "$ADB_SERVER_PORT" kill-server >/dev/null 2>&1
}
trap cleanup EXIT
PIDS=()

step "building"
cd "$ROOT"
BIN="$ROOT/.e2e-bin"
mkdir -p "$BIN"
go build -o "$BIN/" ./cmd/...
dim "binaries in $BIN"

rm -rf "$WORK"
mkdir -p "$WORK"
cp "$BIN"/* "$WORK/"

step "generating PKI"
"$WORK/ard-ca" init -dir "$WORK/pki" -san localhost,127.0.0.1 >/dev/null
"$WORK/ard-ca" device   -dir "$WORK/pki" -id  dev-e2e >/dev/null
"$WORK/ard-ca" operator -dir "$WORK/pki" -name alice >/dev/null
ok "server, device and operator certificates issued"

cat > "$WORK/operators.yaml" <<'YAML'
roles:
  - name: e2e
    permissions: ["*"]
    grants: ["*"]
YAML

step "starting mock adbd on 127.0.0.1:5599"
"$WORK/mockadbd" -addr 127.0.0.1:5599 > "$WORK/mock.log" 2>&1 &
PIDS+=($!)
sleep 1

step "starting gateway"
"$WORK/ard-server" \
  -listen-devices 127.0.0.1:17000 \
  -listen-operators 127.0.0.1:17100 \
  -control-socket "$WORK/control.sock" \
  -pki "$WORK/pki" \
  -devices dev-e2e \
  -operators "$WORK/operators.yaml" \
  -loopback-base "$LOOPBACK_PORT" \
  -audit "$WORK/audit.log" \
  > "$WORK/server.log" 2>&1 &
PIDS+=($!)
sleep 1

step "starting agent (dials out to the gateway)"
"$WORK/ard-agent" \
  -gateway 127.0.0.1:17000 \
  -server-name localhost \
  -device dev-e2e \
  -name "e2e-device" \
  -adbd 127.0.0.1:5599 \
  -ca "$WORK/pki/server/ca.crt" \
  -cert "$WORK/pki/devices/leaves/dev-e2e.crt" \
  -key "$WORK/pki/devices/leaves/dev-e2e.key" \
  > "$WORK/agent.log" 2>&1 &
PIDS+=($!)
sleep 2

if grep -q "connected" "$WORK/agent.log"; then
  ok "agent connected through the gateway"
else
  fail "agent did not connect"
  dim "--- agent log ---"; sed 's/^/    /' "$WORK/agent.log" | tail -20
  dim "--- server log ---"; sed 's/^/    /' "$WORK/server.log" | tail -20
  exit 1
fi

step "starting proxy"
"$WORK/ard-proxy" -control "$WORK/control.sock" > "$WORK/proxy.log" 2>&1 &
PIDS+=($!)
sleep 3

if ss -tln 2>/dev/null | grep -q "127.0.0.1:$LOOPBACK_PORT"; then
  ok "loopback port $LOOPBACK_PORT is listening for the device"
else
  fail "loopback port $LOOPBACK_PORT was not opened"
  sed 's/^/    /' "$WORK/proxy.log" | tail -20
fi

if [[ -z "$ADB_BIN" ]]; then
  fail "adb is not installed; cannot validate against the real client"
  exit 1
fi

step "talking to the device with the stock adb"
"$ADB_BIN" -P "$ADB_SERVER_PORT" kill-server >/dev/null 2>&1
connect_out="$(timeout "$ADB_TIMEOUT" "$ADB_BIN" -P "$ADB_SERVER_PORT" connect "127.0.0.1:$LOOPBACK_PORT" 2>&1 || true)"
dim "$connect_out"

SERIAL="127.0.0.1:$LOOPBACK_PORT"
state=""
for _ in $(seq 1 40); do
  line="$(timeout "$ADB_TIMEOUT" "$ADB_BIN" -P "$ADB_SERVER_PORT" devices 2>/dev/null | grep -F "$SERIAL" || true)"
  case "$line" in
    *"	device") state=device; break ;;
    *offline*|*unauthorized*) state="${line##*$'\t'}"; ;;
  esac
  sleep 0.25
done

if [[ "$state" == "device" ]]; then
  ok "adb reports the device online as $SERIAL"
else
  fail "adb never reached the device state (last: ${state:-absent})"
  dim "--- proxy ---"; sed 's/^/    /' "$WORK/proxy.log" | tail -15
  dim "--- server ---"; sed 's/^/    /' "$WORK/server.log" | tail -15
  exit 1
fi

run_shell() {
  local want="$1"; shift
  local out
  out="$(timeout "$ADB_TIMEOUT" "$ADB_BIN" -P "$ADB_SERVER_PORT" -s "$SERIAL" shell "$@" 2>&1 || true)"
  if [[ -z "$out" ]]; then out="<no output: command timed out or produced nothing>"; fi
  if [[ "$out" == *"$want"* ]]; then
    ok "adb shell $* -> $out"
  else
    fail "adb shell $* returned '$out', expected to contain '$want'"
  fi
}

run_shell "e2e-through-the-relay" echo e2e-through-the-relay
run_shell "device"               get-state

step "checking a failed command still reports its exit status"
set +e
out="$(timeout "$ADB_TIMEOUT" "$ADB_BIN" -P "$ADB_SERVER_PORT" -s "$SERIAL" shell definitely-not-a-command 2>&1)"
rc=$?
set -e
if [[ $rc -eq 127 ]]; then
  ok "unknown command exits 127 through the relay"
else
  fail "unknown command exited $rc, expected 127 (output: $out)"
fi

step "checking stdin survives the round trip"
stdin_file="$WORK/stdin.txt"
printf 'relay-payload-through-stdin\n' > "$stdin_file"
set +e
out="$(timeout "$ADB_TIMEOUT" "$ADB_BIN" -P "$ADB_SERVER_PORT" -s "$SERIAL" shell cat < "$stdin_file" 2>&1)"
rc=$?
set -e
if [[ $rc -eq 0 && "$out" == *relay-payload-through-stdin* ]]; then
  ok "stdin reaches the device and its output returns"
else
  fail "stdin round trip failed (rc=$rc out='$out')"
fi

step "checking audit trail"
audit_line="$(grep -c '"kind":"stream.open"' "$WORK/audit.log" 2>/dev/null || echo 0)"
if [[ "$audit_line" -gt 0 ]]; then
  ok "stream.open recorded in the audit log"
else
  dim "audit log not at /var/log/ard/audit.log in this run; checking server stderr"
  if grep -q 'stream.open' "$WORK/server.log" 2>/dev/null; then
    ok "stream.open appears in the gateway log"
  else
    fail "no stream.open record found"
  fi
fi

step "checking role isolation"
# The impostor runs in the background: an agent rejected by the gateway retries
# with backoff by design, so running it in the foreground would never return.
"$WORK/ard-agent" \
  -gateway 127.0.0.1:17000 -server-name localhost \
  -device dev-impostor -adbd 127.0.0.1:5599 \
  -ca "$WORK/pki/server/ca.crt" \
  -cert "$WORK/pki/devices/leaves/dev-e2e.crt" \
  -key "$WORK/pki/devices/leaves/dev-e2e.key" \
  > "$WORK/impostor.log" 2>&1 &
IMPOSTOR=$!
PIDS+=("$IMPOSTOR")
sleep 3
kill "$IMPOSTOR" 2>/dev/null || true
if grep -qiE "not enrolled|identity|certificate is for" "$WORK/impostor.log" "$WORK/server.log"; then
  ok "a device claiming another UUID is refused"
else
  fail "identity mismatch was not detected"
  sed 's/^/    /' "$WORK/impostor.log" | tail -5
fi

echo
if [[ $FAILURES -eq 0 ]]; then
  printf '%sALL CHECKS PASSED%s\n' "$GREEN" "$OFF"
else
  printf '%s%d CHECK(S) FAILED%s\n' "$RED" "$FAILURES" "$OFF"
fi
echo
echo "logs are in $WORK:"
ls -1 "$WORK"/*.log | sed 's/^/  /'
exit $(( FAILURES > 0 ? 1 : 0 ))