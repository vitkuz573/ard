#!/usr/bin/env bash
# End-to-end check of the whole data path on one host, with no VPS involved.
#
#   mockadbd  <-  ard-agent  --mTLS/yamux-->  ard-server  --mTLS-->  ard-connect  <--  stock adb
#
# The mock stands in for a device's adbd, so this exercises the real transport, the real
# registry, the real ACL policy and the real operator path, and validates them with the
# real adb binary. What it cannot cover is the network: that needs the acceptance run
# against the gateway over the internet, which scripts/e2e-operator.sh does.
#
# What this covers that the operator script does not:
#
#   - an agent that presents another device's certificate is refused, so a certificate
#     alone is not authority to claim an identity;
#   - a stream open is recorded in the audit log, not merely permitted;
#   - the audit log is a file on disk with those records in it.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="${WORK:-$(mktemp -d "${TMPDIR:-/tmp}/ard-e2e-local.XXXXXX")}"
ADB_SERVER_PORT="${ADB_SERVER_PORT:-5099}"
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
  # ARD_KEEP_WORK=1 leaves the logs behind. A failure that removes its own evidence is a
  # failure that has to be guessed at.
  if [[ "${ARD_KEEP_WORK:-0}" != "0" ]]; then
    echo "work dir kept: $WORK" >&2
    return
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT
PIDS=()

DEVICE="dev-e2e"
OPERATOR="alice"

step "building"
cd "$ROOT"
BIN="$WORK/bin"
mkdir -p "$BIN"
for cmd in ard-server ard-ca ard-agent ard-connect mockadbd; do
  go build -o "$BIN/$cmd" "./cmd/$cmd"
done
dim "binaries in $BIN"

if [[ -z "$ADB_BIN" ]]; then
  fail "adb is not installed; cannot validate against the real client"
  exit 1
fi

step "generating PKI"
"$BIN/ard-ca" init -dir "$WORK/pki" -san localhost,127.0.0.1 >/dev/null
"$BIN/ard-ca" device   -dir "$WORK/pki" -id "$DEVICE" >/dev/null
"$BIN/ard-ca" operator -dir "$WORK/pki" -name "$OPERATOR" >/dev/null
ok "server, device and operator certificates issued"

# An operator with a grant but deliberately no "shell". A raw ADB connection cannot be
# split by permission -- one connection carries shell, install, files and forwarding
# together -- so this is the role that must be refused when it tries to drive a device.
cat > "$WORK/operators.yaml" <<YAML
roles:
  - name: e2e
    permissions: ["shell", "exec", "files", "install", "logcat"]
    grants: ["$DEVICE"]
    members: ["$OPERATOR"]
  - name: e2e-observer
    permissions: ["logcat"]
    grants: ["$DEVICE"]
    members: ["bob"]
YAML

step "starting mock adbd"
"$BIN/mockadbd" -addr 127.0.0.1:0 > "$WORK/mock.log" 2>&1 &
PIDS+=($!)
MOCKADDR=""
for _ in $(seq 1 40); do
  # || true: the assignment's exit status is the substitution's, so a not-yet-written
  # log line would otherwise end the run under set -e instead of waiting for it.
  MOCKADDR="$(grep -oE '127\.0\.0\.1:[0-9]+' "$WORK/mock.log" 2>/dev/null | head -1 || true)"
  [[ -n "$MOCKADDR" ]] && break
  sleep 0.25
done
if [[ -n "$MOCKADDR" ]]; then
  ok "mock adbd on $MOCKADDR"
else
  fail "mock adbd did not report an address"
  dim "--- mock log ---"; sed 's/^/    /' "$WORK/mock.log" | tail -20
  exit 1
fi

DEVPORT=$(( 18000 + RANDOM % 1000 ))
OPPORT=$(( DEVPORT + 1 ))
ENPORT=$(( DEVPORT + 2 ))
LOCALPORT=$(( 29000 + RANDOM % 1000 ))

step "starting gateway"
"$BIN/ard-server" \
  -listen-devices "127.0.0.1:$DEVPORT" \
  -listen-operators "127.0.0.1:$OPPORT" \
  -listen-enrol "127.0.0.1:$ENPORT" \
  -control-socket "$WORK/control.sock" \
  -pki "$WORK/pki" \
  -devices "$DEVICE" \
  -operators "$WORK/operators.yaml" \
  -audit "$WORK/audit.log" \
  > "$WORK/server.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 40); do
  grep -q "enrol on" "$WORK/server.log" 2>/dev/null && break
  sleep 0.25
done
if grep -q "enrol on" "$WORK/server.log"; then
  ok "gateway listening on devices $DEVPORT and operators $OPPORT"
else
  fail "gateway did not start"
  dim "--- server log ---"; sed 's/^/    /' "$WORK/server.log" | tail -20
  exit 1
fi

step "starting agent (dials out to the gateway)"
"$BIN/ard-agent" \
  -gateway "127.0.0.1:$DEVPORT" \
  -server-name localhost \
  -device "$DEVICE" \
  -name "e2e-device" \
  -adbd "$MOCKADDR" \
  -ca "$WORK/pki/server/ca.crt" \
  -cert "$WORK/pki/devices/leaves/$DEVICE.crt" \
  -key "$WORK/pki/devices/leaves/$DEVICE.key" \
  > "$WORK/agent.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 40); do
  grep -q "serving" "$WORK/agent.log" 2>/dev/null && break
  sleep 0.25
done

if grep -q "serving" "$WORK/agent.log"; then
  ok "agent connected through the gateway"
else
  fail "agent did not connect"
  dim "--- agent log ---"; sed 's/^/    /' "$WORK/agent.log" | tail -20
  dim "--- server log ---"; sed 's/^/    /' "$WORK/server.log" | tail -20
  exit 1
fi

step "starting the operator client"
"$BIN/ard-connect" \
  -gateway "127.0.0.1:$OPPORT" \
  -ca "$WORK/pki/server/ca.crt" \
  -cert "$WORK/pki/operators/leaves/$OPERATOR.crt" \
  -key "$WORK/pki/operators/leaves/$OPERATOR.key" \
  -listen "127.0.0.1:$LOCALPORT" \
  > "$WORK/connect.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 40); do
  grep -q "publishing the adb port" "$WORK/connect.log" 2>/dev/null && break
  sleep 0.25
done
if grep -q "publishing the adb port" "$WORK/connect.log"; then
  ok "one local adb port published at 127.0.0.1:$LOCALPORT"
else
  fail "the operator client did not start"
  dim "--- client log ---"; sed 's/^/    /' "$WORK/connect.log" | tail -20
  exit 1
fi

step "talking to the device with the stock adb"
export ADB_VENDOR_KEYS="$WORK/adbkeys"
mkdir -p "$ADB_VENDOR_KEYS"
# adb talks to the client as if it were its own server: it asks which devices exist
# rather than being handed a list, so there is no adb connect and no serial in advance.
# The serial is the device UUID, which is stable across reconnects and across machines.
# || true: adb kill-server exits non-zero when no server was running, which is the
# normal case on the first call and must not end the run under set -e.
timeout "$ADB_TIMEOUT" "$ADB_BIN" -P "$LOCALPORT" kill-server >/dev/null 2>&1 || true
for _ in $(seq 1 40); do
  timeout "$ADB_TIMEOUT" "$ADB_BIN" -P "$LOCALPORT" devices >/dev/null 2>&1 && break
  sleep 0.25
done

SERIAL="$DEVICE"
state=""
for _ in $(seq 1 40); do
  line="$(timeout "$ADB_TIMEOUT" "$ADB_BIN" -P "$LOCALPORT" devices 2>/dev/null | grep -F "$SERIAL" || true)"
  case "$line" in
    *"	device") state=device; break ;;
    *offline*|*unauthorized*) state="${line##*$'\t'}"; ;;
  esac
  sleep 0.25
done

if [[ "$state" == "device" ]]; then
  ok "adb reports the device online as $SERIAL, by asking"
else
  fail "adb never reached the device state (last: ${state:-absent})"
  dim "--- client ---"; sed 's/^/    /' "$WORK/connect.log" | tail -15
  dim "--- server ---"; sed 's/^/    /' "$WORK/server.log" | tail -15
  exit 1
fi

run_shell() {
  local want="$1"; shift
  local out
  out="$(timeout "$ADB_TIMEOUT" "$ADB_BIN" -P "$LOCALPORT" -s "$SERIAL" shell "$@" 2>&1 || true)"
  if [[ -z "$out" ]]; then out="<no output: command timed out or produced nothing>"; fi
  if [[ "$out" == *"$want"* ]]; then
    ok "adb shell $* -> $out"
  else
    fail "adb shell $* returned '$out', expected to contain '$want'"
  fi
}

# Only commands mockadbd implements are asked for. Anything else reports 127 and would be
# testing the mock rather than the path: getprop reads and exit-code propagation are
# covered against real hardware instead.
run_shell "e2e-through-the-relay" echo e2e-through-the-relay
run_shell "aarch64"              uname -a

step "checking a failed command still reports its exit status"
set +e
out="$(timeout "$ADB_TIMEOUT" "$ADB_BIN" -P "$LOCALPORT" -s "$SERIAL" shell definitely-not-a-command 2>&1)"
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
out="$(timeout "$ADB_TIMEOUT" "$ADB_BIN" -P "$LOCALPORT" -s "$SERIAL" shell cat < "$stdin_file" 2>&1)"
rc=$?
set -e
if [[ $rc -eq 0 && "$out" == *relay-payload-through-stdin* ]]; then
  ok "stdin reaches the device and its output returns"
else
  fail "stdin round trip failed (rc=$rc out='$out')"
fi

step "checking the audit trail"
audit_lines="$(grep -c '"kind":"stream.open"' "$WORK/audit.log" 2>/dev/null || true)"
audit_lines="${audit_lines:-0}"
if [[ "$audit_lines" -gt 0 ]]; then
  ok "stream.open recorded in the audit log, $audit_lines time(s)"
else
  fail "no stream.open record in $WORK/audit.log"
  dim "--- audit log ---"; tail -5 "$WORK/audit.log" 2>/dev/null | sed 's/^/    /'
fi
# The actor is the operator identity, not a component name: an audit trail that cannot
# say which human opened a stream is not evidence of anything.
if grep -q '"actor":"alice"' "$WORK/audit.log" 2>/dev/null; then
  ok "the audit record names the operator who opened the stream"
else
  fail "no stream.open record naming the operator"
fi

step "checking the gateway refuses what the policy does not permit"
"$BIN/ard-ca" operator -dir "$WORK/pki" -name bob >/dev/null 2>&1
BADPORT=$(( LOCALPORT + 40 ))
"$BIN/ard-connect" \
  -gateway "127.0.0.1:$OPPORT" \
  -ca "$WORK/pki/server/ca.crt" \
  -cert "$WORK/pki/operators/leaves/bob.crt" \
  -key "$WORK/pki/operators/leaves/bob.key" \
  -listen "127.0.0.1:$BADPORT" \
  > "$WORK/connect-bob.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 40); do
  grep -q "publishing the adb port" "$WORK/connect-bob.log" 2>/dev/null && break
  sleep 0.25
done
timeout "$ADB_TIMEOUT" "$ADB_BIN" -P "$BADPORT" kill-server >/dev/null 2>&1 || true
for _ in $(seq 1 40); do
  timeout "$ADB_TIMEOUT" "$ADB_BIN" -P "$BADPORT" devices >/dev/null 2>&1 && break
  sleep 0.25
done

bobout="$(timeout "$ADB_TIMEOUT" "$ADB_BIN" -P "$BADPORT" -s "$SERIAL" shell echo should-not-run 2>&1 || true)"
dim "$bobout"
if [[ "$bobout" == *should-not-run* ]]; then
  fail "an operator whose role has no shell ran a command"
else
  ok "an operator whose role has no shell is refused"
fi
if [[ "$bobout" == *"may not attach"* ]]; then
  ok "the refusal names the reason, on the operator's own terminal"
else
  fail "the refusal did not reach adb's stderr: '$bobout'"
fi
if grep -qE '"kind":"stream.open","actor":"bob"' "$WORK/audit.log" 2>/dev/null; then
  fail "a stream was opened for an operator who may not drive the device"
else
  ok "no stream was opened for the refused operator"
fi

step "checking a device cannot claim another device's identity"
# The impostor runs in the background: an agent rejected by the gateway retries
# with backoff by design, so running it in the foreground would never return.
# It presents a valid device certificate and claims a different UUID. The
# certificate name and the claimed UUID have to agree, or one stolen certificate
# would be authority over every device.
"$BIN/ard-agent" \
  -gateway "127.0.0.1:$DEVPORT" -server-name localhost \
  -device dev-impostor -adbd "$MOCKADDR" \
  -ca "$WORK/pki/server/ca.crt" \
  -cert "$WORK/pki/devices/leaves/$DEVICE.crt" \
  -key "$WORK/pki/devices/leaves/$DEVICE.key" \
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

timeout "$ADB_TIMEOUT" "$ADB_BIN" -P "$LOCALPORT" kill-server >/dev/null 2>&1 || true

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
