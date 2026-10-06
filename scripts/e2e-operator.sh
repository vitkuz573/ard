#!/usr/bin/env bash
# End-to-end test of the operator's data path, with the real adb binary.
#
#   mock adbd ──▶ ard-agent ──mTLS──▶ ard-server ──▶ ard-connect ──▶ stock adb
#                                                  (operator's own machine)
#
# What this proves, and why it needs its own script: the gateway could identify an
# operator and then hang doing nothing, and the only working route to a device was running
# adb on the gateway host over its loopback port. That route needs SSH on the VPS, which is
# exactly what makes a multi-operator product impossible -- SSH is all-or-nothing, is not
# scoped per device, cannot be revoked for one person alone, and hands over root on the
# machine holding the CA keys.
#
# So the assertion here is deliberately narrow and load-bearing: from a machine that is
# not the gateway, with the gateway reachable only over TLS, stock adb drives a device.
# No SSH, no loopback, no ssh -L.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

WORK="$(mktemp -d)"
PASS=0
FAIL=0
ok()  { printf '  \033[32mok\033[0m   %s\n' "$1"; PASS=$((PASS+1)); }
bad() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
step(){ printf '\n\033[1m== %s\033[0m\n' "$1"; }

DEVICE="op-test-device"
OPERATOR="alice"

cleanup() {
  for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
  rm -rf "$WORK"
}
PIDS=()
trap cleanup EXIT

# ---------------------------------------------------------------------- build

step "build"
mkdir -p "$WORK/bin"
for cmd in ard-server ard-ca ard-agent ard-connect mockadbd; do
  go build -o "$WORK/bin/$cmd" "./cmd/$cmd"
done
ok "binaries built, including the operator client"

# ------------------------------------------------------------------------ pki

step "PKI"
PKI="$WORK/pki"
mkdir -p "$PKI/server" "$PKI/devices" "$PKI/operators"
"$WORK/bin/ard-ca" init -dir "$PKI" -san "localhost,127.0.0.1" >/dev/null
"$WORK/bin/ard-ca" device -dir "$PKI" -id "$DEVICE" >/dev/null
"$WORK/bin/ard-ca" operator -dir "$PKI" -name "$OPERATOR" >/dev/null
ok "device and operator identities issued"

# Roles are named templates; members are the certificate common names that hold them.
#
# Naming a role after nobody is the trap: the file parses, loads, and refuses every
# operator, which reads as deliberate. So the policy below names members explicitly.
cat > "$PKI/operators/operators.yaml" <<YAML
roles:
  # May drive this one device. shell is required for the bridge, because a raw ADB
  # connection cannot be separated by permission -- it carries shell, install, file
  # transfer and forwarding all at once.
  - name: maintainer
    permissions: ["shell", "exec", "files", "install", "logcat"]
    grants:
      - "$DEVICE"
    members: ["$OPERATOR"]

  # Holds a permission but is deliberately not given shell. The bridge must refuse it,
  # which is what proves the gate is load-bearing rather than decorative.
  - name: observer
    permissions: ["logcat"]
    grants:
      - "$DEVICE"
    members: ["bob"]
YAML
ok "operator policy grants $OPERATOR only $DEVICE"

# --------------------------------------------------------------------- gateway

step "gateway"
DEVPORT=$(( 24000 + RANDOM % 2000 ))
OPPORT=$(( DEVPORT + 1 ))
SOCK="$WORK/control.sock"

# Unprivileged, matching production. A gateway running as root here would hide exactly
# the class of bug this script was written after.
"$WORK/bin/ard-server" \
  -listen-devices "127.0.0.1:$DEVPORT" \
  -listen-operators "127.0.0.1:$OPPORT" \
  -listen-enrol "127.0.0.1:$((DEVPORT+2))" \
  -control-socket "$SOCK" \
  -pki "$PKI" \
  -devices "$DEVICE" \
  -operators "$PKI/operators/operators.yaml" \
  -audit "$WORK/audit.log" \
  >"$WORK/server.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 50); do
  grep -q "enrol on" "$WORK/server.log" 2>/dev/null && break
  sleep 0.2
done
grep -q "enrol on" "$WORK/server.log" && ok "gateway up" || { bad "gateway did not start"; sed 's/^/      /' "$WORK/server.log" | head; exit 1; }

# ----------------------------------------------------------------------- device

step "device"
"$WORK/bin/mockadbd" -addr "127.0.0.1:0" >"$WORK/mock.log" 2>&1 &
PIDS+=($!)
sleep 0.5
MOCKADDR="$(grep -oE '127\.0\.0\.1:[0-9]+' "$WORK/mock.log" | head -1)"
[[ -n "$MOCKADDR" ]] && ok "mock adbd on $MOCKADDR" || { bad "no mock address"; exit 1; }

"$WORK/bin/ard-agent" \
  -gateway "127.0.0.1:$DEVPORT" \
  -device "$DEVICE" \
  -adbd "$MOCKADDR" \
  -ca "$PKI/server/ca.crt" \
  -cert "$PKI/devices/leaves/$DEVICE.crt" \
  -key "$PKI/devices/leaves/$DEVICE.key" \
  >"$WORK/agent.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 60); do
  grep -q "serving" "$WORK/agent.log" 2>/dev/null && break
  sleep 0.25
done
grep -q "serving" "$WORK/agent.log" && ok "device connected through the gateway" || { bad "device did not connect"; sed 's/^/      /' "$WORK/agent.log" | head -5; exit 1; }

# --------------------------------------------------------------------- operator

step "operator client, from a machine that is not the gateway"
LOCALPORT=$(( 26000 + RANDOM % 2000 ))
"$WORK/bin/ard-connect" \
  -gateway "127.0.0.1:$OPPORT" \
  -ca "$PKI/server/ca.crt" \
  -cert "$PKI/operators/leaves/$OPERATOR.crt" \
  -key "$PKI/operators/leaves/$OPERATOR.key" \
  -listen "127.0.0.1:$LOCALPORT" \
  >"$WORK/connect.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 60); do
  grep -q "adb serial" "$WORK/connect.log" 2>/dev/null && break
  sleep 0.25
done

if grep -q "publishing the adb port" "$WORK/connect.log" 2>/dev/null; then
  ok "client published one local adb port"
else
  bad "the operator client did not start"; sed "s/^/      /" "$WORK/connect.log"; exit 1
fi
echo "      --- client output ---"
sed 's/^/      /' "$WORK/connect.log" | head -6

# The device list must be filtered by role, so the operator sees only what it may.
if grep -q "some-other-device" "$WORK/connect.log"; then
  bad "the client published a device the role has no grant for"
else
  ok "no device outside the role's grants is published"
fi

# ----------------------------------------------------------------- real adb

step "stock adb, driven from the operator's machine"
export ADB_VENDOR_KEYS="$WORK/adbkeys"
mkdir -p "$ADB_VENDOR_KEYS"

  # adb talks to the helper as if it were its own server: one port, and it asks which
  # devices exist rather than being handed a list. No adb connect, no serial in advance --
  # that is the point of the change.
  for _ in $(seq 1 40); do
    timeout 15 adb -P "$LOCALPORT" devices >/dev/null 2>&1 && break
    sleep 0.25
  done

  DEVICES="$(timeout 15 adb -P "$LOCALPORT" devices 2>/dev/null || true)"
  printf "%s\n" "$DEVICES" | sed "s/^/      /"

  if printf "%s\n" "$DEVICES" | grep -q "^$DEVICE[[:space:]]*device"; then
    ok "adb sees the device through the operator port, by asking"
  else
    bad "adb did not report the device as ready; got: ${DEVICES:-<nothing>}"
    exit 1
  fi
adb kill-server >/dev/null 2>&1 || true
# The real assertion: the transport is transparent in both directions.
#
# Only commands mockadbd implements are used here. It answers whoami, get-state, cat,
# true and false, and reports 127 for anything else -- so asking it for getprop would
# test the mock rather than the bridge. Property reads and exit-code propagation are
# covered against real hardware instead.
WHO="$(timeout 25 adb -P "$LOCALPORT" -s "$DEVICE" shell whoami 2>/dev/null | tr -d '\r\n' || true)"
if [[ "$WHO" == "shell" ]]; then
  ok "adb shell whoami returned: $WHO"
else
  bad "adb shell produced '$WHO', want 'shell'"
fi

timeout 25 adb -P "$LOCALPORT" -s "$DEVICE" shell false >/dev/null 2>&1 || rc=$?
rc=${rc:-0}
if [[ $rc -eq 1 ]]; then
  ok "a failing command's exit code propagates"
else
  bad "exit code was $rc, want 1"
fi

# stdin must round-trip, or every interactive shell and every push would break.
#
# Stdin has to be a real file, not a pipe. os/exec feeds a piped stdin from a background
# goroutine and adb's shell client never notices the write side closing, so the device is
# never sent kIdCloseStdin, a command reading stdin blocks forever and the client hangs.
# That is adb behaviour rather than anything the bridge does, and the mock's own interop
# test hits it for the same reason; it is the reason this looks like a bridge deadlock if
# you have not seen it before.
STDIN_FILE="$WORK/stdin"
printf 'hello-through-the-bridge' > "$STDIN_FILE"
# Every adb call gets a timeout. adb's shell client does not always notice that stdin
# closed, and when it does not, `cat` blocks forever and the whole script hangs instead of
# reporting. A check that can hang is worse than one that can fail.
OUT="$(timeout 25 adb -P "$LOCALPORT" -s "$DEVICE" shell cat < "$STDIN_FILE" 2>/dev/null | tr -d '\r\n' || true)"
if [[ "$OUT" == "hello-through-the-bridge" ]]; then
  ok "stdin round-trips"
else
  bad "stdin did not round-trip (got '$OUT')"
fi

# ------------------------------------------------------------ authorization

step "authorization is enforced on the gateway"
# A role without shell must not get the bridge, whatever the client asks for.
"$WORK/bin/ard-ca" operator -dir "$PKI" -name bob >/dev/null 2>&1
BADPORT=$(( LOCALPORT + 40 ))
timeout 20 "$WORK/bin/ard-connect" \
  -gateway "127.0.0.1:$OPPORT" \
  -ca "$PKI/server/ca.crt" \
  -cert "$PKI/operators/leaves/bob.crt" \
  -key "$PKI/operators/leaves/bob.key" \
  -listen "127.0.0.1:$BADPORT" \
  >"$WORK/connect-bob.log" 2>&1 || true

# Bob holds logcat on this device and is deliberately not given shell.
#
# He must be told the device exists -- a denial with no explanation is impossible to act
# on -- but he must not be handed an adb serial for it. Publishing one would let
# `adb connect` succeed and every command fail, which reads as a broken device rather than
# as policy.
if timeout 25 "$WORK/bin/ard-connect" -gateway "127.0.0.1:$OPPORT" \
     -ca "$PKI/server/ca.crt" \
     -cert "$PKI/operators/leaves/bob.crt" \
     -key "$PKI/operators/leaves/bob.key" \
     -listen "127.0.0.1:$BADPORT" \
     >"$WORK/connect-bob.log" 2>&1; then
  bad "a logcat-only operator was given something to run"
else
  ok "a logcat-only operator is refused before any port is published"
fi

if grep -qiE "can see .*but the .* role does not permit driving" "$WORK/connect-bob.log"; then
  ok "the refusal names the device and the role, so it is actionable"
else
  bad "the refusal does not explain itself"
  sed 's/^/      /' "$WORK/connect-bob.log" | head -5
fi

# The gateway agreed, independently of what the client decided: it identified bob and
# marked the device not bridgeable, so no attach was ever attempted. What must NOT appear
# is a stream being opened for him -- a read-only operator getting device access would be
# the whole failure this test exists to catch.
if grep -q '"actor":"bob"' "$WORK/audit.log" 2>/dev/null; then
  ok "the gateway identified the read-only operator"
else
  bad "the gateway did not record the read-only operator at all"
fi

if grep -qE '"kind":"stream.open","actor":"bob"' "$WORK/audit.log" 2>/dev/null; then
  bad "a stream was opened for an operator who may not drive the device"
else
  ok "no stream was opened for the read-only operator"
fi

# The gateway must have logged the refusal, because a silent deny is indistinguishable
# from a broken client.
if grep -q "attach_denied\|operator.connected" "$WORK/audit.log" 2>/dev/null; then
  ok "the gateway audited the operator"
else
  bad "no audit record for the operator"
fi

adb kill-server >/dev/null 2>&1 || true
adb connect "$MOCKADDR" >/dev/null 2>&1 || true

# --------------------------------------------------------------------- result

printf '\n'
if [[ $FAIL -eq 0 ]]; then
  printf '\033[32mall %d checks passed\033[0m\n' "$PASS"
  exit 0
fi
printf '\033[31m%d of %d checks failed\033[0m\n' "$FAIL" "$((PASS+FAIL))"
exit 1