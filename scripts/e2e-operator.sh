#!/usr/bin/env bash
# End-to-end test of the operator's data path, with the real adb binary.
#
#   mock adbd ──▶ ard-agent ──mTLS──▶ ard-server ──▶ ard-connect ──▶ stock adb
#                                                  (operator's own machine)
#
# What this proves, and why it needs its own script: a gateway that identifies an operator and
# then hangs doing nothing looks exactly like a product that works. Reaching a device must not
# require SSH on the VPS -- SSH is all-or-nothing, is not scoped per device, cannot be revoked
# for one person alone, and hands over root on the machine holding the CA keys.
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
# A second device whose banner advertises no sync features beyond shell_v2 and cmd, which
# is what puts adb on the v1 sync path. It is a separate identity rather than a flag on the
# first one because the path is chosen per device, from that device's own feature list, and
# a gateway that answered both from one list would be testing the same reply twice.
DEVICE_V1="op-test-device-v1sync"
OPERATOR="alice"

cleanup() {
  for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
  # ARD_KEEP_WORK=1 leaves the logs behind. A failure that removes its own evidence is a
  # failure that has to be guessed at, and this script has already wasted hours on that.
  if [[ "${ARD_KEEP_WORK:-0}" != "0" ]]; then
    echo "work dir kept: $WORK" >&2
    return
  fi
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
"$WORK/bin/ard-ca" device -dir "$PKI" -id "$DEVICE_V1" >/dev/null
"$WORK/bin/ard-ca" operator -dir "$PKI" -name "$OPERATOR" >/dev/null
ok "device and operator identities issued"

# Roles are named templates; members are the certificate common names that hold them.
#
# Naming a role after nobody is the trap: the file parses, loads, and refuses every
# operator, which reads as deliberate. So the policy below names members explicitly.
#
# `adb logcat` is not a permission and is not written here: it has no service name of its
# own, so it arrives as the shell service with a command line attached and is governed by
# "shell". A name the gateway does not know stops it from starting, which is the point --
# a policy that loads and grants less than it reads as control and is not.
#
# The permissions are split across four roles so that each check below is about one gate
# rather than about a role that holds everything:
#
#   maintainer  holds everything, and drives the device throughout this script
#   observer    holds a permission and no shell, so the bridge refuses it
#   driver      holds shell and no forward or reverse, so those two permissions can be
#               revoked and the revocation observed against the real client
#   porter      holds forward and reverse on the same device as the maintainer, so the
#               only thing between one operator's port and another's is ownership
cat > "$PKI/operators/operators.yaml" <<YAML
roles:
  # May drive these two devices. shell is required for the bridge, because a raw ADB
  # connection cannot be separated by permission -- it carries shell, install, file
  # transfer and forwarding all at once.
  - name: maintainer
    permissions: ["shell", "exec", "files", "install", "forward", "reverse"]
    grants:
      - "$DEVICE"
      - "$DEVICE_V1"
    members: ["$OPERATOR"]

  # Holds a permission but is deliberately not given shell. The bridge must refuse it,
  # which is what proves the gate is load-bearing rather than decorative.
  - name: observer
    permissions: ["files"]
    grants:
      - "$DEVICE"
    members: ["bob"]

  # Holds shell and drives the device, but binds no port on the gateway in either
  # direction. Every `adb forward` and `adb reverse` from this role must be refused.
  - name: driver
    permissions: ["shell", "exec", "files", "install"]
    grants:
      - "$DEVICE"
    members: ["carol"]

  # Holds forward and reverse on the same device as the maintainer, so that one operator
  # cannot release another's port. Ownership is the only thing between them.
  - name: porter
    permissions: ["shell", "forward", "reverse"]
    grants:
      - "$DEVICE"
    members: ["frank"]
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
  -devices "$DEVICE,$DEVICE_V1" \
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

# The second device advertises no sync features beyond shell_v2 and cmd. adb picks the
# spelling of every sync command it sends from the feature list it is given for the device,
# so this banner is what puts it on the v1 path -- and it has to be a device of its own,
# because the list is per device and a gateway that answered both from one list would make
# the two checks measure the same reply.
V1_BANNER='device::ro.product.name=ard_mock_v1sync;ro.product.model=MockV1;ro.build.type=user;features=shell_v2,cmd,'
"$WORK/bin/mockadbd" -addr "127.0.0.1:0" -banner "$V1_BANNER" >"$WORK/mock-v1.log" 2>&1 &
PIDS+=($!)
sleep 0.5
MOCKADDR_V1="$(grep -oE '127\.0\.0\.1:[0-9]+' "$WORK/mock-v1.log" | head -1)"
[[ -n "$MOCKADDR_V1" ]] && ok "second mock adbd on $MOCKADDR_V1" || { bad "no second mock address"; exit 1; }

"$WORK/bin/ard-agent" \
  -gateway "127.0.0.1:$DEVPORT" \
  -device "$DEVICE_V1" \
  -adbd "$MOCKADDR_V1" \
  -ca "$PKI/server/ca.crt" \
  -cert "$PKI/devices/leaves/$DEVICE_V1.crt" \
  -key "$PKI/devices/leaves/$DEVICE_V1.key" \
  >"$WORK/agent-v1.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 60); do
  grep -q "serving" "$WORK/agent-v1.log" 2>/dev/null && break
  sleep 0.25
done
grep -q "serving" "$WORK/agent-v1.log" && ok "the v1-sync device connected through the gateway" || { bad "the v1-sync device did not connect"; sed 's/^/      /' "$WORK/agent-v1.log" | head -5; exit 1; }

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
  printf '%s\n' "$DEVICES" | sed 's/^/      /'

  if printf "%s\n" "$DEVICES" | grep -q "^$DEVICE[[:space:]]*device"; then
    ok "adb sees the device through the operator port, by asking"
  else
    bad "adb did not report the device as ready; got: ${DEVICES:-<nothing>}"
    exit 1
  fi
adb kill-server >/dev/null 2>&1 || true

# ------------------------------------------------------------------ features

step "adb is told what the device supports, from the device"

# adb reads this before it decides anything, and it decides the spelling of every command it
# sends. A server that answers from its own opinion puts the client on a path the device cannot
# serve, and the failure surfaces much later as a protocol fault on the device rather than as a
# refusal here. So the answer has to come from the device's own banner, and the check is that
# the bytes adb received are the device's list rather than a plausible one.
#
# The request is written by hand rather than asked of adb, because there is no adb command that
# prints it: this is the server protocol adb speaks on the operator's behalf.
#
# A connection per request, which is what adb does -- it opens a fresh connection for each host
# service request -- and a second request on one connection is answered with silence and a
# close. Asking both questions on one socket would measure that instead of the answers.
#
# Each answer is labelled with the request that produced it, because the reply carries no
# serial and there are two devices with different feature lists. Matching an answer to a
# device is the whole basis of the per-device check below, and grepping the answers as one
# blob would leave that mapping to the order they happened to come back in.
FEATURES_RAW="$(timeout 15 python3 -c "
import socket

def ask(label, req):
    s = socket.create_connection(('127.0.0.1', $LOCALPORT), 5)
    s.settimeout(10)
    try:
        s.sendall(b'%04x' % len(req) + req)
        tok = s.recv(4)
        n = int(s.recv(4), 16)
        body = b''
        while len(body) < n:
            body += s.recv(n - len(body))
        print(label + '\t' + tok.decode() + '\t' + body.decode())
    finally:
        s.close()

ask('host', b'host:features')
ask('v2', b'host-serial:$DEVICE:features')
ask('v1', b'host-serial:$DEVICE_V1:features')
" 2>&1 || true)"
printf '%s\n' "$FEATURES_RAW" | sed 's/^/      /'

# The v2 mock's banner lists ls_v2, which is what makes a directory push work, and it does
# not list sendrecv_v2_brotli, which adb would then compress a large push with. Both halves
# are checked: a list carrying everything would break a push, and a list carrying nothing
# would break every command.
#
# Read by the label the asker printed, which is the only thing tying an answer to a device.
features_for() { printf '%s\n' "$FEATURES_RAW" | awk -F'\t' -v k="$1" '$1 == k { print $3; exit }'; }
V2_FEATURES="$(features_for v2)"
V1_FEATURES="$(features_for v1)"
printf '      v2 answer: %s\n' "$V2_FEATURES"
printf '      v1 answer: %s\n' "$V1_FEATURES"

# Both answers must be OKAY as well as correct: a refusal reads as an empty list, and an
# empty list is indistinguishable here from a device that was told it has nothing.
if [[ "$V2_FEATURES" == "ls_v2"* || "$V2_FEATURES" == *"ls_v2,"* ]]; then
  ok "adb's answer for the v2 device carries what that device's own banner said"
else
  bad "adb's answer for the v2 device does not carry ls_v2 from its own banner"
fi

if [[ -z "$V1_FEATURES" ]]; then
  bad "adb's answer for the v1-sync device was refused, so nothing after this would be meaningful"
elif [[ "$V1_FEATURES" == *ls_v2* || "$V1_FEATURES" == *stat_v2* || "$V1_FEATURES" == *sendrecv_v2* ]]; then
  bad "the v1-sync device was told it has the v2 sync features, so adb would never take the v1 path"
else
  ok "adb is told the v1-sync device has no v2 sync features, which is what selects the v1 path"
fi

if printf '%s\n' "$FEATURES_RAW" | grep -q "sendrecv_v2_brotli"; then
  bad "adb was told the device supports a compression the device does not implement"
else
  ok "adb is not told the device supports anything it does not"
fi

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

# ------------------------------------------------------------------- files

step "adb push and adb pull carry a file byte for byte"

# An operator's reason for wanting a gateway rather than a shell is usually a file: an APK to
# install, a config to drop, a log to collect. So the transfer is checked on the bytes rather
# than on adb's own report, which is printed before anything is known about what landed.
#
# Two sizes, because they are not the same case and only one of them is obvious. A file under
# one sync frame travels as a single DATA frame and fits in one packet; a larger one is split,
# and the device's frames come back 64 KiB at a time -- which is larger than the window this
# gateway offers, so a relay that reads only what it advertised truncates the pull and says
# nothing. A checksum on a 300 KB file is what catches that; a 14 byte file never would.

PUSH_SRC="$WORK/pushed.bin"
head -c 14 /dev/urandom > "$PUSH_SRC"
PUSH_DST="/data/local/tmp/pushed-through-the-gateway.bin"
if timeout 60 adb -P "$LOCALPORT" -s "$DEVICE" push "$PUSH_SRC" "$PUSH_DST" >"$WORK/push.log" 2>&1; then
  ok "adb push reported success"
else
  bad "adb push failed"
  sed 's/^/      /' "$WORK/push.log" | head -3
fi

PULL_DST="$WORK/pulled.bin"
if timeout 60 adb -P "$LOCALPORT" -s "$DEVICE" pull "$PUSH_DST" "$PULL_DST" >"$WORK/pull.log" 2>&1 &&
   cmp -s "$PUSH_SRC" "$PULL_DST"; then
  ok "a small file survives push then pull unchanged"
else
  bad "a small file did not come back identical"
  sed 's/^/      /' "$WORK/pull.log" | head -3
  ls -l "$PULL_DST" 2>/dev/null | sed 's/^/      /'
fi

BIG_SRC="$WORK/pushed-big.bin"
head -c 300000 /dev/urandom > "$BIG_SRC"
BIG_DST="/data/local/tmp/pushed-big-through-the-gateway.bin"
BIG_BACK="$WORK/pulled-big.bin"
if timeout 120 adb -P "$LOCALPORT" -s "$DEVICE" push "$BIG_SRC" "$BIG_DST" >"$WORK/push-big.log" 2>&1 &&
   timeout 120 adb -P "$LOCALPORT" -s "$DEVICE" pull "$BIG_DST" "$BIG_BACK" >"$WORK/pull-big.log" 2>&1 &&
   cmp -s "$BIG_SRC" "$BIG_BACK"; then
  ok "a file spanning many sync frames survives push then pull unchanged"
else
  bad "a large file did not come back identical"
  sed 's/^/      /' "$WORK/push-big.log" "$WORK/pull-big.log" 2>/dev/null | head -6
  ls -l "$BIG_BACK" 2>/dev/null | sed 's/^/      /'
fi

# ------------------------------------------------------------ directories

step "a directory survives push and pull through the gateway"

# A directory is the case an operator actually has -- an APK, a config tree, a set of logs --
# and it is not a bigger single file. adb asks the device what the directory contains before
# it sends anything, so the whole path depends on the device's listing being answered in the
# shape this adb build reads. A gateway that moves bytes but gets the listing wrong pushes a
# single file with the directory's name and reports success.
PUSHDIR="$WORK/dir-to-push"
mkdir -p "$PUSHDIR/nested"
printf 'first file'  > "$PUSHDIR/one.txt"
printf 'second file' > "$PUSHDIR/nested/two.txt"
# A file big enough to span more than one sync frame, so the pull inside the directory is not
# passing because everything fits in a single packet.
head -c 200000 /dev/urandom > "$PUSHDIR/nested/three.bin"

DIRDST="/data/local/tmp/dir-through-the-gateway"
if timeout 120 adb -P "$LOCALPORT" -s "$DEVICE" push "$PUSHDIR" "$DIRDST" >"$WORK/push-dir.log" 2>&1; then
  ok "adb push reported success for a directory"
else
  bad "adb push failed for a directory"
  sed 's/^/      /' "$WORK/push-dir.log" | head -3
fi

DIRBACK="$WORK/dir-pulled-back"
rm -rf "$DIRBACK"
if timeout 120 adb -P "$LOCALPORT" -s "$DEVICE" pull "$DIRDST" "$DIRBACK" >"$WORK/pull-dir.log" 2>&1; then
  ok "adb pull reported success for a directory"
else
  bad "adb pull failed for a directory"
  sed 's/^/      /' "$WORK/pull-dir.log" | head -3
fi

# Compared on the bytes and on the shape, because a pull that returns one file and reports
# success is exactly what a broken listing looks like. adb prints "N files pulled" whatever it
# actually did, so the count in its own output is not the assertion.
if [[ "$(cat "$DIRBACK/one.txt" 2>/dev/null)" == "first file" ]] &&
   [[ "$(cat "$DIRBACK/nested/two.txt" 2>/dev/null)" == "second file" ]] &&
   cmp -s "$PUSHDIR/nested/three.bin" "$DIRBACK/nested/three.bin"; then
  ok "every file in the directory came back, including a nested one spanning many frames"
else
  bad "the directory did not come back intact"
  find "$DIRBACK" -type f 2>/dev/null | sort | sed 's/^/      /'
fi

# ------------------------------------------------- the v1 sync path

step "a directory survives push and pull on the v1 sync path"

# adb picks the spelling of every sync command from the feature list it is given for the
# device, and the two spellings are not interchangeable on the wire. A v2 listing entry is a
# DNT2 word, a 68-byte stat body, and a length-prefixed name; a v1 one is a DENT word, four
# 4-byte words, and the name. Neither client reads the other's, and both report a
# directory pull that collected nothing as a plain failure.
#
# So this is the same check against a device that advertises no v2 sync features, which is
# what a device predating them looks like and what puts adb on the v1 path. The reply
# widths on that path are the ones measured off a stock client's reads, and getting either
# wrong ends the directory walk rather than failing the command: a walk that stops after
# the first entry returns a directory with one file in it, and a client waiting out a read
# of a width the device did not send hangs at the end of the listing instead of reporting.
#
# The nested file is larger than one DATA frame so the transfer inside the directory is not
# passing because everything fits in a single packet.
V1DIR_DST="/data/local/tmp/dir-on-the-v1-path"
if timeout 120 adb -P "$LOCALPORT" -s "$DEVICE_V1" push "$PUSHDIR" "$V1DIR_DST" >"$WORK/push-dir-v1.log" 2>&1; then
  ok "adb push reported success for a directory on the v1 path"
else
  bad "adb push failed for a directory on the v1 path"
  sed 's/^/      /' "$WORK/push-dir-v1.log" | head -3
fi

V1DIR_BACK="$WORK/dir-pulled-back-v1"
rm -rf "$V1DIR_BACK"
if timeout 120 adb -P "$LOCALPORT" -s "$DEVICE_V1" pull "$V1DIR_DST" "$V1DIR_BACK" >"$WORK/pull-dir-v1.log" 2>&1; then
  ok "adb pull reported success for a directory on the v1 path"
else
  bad "adb pull failed for a directory on the v1 path"
  sed 's/^/      /' "$WORK/pull-dir-v1.log" | head -3
fi

if [[ "$(cat "$V1DIR_BACK/one.txt" 2>/dev/null)" == "first file" ]] &&
   [[ "$(cat "$V1DIR_BACK/nested/two.txt" 2>/dev/null)" == "second file" ]] &&
   cmp -s "$PUSHDIR/nested/three.bin" "$V1DIR_BACK/nested/three.bin"; then
  ok "every file came back on the v1 path, including a nested one spanning many frames"
else
  bad "the directory did not come back intact on the v1 path"
  find "$V1DIR_BACK" -type f 2>/dev/null | sort | sed 's/^/      /'
fi

# The shape as well as the contents, for the reason given above: a walk that stopped after
# the first entry produces one file, no error, and a per-file comparison that never got to
# run. Counting what came back is what distinguishes the two.
V1DIR_FILES="$(find "$V1DIR_BACK" -type f 2>/dev/null | wc -l | tr -d ' ')"
if [[ "$V1DIR_FILES" == "3" ]]; then
  ok "the v1 listing was walked to the end: three files, not one"
else
  bad "the v1 listing returned $V1DIR_FILES files, want 3"
  find "$V1DIR_BACK" -type f 2>/dev/null | sort | sed 's/^/      /'
fi

# ----------------------------------------------------------- port forwarding

step "adb forward and adb reverse carry bytes to the other end"

# Both directions are checked on the bytes, for the same reason as the files above: each of
# these commands reports success when it has bound a port and nothing more. What has to work
# is what happens when something connects to a bound port.
#
# The asymmetry is the point of the two checks. `adb forward` binds a port on the machine
# running the adb binary's server -- here, the gateway -- and reaches the device through it.
# `adb reverse` binds a port on the device and reaches the gateway through it. So each needs
# an echo server on the far side, and a forward and a reverse that both "succeeded" while
# carrying nothing are the failure this section exists to catch.

# One echo server per direction. The device's own loopback is where a forward lands, and the
# gateway's loopback is where a reverse lands; on this one machine they are the same address,
# which is why the two checks are separate rather than one check that reuses a result.
cat > "$WORK/echo.py" <<'PYEOF'
import socket, sys, threading
port = int(sys.argv[1])
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port))
srv.listen(8)
print("listening", port, flush=True)
def handle(c):
    try:
        while True:
            b = c.recv(4096)
            if not b:
                break
            c.sendall(b"echo:" + b)
    except OSError:
        pass
    finally:
        c.close()
while True:
    conn, _ = srv.accept()
    threading.Thread(target=handle, args=(conn,), daemon=True).start()
PYEOF

FWD_PORT=$(( 37000 + RANDOM % 1000 ))
python3 "$WORK/echo.py" "$FWD_PORT" >"$WORK/echo-fwd.log" 2>&1 &
PIDS+=($!)
REV_PORT=$(( 38500 + RANDOM % 1000 ))
python3 "$WORK/echo.py" "$REV_PORT" >"$WORK/echo-rev.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 40); do
  [[ -s "$WORK/echo-fwd.log" && -s "$WORK/echo-rev.log" ]] && break
  sleep 0.25
done

# adb forward: bind here, land on the device.
FWD_LOCAL=$(( 40000 + RANDOM % 1000 ))
if timeout 30 adb -P "$LOCALPORT" -s "$DEVICE" forward "tcp:$FWD_LOCAL" "tcp:$FWD_PORT" 2>&1; then
  ok "adb forward bound a port on the gateway"
else
  bad "adb forward failed"
fi

# The listing is adb's own report that the forward exists, and it is checked separately from the
# round trip: a forward that is bound but leads nowhere lists correctly and carries nothing.
FWDLIST="$(timeout 30 adb -P "$LOCALPORT" -s "$DEVICE" forward --list 2>&1 || true)"
printf '%s\n' "$FWDLIST" | sed 's/^/      /'
if printf '%s\n' "$FWDLIST" | grep -q "tcp:$FWD_LOCAL" && printf '%s\n' "$FWDLIST" | grep -q "tcp:$FWD_PORT"; then
  ok "adb forward --list reports the bound port and where it leads"
else
  bad "adb forward --list does not report the forward"
fi

FWD_OUT="$(timeout 30 python3 -c "
import socket
c = socket.create_connection(('127.0.0.1', $FWD_LOCAL), 5)
c.sendall(b'through-the-forward')
c.settimeout(10)
print(c.recv(256).decode(), end='')
c.close()
" 2>&1 || true)"
printf '%s\n' "$FWD_OUT" | sed 's/^/      /'
if [[ "$FWD_OUT" == "echo:through-the-forward" ]]; then
  ok "a connection to the forwarded port reached the device and came back"
else
  bad "the forwarded port carried nothing"
fi

# adb reverse: bind on the device, land on the gateway.
REV_REMOTE=$(( 41500 + RANDOM % 1000 ))
if timeout 30 adb -P "$LOCALPORT" -s "$DEVICE" reverse "tcp:$REV_REMOTE" "tcp:$REV_PORT" 2>&1; then
  ok "adb reverse bound a port on the device"
else
  bad "adb reverse failed"
fi

REV_OUT="$(timeout 30 python3 -c "
import socket
c = socket.create_connection(('127.0.0.1', $REV_REMOTE), 5)
c.sendall(b'through-the-reverse')
c.settimeout(10)
print(c.recv(256).decode(), end='')
c.close()
" 2>&1 || true)"
printf '%s\n' "$REV_OUT" | sed 's/^/      /'
if [[ "$REV_OUT" == "echo:through-the-reverse" ]]; then
  ok "a connection to the reversed port reached the gateway and came back"
else
  bad "the reversed port carried nothing"
fi

# Both are released, and the removal is what proves the ports were this gateway's rather than
# something left behind by a previous run of this script.
timeout 30 adb -P "$LOCALPORT" -s "$DEVICE" forward --remove "tcp:$FWD_LOCAL" >/dev/null 2>&1 || true
timeout 30 adb -P "$LOCALPORT" -s "$DEVICE" reverse --remove "tcp:$REV_REMOTE" >/dev/null 2>&1 || true
if python3 -c "
import socket, sys
try:
    socket.create_connection(('127.0.0.1', $FWD_LOCAL), 2).close()
except OSError:
    sys.exit(0)
sys.exit(1)
"; then
  ok "the forward was released and its port is no longer accepting"
else
  bad "the forward's port is still bound after --remove"
fi

# ------------------------------------------------------------ authorization

step "authorization is enforced on the gateway"
# A role without shell must not get the bridge, whatever the client asks for.
"$WORK/bin/ard-ca" operator -dir "$PKI" -name bob >/dev/null 2>&1
BADPORT=$(( LOCALPORT + 40 ))
"$WORK/bin/ard-connect" \
  -gateway "127.0.0.1:$OPPORT" \
  -ca "$PKI/server/ca.crt" \
  -cert "$PKI/operators/leaves/bob.crt" \
  -key "$PKI/operators/leaves/bob.key" \
  -listen "127.0.0.1:$BADPORT" \
  >"$WORK/connect-bob.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 60); do
  grep -q "publishing the adb port" "$WORK/connect-bob.log" 2>/dev/null && break
  sleep 0.25
done

# Bob's client publishes a port, exactly as alice's does, and that is the design rather than a
# gap: the client does not know which devices exist and deliberately does not ask. It cannot
# decide who may drive what -- the gateway holds that policy -- so a client-side refusal would
# mean the client had a copy of it, and two copies of an authorization policy is one too many.
# The refusal therefore happens where the decision is made, at the transport request.
if grep -q "publishing the adb port" "$WORK/connect-bob.log" 2>/dev/null; then
  ok "bob's client publishes a port; it holds no device list to decide from"
else
  bad "bob's client did not publish a port, so the checks below would prove nothing"
  sed 's/^/      /' "$WORK/connect-bob.log" | head -5
  exit 1
fi

adb kill-server >/dev/null 2>&1 || true
export ADB_VENDOR_KEYS="$WORK/adbkeys"
for _ in $(seq 1 40); do
  timeout 15 adb -P "$BADPORT" devices >/dev/null 2>&1 && break
  sleep 0.25
done

# Bob holds files on this device and is deliberately not given shell. So he must be told the
# device exists -- a denial with no explanation is impossible to act on -- and he must not be
# able to open a transport to it. The distinction is that the device is visible in the listing
# and the refusal comes when he tries to use it, which is where the policy is.
BOBDEVICES="$(timeout 15 adb -P "$BADPORT" devices 2>/dev/null || true)"
printf "%s\n" "$BOBDEVICES" | sed 's/^/      /'

if printf "%s\n" "$BOBDEVICES" | grep -q "^$DEVICE[[:space:]]*device"; then
  ok "an operator entitled to the device is told it exists"
else
  bad "the device is hidden from an operator whose role holds a permission on it"
fi

# Now the refusal. adb prints the gateway's FAIL message on stderr, so that is where the reason
# has to appear: this is the operator's own terminal, and it is the only thing they will read.
#
# It ran the client under `timeout` and read the exit code, and `timeout` kills a long-running
# process with exit 124 -- the same thing an operator with shell gets. The check is on the
# message in the output above and on the outcome below, never on the client's exit code alone.
BOBOUT="$(timeout 25 adb -P "$BADPORT" -s "$DEVICE" shell whoami 2>&1 || true)"
printf '%s\n' "$BOBOUT" | sed 's/^/      /'

# The message names a refusal, so the check is on the outcome -- a shell ran or it did not --
# rather than on the presence of a string. An operator whose role grants shell would otherwise
# satisfy a grep for "may not attach" if any other part of the output ever said it, and the
# check would pass while the thing it exists to catch went unnoticed.
if printf '%s\n' "$BOBOUT" | grep -q "^shell$"; then
  bad "an operator whose role holds no shell got a shell session"
else
  ok "an operator whose role holds no shell is refused a shell session"
fi

# And no session came back that could be mistaken for one: the output has to be the refusal
# alone, with nothing the device produced on it.
if printf '%s\n' "$BOBOUT" | grep -q "may not attach"; then
  ok "the gateway's reason reached the operator's own terminal"
else
  bad "the refusal did not reach adb's stderr, so the operator sees only a failure"
fi

# The refusal has to explain itself: it must name the device, the role and the permission that
# is missing. Any one of the three alone leaves the reader guessing, and the operator's next
# question is always "what do I need to ask for".
if printf '%s\n' "$BOBOUT" | grep -q "$DEVICE" &&
   printf '%s\n' "$BOBOUT" | grep -q "observer" &&
   printf '%s\n' "$BOBOUT" | grep -q "shell"; then
  ok "the refusal names the device, the role and the missing permission"
else
  bad "the refusal does not explain itself"
fi

# The gateway agreed, independently of what the client decided: it identified bob and marked
# the device not bridgeable, so no attach was ever attempted. What must NOT appear is a stream
# being opened for him -- an operator who may not drive the device getting one would be the whole
# failure this test exists to catch.
if grep -q '"actor":"bob"' "$WORK/audit.log" 2>/dev/null; then
  ok "the gateway identified the operator it refused"
else
  bad "the gateway did not record the refused operator at all"
fi

if grep -qE '"kind":"stream.open","actor":"bob"' "$WORK/audit.log" 2>/dev/null; then
  bad "a stream was opened for an operator who may not drive the device"
else
  ok "no stream was opened for the refused operator"
fi

# And the refusal itself has to be in the gateway's log, not only in the client's terminal: an
# operator who cannot see the reason needs an administrator who can, and the administrator reads
# this file.
if grep -q "may not attach" "$WORK/server.log" 2>/dev/null; then
  ok "the gateway logged the refusal and its reason"
else
  bad "the gateway did not log why it refused the operator"
  grep -i bob "$WORK/server.log" | sed 's/^/      /' | head -3
fi

# ------------------------------------------------- revoking a permission

step "revoking a permission takes the capability away, observed through adb"

# A permission that is checked but whose absence nothing observes is a permission that might as
# well not be checked. So the revocation is measured from the other end: an operator whose role
# holds shell drives the device and binds a port in both directions, and an operator whose role
# holds the same permissions without `forward` and `reverse` is stopped at exactly those two.
#
# Both roles drive the same device. If the refusals below came from the device or from the
# transport rather than from the permissions, the driver would be refused too -- so the driver
# passing and the other operator failing on the same device and the same commands is what makes
# this a check of the permission rather than of the path.
"$WORK/bin/ard-ca" operator -dir "$PKI" -name carol >/dev/null 2>&1
CAROLPORT=$(( BADPORT + 1 ))
"$WORK/bin/ard-connect" \
  -gateway "127.0.0.1:$OPPORT" \
  -ca "$PKI/server/ca.crt" \
  -cert "$PKI/operators/leaves/carol.crt" \
  -key "$PKI/operators/leaves/carol.key" \
  -listen "127.0.0.1:$CAROLPORT" \
  >"$WORK/connect-carol.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 60); do
  grep -q "publishing the adb port" "$WORK/connect-carol.log" 2>/dev/null && break
  sleep 0.25
done
if grep -q "publishing the adb port" "$WORK/connect-carol.log" 2>/dev/null; then
  ok "the second operator's client published a port"
else
  bad "the second operator's client did not start, so the checks below would prove nothing"
  sed 's/^/      /' "$WORK/connect-carol.log" | head -5
  exit 1
fi

adb kill-server >/dev/null 2>&1 || true
export ADB_VENDOR_KEYS="$WORK/adbkeys"
for _ in $(seq 1 40); do
  timeout 15 adb -P "$CAROLPORT" devices >/dev/null 2>&1 && break
  sleep 0.25
done

# The positive side first, and on this same device: shell is what the two roles share, so a
# failure here would say the fixture is wrong rather than that the permissions work.
CAROLSHELL="$(timeout 25 adb -P "$CAROLPORT" -s "$DEVICE" shell whoami 2>&1 | tr -d '\r' || true)"
if printf '%s\n' "$CAROLSHELL" | grep -qx "shell"; then
  ok "an operator holding shell drives the device: $CAROLSHELL"
else
  bad "the operator whose role holds shell was refused: $CAROLSHELL"
fi

CAROL_FWD_LOCAL=$(( 42000 + RANDOM % 1000 ))
CAROLFWD="$(timeout 30 adb -P "$CAROLPORT" -s "$DEVICE" forward "tcp:$CAROL_FWD_LOCAL" "tcp:$FWD_PORT" 2>&1 || true)"
printf '%s\n' "$CAROLFWD" | sed 's/^/      /'

# The outcome, not the wording: what matters is that the port was not bound. `adb forward`
# prints the port it bound and nothing else, so a refusal is a message and a success is a
# number, and the port answering is the third and final piece of evidence.
if printf '%s\n' "$CAROLFWD" | grep -qx "$CAROL_FWD_LOCAL"; then
  bad "a forward was bound for a role holding no forward permission"
else
  ok "adb forward is refused to a role that does not hold forward"
fi

# Nothing is listening: a refusal that arrived after the bind would leave a port on the gateway
# reaching the device, which is the whole thing the permission exists to prevent.
if python3 -c "
import socket, sys
try:
    socket.create_connection(('127.0.0.1', $CAROL_FWD_LOCAL), 2).close()
except OSError:
    sys.exit(0)
sys.exit(1)
"; then
  ok "no port is bound on the gateway for the refused forward"
else
  bad "tcp:$CAROL_FWD_LOCAL is accepting connections after the forward was refused"
fi

# And the refusal has to be actionable: the device, the role, and the permission to ask for.
# One of the three alone leaves the reader guessing, and the operator's next question is always
# "what do I need to ask for".
if printf '%s\n' "$CAROLFWD" | grep -q "$DEVICE" &&
   printf '%s\n' "$CAROLFWD" | grep -q "driver" &&
   printf '%s\n' "$CAROLFWD" | grep -q "forward"; then
  ok "the forward refusal names the device, the role and the missing permission"
else
  bad "the forward refusal does not explain itself"
fi

CAROL_REV_REMOTE=$(( 43000 + RANDOM % 1000 ))
CAROLREV="$(timeout 30 adb -P "$CAROLPORT" -s "$DEVICE" reverse "tcp:$CAROL_REV_REMOTE" "tcp:$REV_PORT" 2>&1 || true)"
printf '%s\n' "$CAROLREV" | sed 's/^/      /'

# The same three-part message, for the same reason and on the other direction.
if printf '%s\n' "$CAROLREV" | grep -q "$DEVICE" &&
   printf '%s\n' "$CAROLREV" | grep -q "driver" &&
   printf '%s\n' "$CAROLREV" | grep -q "reverse"; then
  ok "the reverse refusal names the device, the role and the missing permission"
else
  bad "adb reverse was not refused with a reason that explains itself: $CAROLREV"
fi

# The refusal has to be about the permission rather than about the path, so the same command
# from the role that holds `reverse` must not be refused for it. Without this, a refusal
# produced by anything else on the way -- the mock, the transport, a port already in use --
# would satisfy the check above.
HOLDER_REV_REMOTE=$(( 43500 + RANDOM % 1000 ))
HOLDERREV="$(timeout 30 adb -P "$LOCALPORT" -s "$DEVICE" reverse "tcp:$HOLDER_REV_REMOTE" "tcp:$REV_PORT" 2>&1 || true)"
printf '%s\n' "$HOLDERREV" | sed 's/^/      /'
if printf '%s\n' "$HOLDERREV" | grep -q "lacks permission"; then
  bad "the role holding reverse was refused for it: $HOLDERREV"
else
  ok "the role holding reverse is not refused for it on the same device"
fi
timeout 30 adb -P "$LOCALPORT" -s "$DEVICE" reverse --remove "tcp:$HOLDER_REV_REMOTE" >/dev/null 2>&1 || true

# And the same for forward, so both halves of the pair read as permissions rather than as a
# gateway that cannot bind a port at all.
HOLDER_FWD_LOCAL=$(( 44000 + RANDOM % 1000 ))
if timeout 30 adb -P "$LOCALPORT" -s "$DEVICE" forward "tcp:$HOLDER_FWD_LOCAL" "tcp:$FWD_PORT" 2>&1; then
  ok "the role holding forward binds a port on the same device"
else
  bad "the role holding forward was refused; the revocation above would prove nothing"
fi
timeout 30 adb -P "$LOCALPORT" -s "$DEVICE" forward --remove "tcp:$HOLDER_FWD_LOCAL" >/dev/null 2>&1 || true

# ------------------------------------------------- one operator's forwards

step "one operator does not see or release another's forwards"

# A forward outlives the connection that asked for it: adb closes that connection as soon as the
# port is bound, so anything the gateway learns about the forward has to be recorded at binding
# time rather than read off a connection that is gone. Two consequences follow, and both are
# about reachability rather than about tidiness.
#
# The listing is a request about ports, and a device identifier in it is the string `adb -s`
# takes. An unfiltered listing hands one operator the device ids and ports of another
# operator's tunnels.
#
# The removal is worse than the listing: a port bound on the gateway is still listening and still
# serving, so answering OKAY to a removal that did not happen would tell the operator their port
# is gone while anything that can reach the gateway is still reaching a device through it.

# The round-trip section above released its forward, so one is bound here and stays bound for
# the length of this section. It is on the gateway's loopback and it is alice's, and both facts
# are what the next checks turn on.
OWNED_FWD_LOCAL=$(( 45500 + RANDOM % 1000 ))
if timeout 30 adb -P "$LOCALPORT" -s "$DEVICE" forward "tcp:$OWNED_FWD_LOCAL" "tcp:$FWD_PORT" 2>&1; then
  ok "the first operator bound a forward to keep for this section"
else
  bad "could not bind the forward this section depends on"
  exit 1
fi

# The listing is answered from the gateway's own set rather than from the device, so the first
# operator's own port has to appear in it.
ALICE_PORT_LIST="$(timeout 30 adb -P "$LOCALPORT" forward --list 2>&1 || true)"
printf '%s\n' "$ALICE_PORT_LIST" | sed 's/^/      /'
if printf '%s\n' "$ALICE_PORT_LIST" | grep -q "tcp:$OWNED_FWD_LOCAL"; then
  ok "the operator who bound the forward sees it in the listing"
else
  bad "the operator's own forward is not in the listing: $ALICE_PORT_LIST"
fi

# The same question asked by an operator who holds forward on the same device. `adb forward
# --list` with no serial is the form the stock server answers.
CAROL_LIST="$(timeout 30 adb -P "$CAROLPORT" forward --list 2>&1 || true)"
printf '%s\n' "$CAROL_LIST" | sed 's/^/      /'
if printf '%s\n' "$CAROL_LIST" | grep -q "tcp:$OWNED_FWD_LOCAL"; then
  bad "another operator was shown a forward that is not his"
else
  ok "another operator is shown no forward belonging to the first"
fi

# The same for the per-device form, which is what a caller reaching for a scoped answer tries
# first and which the stock server accepts.
CAROL_LIST_SERIAL="$(timeout 30 adb -P "$CAROLPORT" -s "$DEVICE" forward --list 2>&1 || true)"
printf '%s\n' "$CAROL_LIST_SERIAL" | sed 's/^/      /'
if printf '%s\n' "$CAROL_LIST_SERIAL" | grep -q "tcp:$OWNED_FWD_LOCAL"; then
  bad "the per-device listing showed another operator's forward"
else
  ok "the per-device listing shows the asking operator's forwards only"
fi

# The removal needs its own operator. Carol holds no forward permission, so her attempt would
# stop at the permission rather than at the ownership, which is the right answer for her and
# proves nothing about ownership. Frank holds forward on the same device, so the only thing
# standing between him and alice's port is whose it is.
"$WORK/bin/ard-ca" operator -dir "$PKI" -name frank >/dev/null 2>&1
FRANKPORT=$(( CAROLPORT + 1 ))
"$WORK/bin/ard-connect" \
  -gateway "127.0.0.1:$OPPORT" \
  -ca "$PKI/server/ca.crt" \
  -cert "$PKI/operators/leaves/frank.crt" \
  -key "$PKI/operators/leaves/frank.key" \
  -listen "127.0.0.1:$FRANKPORT" \
  >"$WORK/connect-frank.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 60); do
  grep -q "publishing the adb port" "$WORK/connect-frank.log" 2>/dev/null && break
  sleep 0.25
done
if grep -q "publishing the adb port" "$WORK/connect-frank.log" 2>/dev/null; then
  ok "a third operator's client published a port"
else
  bad "the third operator's client did not start, so the ownership checks would prove nothing"
  sed 's/^/      /' "$WORK/connect-frank.log" | head -5
  exit 1
fi

adb kill-server >/dev/null 2>&1 || true
export ADB_VENDOR_KEYS="$WORK/adbkeys"
for _ in $(seq 1 40); do
  timeout 15 adb -P "$FRANKPORT" devices >/dev/null 2>&1 && break
  sleep 0.25
done

# Frank may forward on this device -- the permission is his -- so he binds one of his own, which
# is what makes the listing below a comparison between two non-empty answers rather than between
# an answer and an empty one.
FRANK_FWD_LOCAL=$(( 46000 + RANDOM % 1000 ))
if timeout 30 adb -P "$FRANKPORT" -s "$DEVICE" forward "tcp:$FRANK_FWD_LOCAL" "tcp:$FWD_PORT" 2>&1; then
  ok "the second forward-capable operator bound a port of his own"
else
  bad "the second forward-capable operator could not bind a port; the checks below would prove nothing"
fi

# The listing is then compared in both directions: each operator sees his own port and not the
# other's. One direction alone would pass against a gateway that shows nothing to anybody.
FRANK_LIST="$(timeout 30 adb -P "$FRANKPORT" forward --list 2>&1 || true)"
printf '%s\n' "$FRANK_LIST" | sed 's/^/      /'
if printf '%s\n' "$FRANK_LIST" | grep -q "tcp:$FRANK_FWD_LOCAL"; then
  ok "the second operator sees the forward he bound"
else
  bad "the second operator's own forward is not in his listing: $FRANK_LIST"
fi
if printf '%s\n' "$FRANK_LIST" | grep -q "tcp:$OWNED_FWD_LOCAL"; then
  bad "the second operator was shown the first operator's forward"
else
  ok "neither operator is shown the other's forward"
fi

FRANK_STEAL="$(timeout 30 adb -P "$FRANKPORT" -s "$DEVICE" forward --remove "tcp:$OWNED_FWD_LOCAL" 2>&1 || true)"
printf '%s\n' "$FRANK_STEAL" | sed 's/^/      /'
if printf '%s\n' "$FRANK_STEAL" | grep -qi "another operator"; then
  ok "the refusal says the port belongs to another operator"
else
  bad "removing another operator's forward did not say whose it is: $FRANK_STEAL"
fi

# And the port is still there, which is the part that decides whether the refusal was honest. A
# removal that answered OKAY and left the listener bound would satisfy the check above while the
# tunnel kept carrying traffic.
FWD_STILL_LISTED="$(timeout 30 adb -P "$LOCALPORT" forward --list 2>&1 || true)"
if printf '%s\n' "$FWD_STILL_LISTED" | grep -q "tcp:$OWNED_FWD_LOCAL"; then
  ok "the refused removal left the first operator's forward in place"
else
  bad "the first operator's forward is gone: $FWD_STILL_LISTED"
fi

FWD_STILL_CARRIES="$(timeout 30 python3 -c "
import socket
c = socket.create_connection(('127.0.0.1', $OWNED_FWD_LOCAL), 5)
c.sendall(b'still-bound')
c.settimeout(10)
print(c.recv(256).decode(), end='')
c.close()
" 2>&1 || true)"
printf '%s\n' "$FWD_STILL_CARRIES" | sed 's/^/      /'
if [[ "$FWD_STILL_CARRIES" == "echo:still-bound" ]]; then
  ok "the port refused for removal is still carrying traffic, so the refusal was honest"
else
  bad "the port stopped carrying traffic: $FWD_STILL_CARRIES"
fi

# Frank's own port is released, so the removal half is shown to work rather than to be broken
# for everybody: a check that only ever sees refusals passes against a gateway that removes
# nothing at all.
timeout 30 adb -P "$FRANKPORT" -s "$DEVICE" forward --remove "tcp:$FRANK_FWD_LOCAL" >/dev/null 2>&1 || true
if python3 -c "
import socket, sys
try:
    socket.create_connection(('127.0.0.1', $FRANK_FWD_LOCAL), 2).close()
except OSError:
    sys.exit(0)
sys.exit(1)
"; then
  ok "an operator can still release a forward of his own"
else
  bad "an operator could not release his own forward, so the refusals above prove nothing"
fi

# The forward this section bound is released, so a run of this script leaves nothing listening
# on the gateway.
timeout 30 adb -P "$LOCALPORT" -s "$DEVICE" forward --remove "tcp:$OWNED_FWD_LOCAL" >/dev/null 2>&1 || true
timeout 30 adb -P "$LOCALPORT" -s "$DEVICE" reverse --remove "tcp:$REV_REMOTE" >/dev/null 2>&1 || true

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


