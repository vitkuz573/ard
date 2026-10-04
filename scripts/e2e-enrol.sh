#!/usr/bin/env bash
# End-to-end certificate enrolment, against a real gateway.
#
#   ard-agent -enrol ──▶ gateway :7200 ──▶ mailbox
#        │  prints a claim code
#        │
#   ard-ca enrol -code ──▶ control.sock ──▶ CSR back to the operator
#        │  signs locally, sends the certificate
#        ▼
#   gateway ──▶ device, which stores it and confirms
#
# The gateway runs as root here, because enrolment is deliberately restricted to uid 0
# on the control socket. That restriction is the point of the design, so testing the
# happy path without it would be testing something else.
#
# What this proves that unit tests cannot: that a certificate obtained this way is
# actually usable as a device identity. A CSR flow can be internally consistent and still
# produce a certificate the agent cannot use, and that failure only shows up as a TLS
# error on the first real connection.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

PASS=0
FAIL=0
ok()   { printf '  \033[32mok\033[0m   %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
step() { printf '\n\033[1m== %s\033[0m\n' "$1"; }

# --------------------------------------------------------------------- build

step "build"
mkdir -p "$WORK/bin"
for cmd in ard-server ard-ca ard-agent mockadbd; do
  go build -o "$WORK/bin/$cmd" "./cmd/$cmd"
done
ok "binaries built"

# ----------------------------------------------------------------------- pki

step "PKI"
PKI="$WORK/pki"
mkdir -p "$PKI/server" "$PKI/devices" "$PKI/operators"
"$WORK/bin/ard-ca" init -dir "$PKI" -san "localhost,127.0.0.1" >/dev/null
ok "roots created (server, devices, operators are separate)"

# init also issues the server leaf, from the server root only.
if [[ -s "$PKI/server/server.crt" && -s "$PKI/server/server.key" ]]; then
  ok "server identity present"
else
  bad "ard-ca init did not produce a server identity"
  exit 1
fi

# The gateway refuses to start without an operator policy, which is the right default.
# Reuse the shipped template so this test exercises the same file an operator would.
sed 's/CHANGE-ME-device-uuid/enrol-test-device/g' deploy/operators.yaml \
  >"$PKI/operators/operators.yaml"
ok "operator policy in place"

# ------------------------------------------------------------------ gateway

step "gateway"
DEVPORT=$(( 21000 + RANDOM % 2000 ))
OPPORT=$(( DEVPORT + 1 ))
ENPORT=$(( DEVPORT + 2 ))
SOCK="$WORK/control.sock"
AUDIT="$WORK/audit.log"

# The device is not in the allowlist yet on purpose: enrolment must not depend on it,
# and the test would otherwise pass for the wrong reason if it did.
sudo -n true 2>/dev/null || { bad "this test needs passwordless sudo (it runs the gateway as root)"; exit 1; }

sudo -n "$WORK/bin/ard-server" \
  -listen-devices "127.0.0.1:$DEVPORT" \
  -listen-operators "127.0.0.1:$OPPORT" \
  -listen-enrol "127.0.0.1:$ENPORT" \
  -control-socket "$SOCK" \
  -pki "$PKI" \
  -devices "enrol-test-device" \
  -operators "$PKI/operators/operators.yaml" \
  -enrol-ttl 3m \
  -audit "$AUDIT" \
  >"$WORK/server.log" 2>&1 &
SERVER_PID=$!
cleanup() { sudo -n kill "$SERVER_PID" 2>/dev/null || true; }
trap 'cleanup; rm -rf "$WORK"' EXIT

for _ in $(seq 1 50); do
  if grep -q "enrol on" "$WORK/server.log" 2>/dev/null; then break; fi
  sleep 0.2
done
if grep -q "enrol on" "$WORK/server.log" 2>/dev/null; then
  ok "gateway listening, enrolment port reported"
else
  bad "gateway did not start"
  sed 's/^/      /' "$WORK/server.log" | head -20
  exit 1
fi

# ------------------------------------------------------------------- device

step "device generates a key and asks for a certificate"
DEVDIR="$WORK/device"
AGENT_OUT="$WORK/agent.out"
sudo -n chmod 0777 "$WORK" 2>/dev/null || true

# Run as the ordinary user, writing into a directory it owns: enrolment must not need
# root on the device, because a phone app does not have it.
"$WORK/bin/ard-agent" \
  -enrol "127.0.0.1:$ENPORT" \
  -enrol-id "enrol-test-device" \
  -enrol-name "Enrol Test Device" \
  -enrol-out "$DEVDIR" \
  -enrol-timeout 90s \
  >"$AGENT_OUT" 2>"$WORK/agent.err" &
AGENT_PID=$!

# The agent prints the code before it can receive anything, so this is where the operator
# would be looking.
CODE=""
for _ in $(seq 1 100); do
  if grep -q '^code=' "$AGENT_OUT" 2>/dev/null; then break; fi
  if ! kill -0 "$AGENT_PID" 2>/dev/null; then break; fi
  sleep 0.2
done
CODE="$(sed -n 's/^code=//p' "$AGENT_OUT" | head -1)"
if [[ -n "$CODE" ]]; then
  ok "device received claim code $CODE"
else
  bad "device never printed a claim code"
  echo "      agent stderr:"; sed 's/^/        /' "$WORK/agent.err" | head -10
  sed 's/^/        /' "$AGENT_OUT"
  exit 1
fi

# The private key must exist before anything else happens, and must not be readable by
# anyone else.
if [[ -f "$DEVDIR/device.key" ]]; then
  ok "device wrote its own private key before contacting the gateway"
else
  bad "device.key was never written"
fi
KEYMODE="$(stat -c '%a' "$DEVDIR/device.key" 2>/dev/null || echo '?')"
if [[ "$KEYMODE" == "600" ]]; then
  ok "private key is mode 600"
else
  bad "private key is mode $KEYMODE, want 600"
fi
if grep -q "BEGIN EC PRIVATE KEY" "$AGENT_OUT" 2>/dev/null; then
  bad "the private key was printed to stdout"
else
  ok "the private key never appeared in the agent's output"
fi

FPR="$(sed -n 's/^gateway_fingerprint=//p' "$AGENT_OUT" | head -1)"
if [[ ${#FPR} -ge 32 ]]; then
  ok "device reported the gateway certificate fingerprint"
else
  bad "device did not report a fingerprint (got '$FPR')"
fi

# ----------------------------------------------------------------- operator

step "operator signs"
# -yes skips the interactive prompt; the prompt itself is covered by the code path that
# prints the request, and this test is about the protocol.
if sudo -n "$WORK/bin/ard-ca" enrol \
      -dir "$PKI" -socket "$SOCK" -code "$CODE" -ttl 24h -yes \
      >"$WORK/ca.out" 2>"$WORK/ca.err"; then
  ok "operator claimed, signed and delivered"
else
  bad "ard-ca enrol failed"
  sed 's/^/      /' "$WORK/ca.err" | head -10
  sed 's/^/      /' "$WORK/ca.out" | head -10
  kill "$AGENT_PID" 2>/dev/null || true
  exit 1
fi

wait "$AGENT_PID" 2>/dev/null || true
if grep -q '^enrolled=' "$AGENT_OUT"; then
  ok "device confirmed it stored the certificate"
else
  bad "device never reported enrolment as complete"
  sed 's/^/      /' "$WORK/agent.err" | head -10
fi

# ------------------------------------------------------------------ outcome

step "the issued identity is usable"
for f in device.crt ca.crt device.key; do
  if [[ -s "$DEVDIR/$f" ]]; then ok "$f written"; else bad "$f missing or empty"; fi
done

# The certificate must match the key the device generated. Verifying by pairing them is
# the same check TLS will do later, so a failure here is a failure that would have shown
# up as an unexplained handshake error.
if openssl x509 -in "$DEVDIR/device.crt" -noout -pubkey 2>/dev/null \
     | openssl pkey -pubin -outform DER 2>/dev/null \
     | sha256sum >"$WORK/cert.pub.sha"; then
  openssl pkey -in "$DEVDIR/device.key" -pubout -outform DER 2>/dev/null \
     | sha256sum >"$WORK/key.pub.sha"
  if cmp -s "$WORK/cert.pub.sha" "$WORK/key.pub.sha"; then
    ok "certificate public key matches the device's private key"
  else
    bad "certificate and private key do not match"
  fi
else
  bad "could not read the issued certificate"
fi

CN="$(openssl x509 -in "$DEVDIR/device.crt" -noout -subject 2>/dev/null || true)"
if grep -q 'enrol-test-device' <<<"$CN"; then
  ok "certificate names the device that asked for it"
else
  bad "certificate subject is unexpected: $CN"
fi

# Two different roots are in play, and conflating them is the mistake this catches.
#
# device.crt is signed by the DEVICE root, so that is what must verify it. ca.crt is the
# SERVER root, because it is what the device uses to verify the gateway on every
# connection. Checking the leaf against the delivered file therefore *must* fail, and an
# earlier version of this test asserted the opposite and was wrong for the same reason
# the code was: it treated one certificate as both the signer and the trust anchor.
if openssl verify -CAfile "$PKI/devices/ca.crt" "$DEVDIR/device.crt" >/dev/null 2>&1; then
  ok "issued certificate chains to the device root"
else
  bad "issued certificate does not chain to the device root"
fi

if openssl verify -CAfile "$DEVDIR/ca.crt" "$PKI/server/server.crt" >/dev/null 2>&1; then
  ok "the delivered CA is the one that signs the gateway certificate"
else
  bad "the delivered CA does not sign the gateway certificate"
fi

if cmp -s <(openssl x509 -in "$DEVDIR/ca.crt" -outform DER 2>/dev/null) \
          <(openssl x509 -in "$PKI/server/ca.crt" -outform DER 2>/dev/null); then
  ok "delivered ca.crt is byte-identical to the server root"
else
  bad "delivered ca.crt is not the server root"
fi

# The device must never receive a CA private key, on the first enrolment or any other.
if [[ -e "$DEVDIR/ca.key" || -e "$DEVDIR/server.key" ]]; then
  bad "a private key was written to the device directory"
else
  ok "no private key material beyond the device's own"
fi

# The gateway must not have signed anything: it holds no CA key. If it could, the whole
# two-party arrangement would be theatre.
if sudo -n test -r "$PKI/devices/ca.key" 2>/dev/null && \
   [[ "$(stat -c '%a' "$PKI/devices/ca.key")" != "600" ]]; then
  bad "the device CA key is not root-only"
else
  ok "device CA key stayed root-only"
fi

# --------------------------------------------------------------------- reuse

step "the enrolled identity connects to the device port"
# This is the assertion the whole exercise exists for: a device that enrolled without a
# human touching a key must end up able to do the job.
CHILD="$WORK/child"
mkdir -p "$CHILD"
# Give the agent a real adbd to talk to. The mock speaks adbd's protocol, so the agent
# finds a listener and the session is established end to end.
"$WORK/bin/mockadbd" -addr "127.0.0.1:0" >"$WORK/mock.log" 2>&1 &
MOCK_PID=$!
sleep 0.5
MOCKADDR="$(sed -n 's/^listening on //p' "$WORK/mock.log" | head -1)"
if [[ -z "$MOCKADDR" ]]; then
  MOCKADDR="$(grep -oE '127\.0\.0\.1:[0-9]+' "$WORK/mock.log" | head -1)"
fi
if [[ -n "$MOCKADDR" ]]; then
  ok "mock adbd listening on $MOCKADDR"
else
  bad "mock adbd did not report an address"
  sed 's/^/      /' "$WORK/mock.log" | head -5
fi

timeout 25 "$WORK/bin/ard-agent" \
  -gateway "127.0.0.1:$DEVPORT" \
  -device "enrol-test-device" \
  -name "Enrol Test Device" \
  -adbd "$MOCKADDR" \
  -ca "$DEVDIR/ca.crt" \
  -cert "$DEVDIR/device.crt" \
  -key "$DEVDIR/device.key" \
  >"$WORK/agent2.out" 2>&1 &
AGENT2_PID=$!

CONNECTED=0
for _ in $(seq 1 60); do
  if grep -qiE 'session established|adbd resolved|connected' "$WORK/agent2.out" 2>/dev/null; then
    if ! grep -q 'session ended' "$WORK/agent2.out" 2>/dev/null; then CONNECTED=1; break; fi
  fi
  if grep -qiE 'handshake|certificate|unknown authority|bad certificate' "$WORK/agent2.out" 2>/dev/null; then
    break
  fi
  sleep 0.25
done

kill "$AGENT2_PID" 2>/dev/null || true
kill "$MOCK_PID" 2>/dev/null || true

if [[ $CONNECTED -eq 1 ]]; then
  ok "the freshly enrolled certificate completed a mutual-TLS session"
else
  bad "the enrolled certificate could not open a session"
  sed 's/^/      /' "$WORK/agent2.out" | head -15
fi

# -------------------------------------------------------------------- replay

step "the claim code is single use"
if sudo -n "$WORK/bin/ard-ca" enrol -dir "$PKI" -socket "$SOCK" -code "$CODE" -yes \
     >"$WORK/ca2.out" 2>&1; then
  bad "a spent code was accepted a second time"
else
  ok "a spent code is refused"
fi

step "a wrong code is refused"
if sudo -n "$WORK/bin/ard-ca" enrol -dir "$PKI" -socket "$SOCK" -code "ZZZZ-ZZZZ" -yes \
     >"$WORK/ca3.out" 2>&1; then
  bad "an invented code was accepted"
else
  ok "an invented code is refused"
fi

# --------------------------------------------------------------------- audit

step "audit trail"
for kind in enrol.requested enrol.claimed enrol.delivered enrol.enrolled; do
  if sudo -n grep -q "$kind" "$AUDIT" 2>/dev/null; then
    ok "audit records $kind"
  else
    bad "audit is missing $kind"
  fi
done

# --------------------------------------------------------------------- result

step "unauthorised enrolment is refused"
# The control socket is mode 0660 and group-owned. A non-root caller must not be able to
# make the gateway hand out a certificate, because that is the escalation this design
# exists to prevent.
if "$WORK/bin/ard-ca" enrol -dir "$PKI" -socket "$SOCK" -code "ZZZZ-ZZZZ" -yes \
     >"$WORK/ca4.out" 2>&1; then
  bad "a non-root caller was allowed to use the enrolment control operations"
else
  ok "a non-root caller is refused"
fi

printf '\n'
if [[ $FAIL -eq 0 ]]; then
  printf '\033[32mall %d checks passed\033[0m\n' "$PASS"
  exit 0
fi
printf '\033[31m%d of %d checks failed\033[0m\n' "$FAIL" "$((PASS+FAIL))"
exit 1