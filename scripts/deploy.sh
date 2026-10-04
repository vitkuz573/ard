#!/usr/bin/env bash
# Deploy ARD to the production gateway in one command.
#
#   scripts/deploy.sh
#
# Idempotent and safe to re-run. It cross-compiles, uploads, installs the PKI and
# configuration, opens exactly the ports the gateway needs, installs the systemd
# units, starts everything and then verifies the result rather than assuming it.
#
# Existing PKI is never regenerated. That matters: the CA private keys are the root
# of trust for every device and operator, and replacing them would invalidate every
# issued certificate at once. Pass --rotate-device <uuid> to re-enrol one device.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SECRETS="${ARD_SECRETS_DIR:-$HOME/.ard-secrets}"
ENV_FILE="$SECRETS/prod.env"
KEY="${ARD_SSH_KEY:-$HOME/.ssh/id_ed25519_ard}"
KNOWN_HOSTS="$SECRETS/known_hosts"
TARGET_OS="${ARD_TARGET_OS:-linux/amd64}"
REMOTE_DIR="${ARD_REMOTE_DIR:-/opt/ard}"
STAGE="/root/ard-staging"

RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; DIM=$'\033[2m'; OFF=$'\033[0m'
step() { printf '\n%s==>%s %s\n' "$YELLOW" "$OFF" "$*"; }
ok()   { printf '  %sok%s   %s\n' "$GREEN" "$OFF" "$*"; }
warn() { printf '  %swarn%s %s\n' "$YELLOW" "$OFF" "$*"; }
die()  { printf '\n%sFAILED:%s %s\n' "$RED" "$OFF" "$*" >&2; exit 1; }
dim()  { printf '  %s%s%s\n' "$DIM" "$*" "$OFF"; }

ROTATE_DEVICE=""
FIRST_DEVICE=""
BUILD_ONLY=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --rotate-device) ROTATE_DEVICE="${2:?--rotate-device needs a UUID}"; shift 2 ;;
    --first-device)  FIRST_DEVICE="${2:?--first-device needs a UUID}"; shift 2 ;;
    --build-only)    BUILD_ONLY=1; shift ;;
    -h|--help) sed -n '2,22p' "$0"; exit 0 ;;
    *) die "unknown flag $1" ;;
  esac
done

# ---------------------------------------------------------------- preflight
step "preflight"
command -v go >/dev/null || die "go is not installed"
[[ -r "$ENV_FILE" ]] || die "missing $ENV_FILE (holds the gateway address)"
[[ -f "$KEY" ]]       || die "missing SSH key $KEY"
[[ -s "$KNOWN_HOSTS" ]] || die "missing $KNOWN_HOSTS; refusing to connect to an unpinned host"
# shellcheck disable=SC1090
set -a; source "$ENV_FILE"; set +a
: "${ARD_PROD_HOST:?ARD_PROD_HOST unset in $ENV_FILE}"
REMOTE="${ARD_PROD_USER:-root}@${ARD_PROD_HOST}"
ok "target $REMOTE, os $TARGET_OS"

SSH_OPTS=(-i "$KEY" -o IdentitiesOnly=yes -o PasswordAuthentication=no
          -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$KNOWN_HOSTS"
          -o ConnectTimeout=20 -p "${ARD_PROD_SSH_PORT:-22}")

ssh_() { ssh "${SSH_OPTS[@]}" "$REMOTE" "$@"; }

# ------------------------------------------------------------------ build
step "cross-compiling"
DIST="$ROOT/dist/$TARGET_OS"
mkdir -p "$DIST"
BINARIES=(ard-server ard-proxy ard-agent ard-ca)
for b in "${BINARIES[@]}"; do
  [[ -d "cmd/$b" ]] || continue
  CGO_ENABLED=0 GOOS="${TARGET_OS%/*}" GOARCH="${TARGET_OS#*/}" \
    go build -trimpath -ldflags "-s -w" -o "$DIST/$b" "./cmd/$b"
  printf '  %s%-12s %s bytes\n' "$DIM" "$b" "$(stat -c%s "$DIST/$b")"
done
ok "binaries built for $TARGET_OS"

if [[ $BUILD_ONLY -eq 1 ]]; then
  # Local builds only. Needed to test a change without touching the gateway, which
  # matters when the device under test is someone's actual phone.
  printf '\n%sbuild only%s  binaries in %s\n' "$GREEN" "$OFF" "$DIST"
  exit 0
fi

# ----------------------------------------------------------------- upload
step "uploading"
ssh_ "install -d -m 0700 $STAGE $STAGE/bin"
# scp spells the port flag -P (capital); -p means "preserve times". Passing the
# ssh array straight through would send "22" as a filename.
SCP_OPTS=(-i "$KEY" -o IdentitiesOnly=yes -o PasswordAuthentication=no
          -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$KNOWN_HOSTS"
          -o ConnectTimeout=20 -P "${ARD_PROD_SSH_PORT:-22}")
scp "${SCP_OPTS[@]}" "$DIST"/* "$REMOTE:$STAGE/bin/"
scp "${SCP_OPTS[@]}" \
  deploy/ard-server.service deploy/ard-proxy.service \
  deploy/ard-server.env deploy/ard-proxy.env deploy/operators.yaml \
  deploy/nftables.conf deploy/firewall-verify.sh \
  "$REMOTE:$STAGE/"
ok "uploaded to $STAGE"

# -------------------------------------------------------------- remote work
# Everything below runs in one remote shell so a partial failure cannot leave the
# gateway half-installed: the script is all-or-nothing by construction.
step "installing on the gateway"
ssh_ "bash -s" -- "$FIRST_DEVICE" "$ROTATE_DEVICE" <<'REMOTE'
set -euo pipefail
S=/root/ard-staging
FIRST_DEVICE="${1:-}"
ROTATE_DEVICE="${2:-}"
BINARIES=(ard-server ard-proxy ard-agent ard-ca)

echo "  -- installing binaries into /opt/ard/bin"
install -d -o root -g ard -m 0750 /opt/ard/bin /opt/ard/docs
install -d -o ard  -g ard  -m 0750 /var/lib/ard /var/log/ard
install -d -o root -g ard  -m 0750 /etc/ard
for b in "${BINARIES[@]}"; do
  install -m 0755 "$S/bin/$b" "/opt/ard/bin/$b"
done
# Root owns the binaries so the gateway user cannot replace its own code.
chown -R root:ard /opt/ard

echo "  -- PKI"
P=/etc/ard/pki
install -d -o root -g ard -m 0750 "$P"
if [[ -f "$P/server/server.crt" ]]; then
  echo "     existing PKI found; leaving it untouched"
else
  install -d -o root -g root -m 0750 "$P/server" "$P/devices" "$P/operators"
  SAN="<hostname>,localhost,127.0.0.1,$(hostname -I | awk '{print $1}')"
  "$ARD_BIN_DIR/ard-ca" init -dir "$P" -san "$SAN" >/dev/null 2>&1 \
    || /opt/ard/bin/ard-ca init -dir "$P" -san "$SAN" >/dev/null
  echo "     PKI created"
fi

# Ownership split. The gateway needs certificates and its own server key, and must
# never hold a CA key or a device key: with those it could mint identities, and a
# single compromised process would become authority over the whole fleet.
find "$P" -name 'ca.key' -exec chown root:root {} \; -exec chmod 0600 {} \;
[[ -d "$P/devices/leaves" ]] || install -d -o root -g root -m 0700 "$P/devices/leaves"
find "$P" -path '*/leaves/*' -name '*.key' -exec chown root:root {} \; -exec chmod 0600 {} \;
find "$P" -path '*/leaves/*' -name '*.crt' -exec chown root:ard {} \; -exec chmod 0640 {} \;
find "$P" -name '*.crt' -exec chown root:ard {} \; -exec chmod 0640 {} \;
chown root:ard "$P/server/server.key"; chmod 0640 "$P/server/server.key"
for d in "$P" "$P/server" "$P/devices" "$P/operators"; do
  chown root:ard "$d"; chmod 0750 "$d"
done

ENROLL=""
if [[ -n "$ROTATE_DEVICE" ]]; then
  ENROLL="$ROTATE_DEVICE"
  echo "     re-enrolling $ENROLL"
elif [[ -n "$FIRST_DEVICE" ]]; then
  ENROLL="$FIRST_DEVICE"
  echo "     enrolling $ENROLL"
fi
if [[ -n "$ENROLL" ]]; then
  /opt/ard/bin/ard-ca device -dir "$P" -id "$ENROLL" >/dev/null
  find "$P" -path '*/leaves/*' -name "$ENROLL.key" -exec chown root:root {} \; -exec chmod 0600 {} \;
  find "$P" -path '*/leaves/*' -name "$ENROLL.crt" -exec chown root:ard {} \; -exec chmod 0640 {} \;
fi

echo "  -- configuration"
if [[ -f /etc/ard/operators.yaml ]]; then
  install -m 0640 -o root -g ard "$S/operators.yaml" /etc/ard/operators.yaml.new
  # Preserve operator-defined roles across a deploy; only ship the template when
  # nothing exists yet. Overwriting a live policy from a deploy script would be a
  # good way to silently grant or revoke someone's access.
  mv /etc/ard/operators.yaml.new /etc/ard/operators.yaml.sample
  install -m 0640 -o root -g ard /etc/ard/operators.yaml /etc/ard/operators.yaml.bak
  cp /etc/ard/operators.yaml.bak /etc/ard/operators.yaml
else
  install -m 0640 -o root -g ard "$S/operators.yaml" /etc/ard/operators.yaml
fi
install -m 0640 -o root -g ard "$S/ard-proxy.env" /etc/ard/ard-proxy.env

# Build the server env from the template, substituting the device list.
if [[ -f /etc/ard/ard-server.env ]]; then
  grep -v '^ARD_DEVICES=' /etc/ard/ard-server.env > /etc/ard/ard-server.env.new
else
  grep -v '^ARD_DEVICES=' "$S/ard-server.env" > /etc/ard/ard-server.env.new
fi
# The device allowlist is preserved across deploys and only ever appended to.
#
# Resetting it would silently disconnect every enrolled device on a routine
# redeploy, and because loopback ports are assigned from this list's order, it
# would also renumber every operator's saved serial.
existing=""
if [[ -f /etc/ard/ard-server.env ]]; then
  existing="$(grep '^ARD_DEVICES=' /etc/ard/ard-server.env | cut -d= -f2- || true)"
fi
if [[ -n "$ENROLL" ]]; then
  if [[ -z "$existing" || "$existing" == "CHANGE-ME-device-uuid" ]]; then
    existing="$ENROLL"
  elif [[ ",$existing," != *",$ENROLL,"* ]]; then
    existing="$existing,$ENROLL"
  fi
fi
if [[ -z "$existing" ]]; then
  existing="CHANGE-ME-device-uuid"
  echo "     WARNING: no devices enrolled; pass --first-device <uuid>"
fi
printf 'ARD_DEVICES=%s\n' "$existing" >> /etc/ard/ard-server.env.new
install -m 0640 -o root -g ard /etc/ard/ard-server.env.new /etc/ard/ard-server.env
rm -f /etc/ard/ard-server.env.new

# Grants must reference a real device.
if [[ -n "$ENROLL" ]]; then
  sed -i "s/CHANGE-ME-device-uuid/$ENROLL/g" /etc/ard/operators.yaml
fi

echo "  -- firewall"
install -m 0644 -o root -g root "$S/nftables.conf" /etc/nftables.conf
nft -c -f /etc/nftables.conf
nft -f /etc/nftables.conf
systemctl enable nftables >/dev/null 2>&1 || true
install -m 0755 -o root -g root "$S/firewall-verify.sh" /usr/local/sbin/ard-firewall-verify
install -m 0644 -o root -g root /dev/null /etc/systemd/system/ard-firewall-verify.service
cat > /etc/systemd/system/ard-firewall-verify.service <<'UNIT'
[Unit]
Description=Assert the ARD firewall is enforcing deny-by-default
After=nftables.service
Before=ard-server.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/ard-firewall-verify

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable ard-firewall-verify.service >/dev/null 2>&1 || true

echo "  -- systemd units"
install -m 0644 -o root -g root "$S/ard-server.service" /etc/systemd/system/ard-server.service
install -m 0644 -o root -g root "$S/ard-proxy.service"  /etc/systemd/system/ard-proxy.service
systemctl daemon-reload

echo "  -- starting"
systemctl enable ard-server ard-proxy >/dev/null 2>&1
systemctl restart ard-server ard-proxy
REMOTE
ok "installed"

# ---------------------------------------------------------------- verify
step "verifying"
# Verification is explicit and each check is load-bearing. A deploy that reports
# success without these would report success on a gateway that serves nothing.
check() { printf '  %-46s %s\n' "$1" "$2"; }
fail_count=0
# Verification deliberately tolerates non-zero exits from the probed command.
#
# Several checks assert the ABSENCE of something, and the natural way to ask
# that (grep -c returning 0 matches) exits 1. Under `set -e` with pipefail that
# would abort the deploy on success, and the script would report a failure for a
# correctly configured host. A check must never be able to fake its own verdict.
verify() {
  local desc="$1" cmd="$2" want="$3"
  local got
  got="$(ssh_ "$cmd" 2>/dev/null | tr -d '\r' | tail -1 || true)"
  if [[ "$got" == *"$want"* ]]; then
    check "$desc" "$GREEN ok$OFF"
  else
    check "$desc" "$RED got '${got:-<empty>}'$OFF"
    fail_count=$((fail_count+1))
  fi
}

verify "ard-server running"        "systemctl is-active ard-server" "active"
verify "ard-proxy running"         "systemctl is-active ard-proxy" "active"
verify "firewall enforcing drop"   "nft list chain inet ard input | grep -o 'policy [a-z]*'" "policy drop"
verify "gateway ports in firewall" "nft list chain inet ard input | grep -c 'dport @ard_ports'" "1"
verify "no raw adb port exposed"   "nft list ruleset | grep -cE '5555|dport @adb'" "0"
verify "device listener bound"     "ss -tln | grep -c ':7000'" "1"
verify "operator listener bound"   "ss -tln | grep -c ':7100'" "1"
verify "control socket present"    "test -S /run/ard/control.sock && echo present" "present"
verify "no CA key readable by ard" "sudo -u ard test -r /etc/ard/pki/devices/ca.key 2>/dev/null && echo LEAKED || echo clean" "clean"
verify "audit log writable"        "test -w /var/log/ard && echo writable" "writable"

if [[ $fail_count -ne 0 ]]; then
  echo
  ssh_ "journalctl -u ard-server --no-pager -n 20" || true
  die "$fail_count verification check(s) failed"
fi
ok "all checks passed"

# --------------------------------------------------------------- summary
DEVICE_LINE="$(ssh_ "grep '^ARD_DEVICES=' /etc/ard/ard-server.env | cut -d= -f2-")"
cat <<SUMMARY

$GREEN gateway deployed$OFF
  host        ${ARD_PROD_USER:-root}@${ARD_PROD_HOST} ($(ssh_ hostname))
  devices     $DEVICE_LINE
  device port :7000    operators :7100
  adb serial  127.0.0.1:15000 for the first device, 15001 for the second, and so on

$YELLOW next$OFF
  1. Install the agent on the device (Termux on Android, no root needed):
       apk add go git   # or install the prebuilt binary
       ard-agent -gateway ${ARD_PROD_HOST}:7000 \\
                 -server-name $(ssh_ hostname) \\
                 -device <uuid> \\
                 -ca server-ca.crt -cert device.crt -key device.key
  2. Enrol it:  scripts/deploy.sh --rotate-device <uuid>
  3. On the gateway:  adb connect 127.0.0.1:15000 && adb shell

  Device credentials are on the gateway at
  /etc/ard/pki/devices/leaves/. Copy the .crt, .key and server/ca.crt to the
  device over a channel you trust; the private key must not travel in the clear
  over the internet.
SUMMARY