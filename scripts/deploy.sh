#!/usr/bin/env bash
# Build ARD binaries for the gateway and deploy them.
#
# The gateway has no Go toolchain, so everything is cross-compiled here with
# CGO disabled: the result is a static binary that needs no runtime libraries.
#
# Usage:
#   scripts/deploy.sh                 # build + deploy + restart
#   scripts/deploy.sh --build-only
#   scripts/deploy.sh --no-restart
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SECRETS="${ARD_SECRETS_DIR:-$HOME/.ard-secrets}"
ENV_FILE="$SECRETS/prod.env"
KEY="${ARD_SSH_KEY:-$HOME/.ssh/id_ed25519_ard}"
KNOWN_HOSTS="$SECRETS/known_hosts"

REMOTE_USER="${ARD_PROD_USER:-root}"
REMOTE_DIR="${ARD_REMOTE_DIR:-/opt/ard}"
GOOS_TARGET="linux/amd64"

BUILD_ONLY=0
DO_RESTART=1
for arg in "$@"; do
  case "$arg" in
    --build-only) BUILD_ONLY=1 ;;
    --no-restart) DO_RESTART=0 ;;
    *) echo "deploy: unknown flag $arg" >&2; exit 2 ;;
  esac
done

cd "$ROOT"

BINARIES=(ard-server ard-proxy ard-agent ard-tap ard-ca)
DIST="$ROOT/dist/$GOOS_TARGET"
mkdir -p "$DIST"

echo "==> building for $GOOS_TARGET"
for b in "${BINARIES[@]}"; do
  if [[ ! -d "cmd/$b" ]]; then
    continue
  fi
  CGO_ENABLED=0 GOOS="${GOOS_TARGET%/*}" GOARCH="${GOOS_TARGET#*/}" \
    go build -trimpath -ldflags "-s -w" -o "$DIST/$b" "./cmd/$b"
  echo "    $b $(stat -c%s "$DIST/$b") bytes"
done

if [[ $BUILD_ONLY -eq 1 ]]; then
  echo "==> build only, nothing deployed"
  exit 0
fi

# shellcheck disable=SC1090
set -a; source "$ENV_FILE"; set +a
TARGET="${REMOTE_USER}@${ARD_PROD_HOST:?ARD_PROD_HOST unset}"
SSH_OPTS=(-i "$KEY" -o IdentitiesOnly=yes -o PasswordAuthentication=no
          -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$KNOWN_HOSTS"
          -o ConnectTimeout=15 -p "${ARD_PROD_SSH_PORT:-22}")

echo "==> uploading to ${TARGET}:${REMOTE_DIR}"
ssh "${SSH_OPTS[@]}" "$TARGET" "install -d -m 755 '$REMOTE_DIR/bin'"

TO_SEND=()
for b in "${BINARIES[@]}"; do
  [[ -f "$DIST/$b" ]] && TO_SEND+=("$DIST/$b")
done
scp "${SSH_OPTS[@]}" "${TO_SEND[@]}" "$TARGET:$REMOTE_DIR/bin/"

echo "==> installing"
ssh "${SSH_OPTS[@]}" "$TARGET" "
  set -e
  chmod 755 $REMOTE_DIR/bin/*
  chown -R $REMOTE_USER:$REMOTE_USER $REMOTE_DIR
  if command -v systemctl >/dev/null && [ -f $REMOTE_DIR/ard-server.service ]; then
    install -m 644 $REMOTE_DIR/ard-server.service /etc/systemd/system/ard-server.service
    systemctl daemon-reload
  fi
"

if [[ $DO_RESTART -eq 1 ]]; then
  echo "==> restarting ard-server"
  ssh "${SSH_OPTS[@]}" "$TARGET" "
    systemctl is-active --quiet ard-server \
      && systemctl restart ard-server \
      || echo 'ard-server not installed as a unit yet, skipping restart'
    systemctl --no-pager --lines=15 status ard-server 2>&1 | head -20 || true
  "
fi

echo "==> done"