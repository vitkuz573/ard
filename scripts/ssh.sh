#!/usr/bin/env bash
# SSH/SCP wrapper for the ARD production gateway.
#
# Credentials are never passed on the command line and never stored in the
# repository: the password lives in ~/.ard-secrets/ and is only used for the
# initial key bootstrap. Everything here authenticates with a key.
#
# Usage:
#   scripts/ssh.sh 'uname -a'
#   scripts/ssh.sh -i scp-me-a-file:/tmp/x
set -euo pipefail

SECRETS="${ARD_SECRETS_DIR:-$HOME/.ard-secrets}"
ENV_FILE="$SECRETS/prod.env"
KEY="${ARD_SSH_KEY:-$HOME/.ssh/id_ed25519_ard}"
KNOWN_HOSTS="$SECRETS/known_hosts"

if [[ ! -r "$ENV_FILE" ]]; then
  echo "ssh: missing $ENV_FILE" >&2
  exit 1
fi
# shellcheck disable=SC1090
set -a; source "$ENV_FILE"; set +a

if [[ ! -f "$KNOWN_HOSTS" ]]; then
  echo "ssh: $KNOWN_HOSTS absent; refusing to connect (unknown host key is not acceptable)" >&2
  exit 1
fi

SSH_OPTS=(
  -i "$KEY"
  -o IdentitiesOnly=yes
  -o PasswordAuthentication=no
  -o StrictHostKeyChecking=yes
  -o UserKnownHostsFile="$KNOWN_HOSTS"
  -o ConnectTimeout=15
  -p "${ARD_PROD_SSH_PORT:-22}"
)
TARGET="${ARD_PROD_USER:-root}@${ARD_PROD_HOST:?ARD_PROD_HOST unset}"

exec ssh "${SSH_OPTS[@]}" "$TARGET" "$@"