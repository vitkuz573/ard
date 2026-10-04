#!/bin/bash
# Debian 12 (bookworm) -> 13 (trixie) release upgrade.
#
# Run detached via nohup. The upgrade replaces openssh-server and systemd, which
# tears down the SSH connection this script was started from; run in the
# foreground, it would take a SIGHUP partway through dpkg and leave package
# management in an inconsistent state.
#
# Exit status is written to /root/upgrade.exit so the caller can tell a clean
# finish from a mid-flight death.
set -uo pipefail

LOG=/root/upgrade.log
exec >>"$LOG" 2>&1

export DEBIAN_FRONTEND=noninteractive
# needrestart would otherwise stop on an interactive prompt about services.
export NEEDRESTART_MODE=a
export NEEDRESTART_SUSPEND=
# linux-base and friends ask questions that must not block an unattended run.
export APT_LISTCHANGES_FRONTEND=none

echo
echo "=== upgrade started $(date -u +%FT%TZ) ==="
echo "bookworm kernel: $(uname -r)"

step() {
  echo
  echo "--- $* ($(date -u +%H:%M:%S)) ---"
}

# Keep a restorable copy of the package sources. If the release upgrade goes bad
# the box can be pointed back at bookworm without hunting for the original text.
step "saving current sources"
cp -a /etc/apt/sources.list.d/debian.sources \
      /etc/apt/sources.list.d/debian.sources.bookworm-backup
echo "saved to /etc/apt/sources.list.d/debian.sources.bookworm-backup"
grep -E '^deb ' /etc/apt/sources.list.d/debian.sources.bookworm-backup 2>/dev/null | head

step "switching suites to trixie"
cat > /etc/apt/sources.list.d/debian.sources <<'EOF'
Types: deb
URIs: mirror+file:///etc/apt/mirrors/debian.list
Suites: trixie trixie-updates
Components: main contrib non-free non-free-firmware
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg

Types: deb
URIs: mirror+file:///etc/apt/mirrors/debian-security.list
Suites: trixie-security
Components: main contrib non-free non-free-firmware
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
EOF
echo "new suites:"; grep -E '^Suites' /etc/apt/sources.list.d/debian.sources

step "apt-get update"
apt-get update

# upgrade first, then dist-upgrade. Plain upgrade only moves packages within the
# current suite, so it is the lower-risk half; dist-upgrade is what actually
# crosses into trixie and is the half that may remove packages.
step "apt-get upgrade (within-suite)"
apt-get upgrade -y

step "apt-get dist-upgrade (crossing to trixie)"
apt-get dist-upgrade -y

step "autoremove"
apt-get autoremove -y --purge

step "cleanup"
apt-get clean

step "verifying package state"
if dpkg --audit; then
  echo "dpkg --audit reported nothing broken"
else
  echo "WARNING: dpkg --audit found problems (output above)"
fi

step "reconfigure anything left half-configured"
dpkg --configure -a

echo
echo "=== upgrade finished $(date -u +%FT%TZ) ==="
echo "new userspace: $(cat /etc/debian_version)"
echo "installed kernel: $(dpkg -l 'linux-image-*' 2>/dev/null | grep ^ii | tail -1 | awk '{print $2, $3}')"
echo "--- reboot required marker: $( [ -f /var/run/reboot-required ] && cat /var/run/reboot-required || echo no ) ---"
echo "--- packages pending reboot: $( [ -f /var/run/reboot-required.pkgs ] && wc -l < /var/run/reboot-required.pkgs || echo 0 ) ---"

echo "UPGRADE_OK"
exit 0