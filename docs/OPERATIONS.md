# Gateway host: `<hostname>`

Provisioning record for the production gateway. Kept in the repository so the
host's state is described somewhere other than in a chat log.

## Baseline

| | |
|---|---|
| Provider VPS | `<gateway-address>` (IPv6 `<ipv6-address>`) |
| Hostname | `<hostname>` |
| OS | Debian 13 (trixie), userspace 13.7 |
| Kernel | `6.12.111+deb13-cloud-amd64` |
| Resources | 2 vCPU, 3.9 GiB RAM, 40 GB disk |
| OpenSSH | 10.0p2 |
| No Go toolchain | binaries are cross-compiled locally with `CGO_ENABLED=0` |
| No `/dev/kvm` | the emulator cannot run here; device testing happens on the dev host |

## Access

- **Key-based** for automation: `~/.ssh/id_ed25519_ard`, installed in
  `/root/.ssh/authorized_keys`. Use `scripts/ssh.sh` — it refuses to run if the
  host key is unknown, so it cannot silently connect to a substituted host.
- **Password authentication stays enabled** by explicit operator request, because
  the operator's egress IP changes (mobile hotspot) and they connect from several
  devices. Do not add a source-IP restriction to port 22; it would cause an
  unrecoverable lockout. `MaxAuthTries 3`, `LoginGraceTime 30` and fail2ban are
  what make that acceptable.
- Secrets live in `~/.ard-secrets/` (mode 700), outside the repository. The
  repository `.gitignore` also excludes `*.key`, `*.crt` and `pki/` as a second
  line of defence.

## Firewall

`/etc/nftables.conf`, loaded by `nftables.service`. Default-deny `input`, and
`forward` is dropped outright — nothing on this host routes.

Only TCP 22 is accepted. ICMP is accepted deliberately: without path MTU discovery
the symptom is a hung TLS handshake rather than a routing error.

`destroy table inet ard` replaces the table instead of `flush ruleset`, so
reloading never deletes the table fail2ban uses for its active bans. `destroy`
requires nft >= 1.0.9; Debian 13 ships 1.1.3.

`ard-firewall-verify.service` asserts at every boot that the `input` chain is
actually `policy drop`, ordered `After=nftables.service` and
`Before=ard-server.service`. A gateway that silently lost its ruleset would be
indistinguishable from an open one — no log line, no alarm, every device and
operator port reachable. This turns that into a visible failure.

> Incident worth remembering: an earlier drop-in added `After=fail2ban.service`
> to `nftables.service` while fail2ban's own unit already had
> `After=nftables.service`. systemd dropped the `nftables` job to break the
> ordering cycle, and the firewall silently did not come up after a reboot while
> still reporting `enabled`. Ordering constraints must not be added in both
> directions.

## Other services

- `fail2ban` — sshd jail, 5 attempts / 10 min / 1 h ban, `nftables-multiport`.
  Requires `python3-systemd`; without it the jail fails to pick a backend and
  exits 255 with no obvious error. Set `loglevel = DEBUG` to a file in
  `/etc/fail2ban/fail2ban.local` when it misbehaves.
- `unattended-upgrades` — security updates.
- `ard` system user (uid 999, nologin) — the gateway runs unprivileged.
  `/opt/ard/bin` is root-owned and group-readable by `ard`, so a compromised
  gateway process cannot replace its own binaries.
- sysctl: `nf_conntrack_max=131072`, `somaxconn=4096`, `syn_backlog=4096`,
  `ip_local_port_range=10240 65000`, `file-max=262144` — a relay fans many
  operator streams onto one connection per device.

## Maintenance notes

- `/etc/apt/sources.list.d/debian.sources.bookworm-backup` holds the pre-upgrade
  suite definition, and `/root/pre-trixie-etc.tar.gz` plus
  `/root/pre-trixie-selections.txt` hold the pre-upgrade `/etc` and package set.
- Release upgrades must be run detached (`setsid nohup`), never in a foreground
  SSH session: openssh and systemd are replaced mid-run, the connection dies, and
  a foreground dpkg would take a SIGHUP and leave package management inconsistent.
- `pkill -f <pattern>` over SSH will match and kill the shell running it, because
  sshd executes the command as `bash -c "<command>"` and the pattern is present in
  that command line. Kill by PID.