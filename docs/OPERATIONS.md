# Gateway operations

Hardening and maintenance notes for an ARD gateway host.

This is a **template and a set of lessons**, not a record of any particular
deployment. The host-specific parts — address, hostname, sizes, versions — are
placeholders to be filled in locally, and are deliberately kept out of version
control: a repository that names a reachable gateway is a repository that gets
scanned. Keep the real values in your own provisioning notes or password
manager, not in a file the world can read.

## Baseline

Record this per host, locally:

| | |
|---|---|
| Provider VPS | `<address>` |
| Hostname | `<hostname>` |
| OS | Debian 13 (trixie) or newer |
| Resources | `<vCPU / RAM / disk>` |
| No Go toolchain | binaries are cross-compiled locally with `CGO_ENABLED=0` |
| No `/dev/kvm` | the emulator cannot run here; device testing happens on a dev host |

## Access

- **Key-based** for automation: an `~/.ssh/id_ed25519_ard` key, installed in
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

- Before a release upgrade, keep a copy of the suite definition, `/etc`, and the
  installed package set somewhere outside the host. Naming the exact filenames is
  deployment-specific; taking the backup is not.
- Release upgrades must be run detached (`setsid nohup`), never in a foreground
  SSH session: openssh and systemd are replaced mid-run, the connection dies, and
  a foreground dpkg would take a SIGHUP and leave package management inconsistent.
- `pkill -f <pattern>` over SSH will match and kill the shell running it, because
  sshd executes the command as `bash -c "<command>"` and the pattern is present in
  that command line. Kill by PID.
## ARD gateway services

Deployed with a single command: `scripts/deploy.sh`. It cross-compiles, uploads,
installs the PKI, configuration, firewall rules and systemd units, starts
everything, and then verifies the result rather than reporting success on faith.
Re-running it is safe: the PKI and the device allowlist are preserved, never
regenerated.

| Service | Purpose |
|---|---|
| `ard-server` | accepts device and operator connections, holds device sessions |
| `ard-proxy` | presents each device on a loopback port to the stock `adb` |
| `ard-firewall-verify` | asserts at boot that the firewall is really enforcing |

### Enrolling a device

```sh
sudo ard-ca enrol -code <CODE>
```

The device shows the code; this command shows the request it is about to sign -- device
id, request id, role and the SHA-256 of the CSR -- and asks for confirmation. `-yes`
skips the prompt for unattended use, which then shows up in the audit log as an approval
that did not pause.

Two things are refused rather than warned about, because both mean the approval covered
something other than what was signed:

- the CSR names a different device than the one it was submitted as
- the device reports a gateway certificate that is not the one this PKI signs for, which
  is what an interception attempt looks like

The CA key is root-only and `ard-ca enrol` needs it, so this runs as root over SSH. It is
the only signing path: the gateway holds no CA key and cannot issue anything.

Loopback ports are assigned from the order of `ARD_DEVICES` in
`/etc/ard/ard-server.env`, so **treat that list as append-only**: reordering it
changes every operator's saved `adb` serial.

### PKI permissions on the gateway

The gateway runs as `ard` and holds certificates plus its own `server.key`. It
must never hold a CA private key or a device private key, because either would let
a single compromised process mint identities. `tlsx.LoadVerifier` reads `ca.crt`
and never opens `ca.key`, so this is enforced by the type system rather than by
remembering not to use the key. The deploy verifies the gateway user genuinely
cannot read those files.

Posture to verify on every host after deploy:

    systemd-analyze security ard-server.service   ->  1.3 OK
    gateway can read devices/ca.key               ->  no
    gateway can read a device private key         ->  no
    gateway can replace its own binaries          ->  no

### Two deploy bugs that the verifier caught

Worth remembering, because both produced a "successful" deploy of something broken:

- The firewall file shipped from the repository lacked the gateway ports, so a
  deploy replaced a working ruleset with one that blocked them. The deploy now
  checks that the ports are present *and* that no raw ADB port is exposed.
- Verification used `grep -c` to assert the absence of something, which exits 1 on
  zero matches. Under `set -e` with `pipefail` that aborted a correct deploy. A
  check must never be able to fake its own verdict.
