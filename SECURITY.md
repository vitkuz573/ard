# Security policy

## Reporting a vulnerability

**Do not open a public issue.** Use GitHub's private reporting: *Security →
Report a vulnerability* on this repository. That opens a private thread visible
only to the maintainer.

If private reporting is unavailable to you, open a public issue that says only
that you want to report a vulnerability privately and ask for a contact method.
Do not include the details, the proof of concept, or the affected file.

Please do not test against infrastructure you do not own. There is a published
gateway for this project, and it is somebody's paid VPS.

## Never put these in an issue, a PR, or a log paste

This project's failure modes are quiet, so logs get pasted, and logs are where
key material turns up.

- Device or operator **private keys**, and `ca.key` above all
- Certificate files, unless they are a throwaway `ard-ca`-generated test
  identity from a local PKI you just deleted
- Real gateway addresses, hostnames, IPv6 addresses or device serials
- Anything under `~/.ard-secrets/`

If you paste a log that contains key material, say so in the same thread and
rotate the key. A deleted message is not a rotated key; the forge copy may exist
already, and this project's own git history is a standing reminder that
deleting is not the same as removing.

## What the design defends against

Stated so a report can be judged rather than triaged by intuition.

- **A stolen operator certificate** must not let its holder reach devices, or
  enrol new ones. Operator and device trust are separate roots, and a
  cross-role TLS handshake is refused at the listener.
- **A stolen device certificate** must not let its holder connect as an operator.
  Same mechanism, opposite direction.
- **A compromised gateway process** must not be able to mint identities. The
  gateway holds `ca.crt` and never `ca.key`; this is enforced by the type
  system, not by discipline. Certificate enrolment preserves this: the gateway
  stores certificate requests and delivers signed certificates, and signing
  happens in `ard-ca` on the operator's side. Because the control socket is mode
  0660 and group-owned by the gateway's own user, enrolment operations there
  additionally require peer uid 0 -- otherwise the gateway could issue
  certificates to itself.
- **A device behind carrier-grade NAT** is reachable only by dialling out.
  There is no inbound path to add, so there is nothing to forward.

## What the design does not defend against

Stated because a security tool that overstates itself is worse than none.

- **A compromised phone.** The agent runs as an ordinary app. Whatever can run
  code as the app can read its files, including its own private key.
- **A malicious operator.** Anyone holding an operator certificate has real `adb`
  access to the devices their role grants. That is the product: `ard-connect`
  bridges a raw ADB connection, and one ADB connection carries shell, install,
  file transfer and port forwarding together. So the bridge requires the `shell`
  permission specifically, and holding `shell` on a device means holding adb on
  that device. Roles control *which devices* and *what class of access*; they do
  not sandbox `shell` once granted.
- **A permission model finer than one connection can carry.** The policy has eight
  permissions and only one of them decides anything on the operator leg. A role that
  holds `logcat` but not `shell` sees the device in `adb devices` and is refused a
  transport with the reason on its own terminal; a role that holds `shell` gets shell,
  install, file transfer and forwarding, because ADB multiplexes them over one TCP
  connection. `forward` and `reverse` are named in the policy vocabulary and are not
  consulted on their own: both requests arrive on a switched transport, whose gate is
  `shell`. What the permissions buy is which *devices* a role may drive, not a finer
  cut within one.
- **A hostile network** during first contact. A device enrolling has no CA
  certificate, so it cannot verify the gateway at all: the connection that carries
  its certificate request is not authenticated. It reports the fingerprint of the
  certificate it was shown, and `ard-ca` compares it against the PKI before
  signing, so an interception attempt fails before a certificate exists. After
  enrolment the device verifies the gateway normally. Between those two points the
  only thing standing between a device and a machine-in-the-middle is the operator
  noticing a mismatch.
- **A hostile network**, in the sense of an attacker who can intercept and
  terminate TLS. Mutual TLS with private keys that never leave their host is the
  boundary; there is no pinning of the server's *name*, only of its role.
- **Traffic analysis and volume.** Every operator stream is multiplexed over the
  one connection the device made. That hides ADB's structure, not its existence.

## Known platform constraint

Android blocks network access for an app in the `APP_STANDBY` bucket, and a phone that is
not charging makes that the default for anything not in the foreground. The agent is a
long-lived outbound client, so the app holds a foreground service for as long as it is
running; the operator must press **Start** rather than running the binary by hand.

The failure mode is a dial timeout. Nothing mentions standby, so it reads as a network
problem or a broken gateway, and it disappears when the phone is plugged in — which makes
it look intermittent. Worth knowing before spending time on the gateway.

## Known exposure created by ADB itself

`adb tcpip <port>` binds adbd to **every** interface, including the mobile
network. A device that has had it run is reachable from the internet by anyone
who guesses the port, until it reboots. This was measured, not assumed.

**Prefer wireless debugging with pairing**: it binds to the WiFi interface only
and uses per-session tokens. If `adb tcpip` was used, treat it as temporary and
reboot the device when finished.

ARD does not open this socket and cannot close it — it belongs to the platform.
This is also why the agent cannot survive a reboot on its own: after a reboot
adbd listens on nothing until a human attaches USB or enables wireless
debugging. The agent finds the address whenever one exists rather than assuming
one.

## Supported versions

Only the current `main`. This is pre-1.0 software with no release tags, so there
is nothing to keep patched retroactively.