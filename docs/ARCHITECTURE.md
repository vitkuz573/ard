# ARD — Architecture

Remote ADB platform. Devices dial out to the gateway (they are unrouted, behind CGNAT).
Operators connect and drive those devices with the stock `adb` binary.

This describes the system as the code is today. Work that is deliberately not done is
in [Deferred](#6-deferred-additive-cannot-break-v1).

---

## 1. Non-negotiable security rules

These are structural, not features. They constrain every component.

1. **`adbd` is never deliberately exposed.** ADB has no authentication: one
   `adb connect` to an exposed `adbd` is full control of the phone (files, install,
   shell, screen). The agent runs on the device and reaches adbd over an address
   the device's own debugging settings opened — see the correction below. What
   ARD guarantees is that it never widens that exposure itself.

   > **Corrected against real hardware.** This document originally said the agent
   > reaches `127.0.0.1:5555` on the device's loopback. Measured on a mid-range
   > Android 14 handset: **nothing listens on 5555 at all.** `/proc/net/tcp6`
   > shows adbd bound only to the single port that wireless debugging or
   > `adb tcpip` opened, on an IPv6 wildcard. `ard-agent` therefore discovers
   > that port rather than assuming one, and the address is optional rather than
   > required, because a default that is wrong on every modern device fails in a
   > way that looks like a network problem.
   >
   > Worse, `adb tcpip 5557` binds adbd to `*`, i.e. every interface including the
   > mobile network. That was verified, not assumed: from a host on the same
   > mobile network the device's CGNAT address accepted a connection on that
   > port. **Prefer wireless debugging with pairing**, which binds to the WiFi
   > interface only and uses per-session tokens. Where `adb tcpip` is used, it is
   > a temporary exposure that a reboot clears.
2. **Enrolment is a mailbox, not a signing service.** A device with no certificate has
   nothing to verify the gateway with and nothing to present, so it cannot use the device
   listener at all. It therefore gets a third listener that completes a server-only TLS
   handshake, submits a CSR, and receives a short claim code. The gateway stores the
   request; it holds no CA key and cannot sign anything. `ard-ca enrol`, running wherever
   the CA lives, claims the request by code, prints it, signs locally and sends the
   certificate back, which the gateway delivers to the waiting device.

   The code is what makes the approval specific: without it, approving "device-7" would
   sign whatever request happened to be filed under that name, and anyone can file one.

   Signing is authorised on the control socket by peer uid 0, not by filesystem
   permissions alone. That socket is mode 0660 and group-owned by the gateway's own user,
   so permissions would otherwise let the gateway process itself hand out certificates --
   which is exactly the escalation this PKI layout exists to prevent.

   First contact is the awkward part, because a device with no CA certificate cannot
   verify anything. Rather than trusting the gateway blindly, the device reports the
   fingerprint of the certificate it was actually shown, and `ard-ca` compares it against
   the server root in the PKI. A machine-in-the-middle can complete the handshake,
   receive the CSR and look entirely convincing; it cannot produce a fingerprint that
   matches, so the attempt fails before a certificate exists.
3. **Device and operator trust are separate roots.** A stolen operator cert must
   not be able to enroll a device, and a stolen device must not reach any device
   other than itself.
4. **Every operator action is attributable.** Auth says *which human*, not *which
   certificate*. Audit is written before the action starts, not after.
5. **No implicit reachability.** Nothing is reachable because it exists. Devices are
   allowlisted by UUID before a session exists, and operator access to a device is a
   grant in the ACL — checked on every request, not once per connection. A forward
   target, when forwards exist, is its own permission.
6. **Devices are inert by default.** A device may only be routed to by an operator
   who holds a grant for that device.
7. **A completed TLS handshake is not an authorization decision.** Under TLS 1.3 the
   client finishes its side of the handshake *before* the server has verified the
   client certificate, which travels in the second flight. A rejected certificate
   surfaces later, as an alert on the first application read or write. So every
   client must complete one authenticated application exchange before acting, and
   must treat failure of that exchange as "not authorized" rather than retrying on
   a new connection. The gates for this are the device handshake
   (`HELLO` → `WELCOME`/`ERR`) and, on the operator leg, the lookup of the
   certificate's common name in the ACL policy — an operator with no role is
   refused before any device question is answered.

---

## 2. Components

```
 DEVICE (unrouted, dials out)      GATEWAY HOST                  OPERATOR'S OWN MACHINE
 ┌──────────────────────┐          ┌───────────────────────┐    ┌───────────────────────┐
 │ ard-agent            │ ①mTLS    │ ard-server            │mTLS│ ard-connect           │
 │  in the agent APK    │◄────────►│  PKI + device         │◄──►│  one published port   │
 │  device identity     │  yamux   │  allowlist            │    │  127.0.0.1:15000      │
 │  yamux client        │─────────►│  registry (by UUID)   │    │  splices each adb     │
 │  pipe ↔ adbd         │◄─②stream─┤  ACL + audit log      │    │  connection to here   │
 │                      │  kind=adb│  adb server protocol  │    │                       │
 └──────────────────────┘          │  enrolment mailbox    │    │ stock adb -P 15000    │
                                   └───────────────────────┘    └───────────────────────┘
```

The operator leg is one TCP port, and what runs on it is the stock `adb` binary.
`ard-connect` publishes a single local port (default `127.0.0.1:15000`); `adb -P` that
port speaks adb's own server protocol to the gateway over mutual TLS, and the gateway
answers the device-discovery and transport-switching requests itself. There is no
per-device port, no separate bridge process, and no device list to copy.

The gateway has three TCP listeners and one unix socket, and the split between them is
made by the certificate root each one trusts, not by application code:

| Listener | Trusts | Serves |
|---|---|---|
| `-listen-devices` `:7000` | device CA | agent sessions: handshake, allowlist, then a yamux session |
| `-listen-operators` `:7100` | operator CA | adb's server protocol, on behalf of one identified operator |
| `-listen-enrol` `:7200` | nothing — no client certificate is asked for | certificate requests only; a device has none until it is enrolled |
| `-control-socket` `/run/ard/control.sock` | filesystem permissions, plus peer uid 0 | `ard-ca` claiming and delivering certificates |

So a device certificate cannot complete a handshake on the operator listener and an
operator certificate cannot register as a device, and that holds even if a code path
forgets to check.

Four product binaries:

| Binary | Runs on | Purpose |
|---|---|---|
| `ard-agent` | device | outbound mTLS session, exposes the device's `adbd` |
| `ard-server` | gateway host | PKI, allowlist, registry, ACL, audit, yamux hub, adb server protocol |
| `ard-connect` | operator side | publishes one local port and splices adb connections to the gateway over mTLS |
| `ard-ca` | offline or the gateway host, as root | issues device and operator certificates |

Two more exist for testing and are not deployed: `cmd/mockadbd` speaks adbd's wire
protocol as a device simulator, and `cmd/probe` sits on one side of a connection to
inspect it.

---

## 3. The single primitive: a stream

Everything is one primitive. **A stream is an authenticated, audited, bidirectional
byte pipe from an operator session to one device.** Terminal, file transfer,
logcat and video are all just typed streams on top of it. No feature adds a new
transport, so adding a feature cannot break the security model.

Device-side stream kinds: `adb` — a raw pipe to that device's `adbd`, and today the
only kind the agent will serve. `ard-agent` refuses any other kind rather than
opening a stream it cannot honour.

The ACL maps each kind to the permission it requires, so a new kind cannot be added
without somebody deciding who may use it: `internal/acl.KindToPermission` maps `shell`,
`exec`, `files`, `logcat`, `screen`, `forward`, `reverse`, `raw-adb`, `adb` and
`operator-bridge` onto permissions, and a kind that is not in the map is refused rather
than allowed by default.

The kinds other than `adb` are named there and not yet served — there is no server-side
PTY and no separate file-transfer path. What the operator leg does today, per attach,
is two things that must not be confused:

- the authorization check is made with kind `operator-bridge`, which maps to the
  `shell` permission. One ADB connection carries shell, install, file transfer and
  forwarding together, so the gate cannot be anything narrower than `shell` without
  handing shell to a role that deliberately excluded it.
- the stream actually opened is of kind `adb`, because that is what the agent
  dispatches on. Passing the permission's name as the stream kind opens a stream
  nothing on the device handles: the connection is accepted and then nothing is ever
  read from it, and the shell request produces no output and no error.

---

## 4. Wire protocols

### 4.1 Device leg — agent → gateway

Mutual TLS 1.3, verified against the device CA and a server name the operator states
(`-server-name`, defaulting to the gateway host). Then:

```
agent   → gateway : "ARD/1 HELLO {"device":..,"name":..,"agent":..}\n"
gateway → agent   : "ARD/1 WELCOME {"session":..,"heartbeat":..}\n"
                    or "ARD/1 ERR <reason>\n"
then               : yamux (the gateway opens streams)
```

Server-initiated stream, header then raw bytes:

```
"ARD/1 ROUTE {"device":"<uuid>","kind":"adb","stream":"<id>","meta":{...}}\n"
<raw bytes, no framing, until EOF>
```

**Why the device leg is multiplexed and the device side is not.** yamux carries N
operator streams over *one* TLS connection per device. Inside it, each `adb`-kind
stream gets its own `adbd` connection, because the gateway already multiplexes: it
terminates ADB itself and normally needs one stream per device, so the agent would
have to build a second multiplexer to avoid it. See risk 2 in section 7 — that
concern was measured and resolved in the opposite direction from the original
assumption.

Streams travel one way only: the gateway opens them, in response to an operator. A
device that asks for one has its stream closed and the attempt recorded as
`device.stream_rejected`, because a device able to originate streams could invert the
model — the gateway opens what an operator asked for, nothing else.

### 4.2 Operator leg — operator → gateway

There is no ARD protocol on the operator leg. The gateway speaks **adb's own server
protocol** (`internal/adbserverproto`), on the same authenticated connection, after
mutual TLS has identified the operator:

```
ard-connect  -gateway gw:7100 ...   ← publishes 127.0.0.1:15000 and prints the port
adb         -P 15000 devices        ← asks which devices exist; the gateway answers
adb         -P 15000 -s <uuid> shell
```

`ard-connect` binds one local port and, for every connection adb opens to it, dials
the gateway and splices the two together — one TLS connection per adb connection,
because adb opens a fresh connection per request and expects each answered on that
connection. It checks the gateway's certificate role is `ard-server` (the gateway
presents its server certificate on every listener, including the operator one), and
it holds no device list: it cannot decide what an operator may reach, and a
client-side copy of that policy is one more copy to keep in step with the gateway's.

Each request is a four-hex-digit length followed by the service name, and the gateway
answers one request per connection, as a real adb server does:

| Request | Reply |
|---|---|
| `host:version` | `OKAY 0004 0029` — four characters and nothing else |
| `host:features` | `OKAY 0008 shell_v2` — only what the gateway can honour |
| `host:devices`, `host:devices-l` | the listing, filtered by ACL, `<serial>\t<device\|offline>` |
| `host-serial:<serial>:features` | the same feature list |
| `host-serial:<serial>:get-state` | `device` or `offline`, from the registry |
| `host:tport:serial:<serial>` | `OKAY` plus a 64-bit transport id, then the connection *is* the device transport |
| `host:transport:<serial>` | bare `OKAY`, then the same, raw |
| `host:connect:<addr>` | `FAIL` — opening a TCP device is not the gateway's business |
| anything else | `FAIL unknown host service '<name>'` |

Nothing is ever left unanswered: adb waits forever for a reply that does not come, so
an unknown service is a `FAIL` and never a silence.

Only `shell_v2` is advertised. With an empty or reduced feature list adb still runs
every command and still exits zero, but it stops upgrading the shell service — it
sends `shell:cmd` instead of `shell,v2,...`, never writes the close-stdin frame, and
never sends or reads an exit status. The two visible symptoms are `adb shell false`
reporting success and `adb shell cat` hanging forever, and neither of them points at
the transport.

**Where the transport becomes ADB.** After `host:tport` the gateway is not speaking
its own protocol any more: it performs the `CNXN`/`OPEN` exchange with the device on
the operator's behalf, acknowledges the client with a bare `OKAY`, and then relays
raw bytes both ways — device `WRTE` payloads to the client, the client's bytes wrapped
in `WRTE` for the device. The relay does not interpret the stream, so under shell v2
the framed stream and its exit status reach the client because nothing got in the way.

### 4.3 What the operator sees, and why it is not a local phone

`adb devices` against a local handset prints something like:

```
List of devices attached
emulator-5554          device
```

Against a gateway it prints the device **UUID**:

```
List of devices attached
3f2a9c14-6b7e-4d55-9a10-2c8e5b1d0f77   device
```

That is not a placeholder and it is not the phone's own serial. adb's protocol asks
for a device by serial, so something has to answer with a serial; the registry has no
separate adb serial to give, because the thing on the far end is not an `adbd` the
operator ever attached to — it is a gateway abstraction in front of a phone whose
`adbd` is reached over a tunnel. Inventing a second identifier and translating between
them would add a mapping that can disagree with the registry, so the UUID is handed
to adb outright: stable across reconnects, already what the ACL is written against,
and meaningful in an audit log.

The consequence is worth stating plainly: a gateway device has no adb serial of its
own, so `adb devices` will not look like a local phone. The alternative is a
fabricated serial that looks familiar and matches nothing.

An entitled device that is enrolled but not attached is listed as `offline` rather
than hidden. An operator who cannot see a device they are entitled to cannot tell
"not mine" from "not there", and a denial with no explanation is impossible to act
on.

---

## 5. Multi-tenancy

Each of these is expensive or impossible to retrofit cleanly, so they are structural
rather than features. This is what the code does today.

| Concern | Decision |
|---|---|
| Identity | The operator certificate's common name, taken from the TLS handshake and never from anything the client sends. `ard-connect` checks the gateway's role is `ard-server` before it speaks; the gateway checks the operator's role is `ard-operator` and then looks that name up in the policy. |
| Authorization | `operator → role → permissions`, and `grants` naming device UUIDs or a `prefix-*`. Two questions are asked separately: may this role open this kind of stream at all, and may it touch this device. Checked on every request, never cached on the socket. |
| Device enrollment | Device generates a keypair and submits a CSR to the mailbox; `ard-ca` signs it after a human approves a specific request. No pre-baked static certificates, and the gateway holds no CA key. |
| Device identity vs connection | A UUID survives reboot, reinstall and IP change. Registry keyed by UUID, not by socket. The certificate's common name and the UUID the agent claims must agree, or one stolen certificate would be authority over every device. |
| Audit | Append-only JSON file, written before the action is granted: operator, device, stream ID, source address, time. Every adb server protocol request is also logged by name, so "asked and was refused" is distinguishable from "never asked". |
| Concurrency | Multiple operators may hold streams to one device simultaneously. Streams are never shared between operators, so one operator cannot read another's terminal. |
| Isolation | Each operator's streams get separate yamux streams. A single operator session cannot address another session's streams. |
| Config | Flags, plus an env file and one YAML policy. dev / staging / prod differ by configuration, never by code. |

Device registry state is `online | draining | offline`. `draining` exists so existing
streams can be finished during a graceful disconnect instead of cut, and `Open`
refuses new streams in that state — but nothing calls `Drain` yet, so today a device
disconnect drops its streams rather than draining them.

A serial an operator's role does not cover is refused **by name**, not merely left out
of the listing: a client can ask for anything, so hiding it is not enough on its own.
The refusal is the same message the stock adb server uses for a device that does not
exist — a message that distinguished the two would tell an operator probing for serials
which of them exist.

---

## 6. Deferred (additive, cannot break v1)

- A web console. Nothing on the operator leg serves it today — the leg speaks adb's
  protocol — so it would need a second protocol and a second TLS policy to keep in step
  with the first.
- Screen streaming. `scrcpy-server` → H.264 → remux to fMP4 → MSE in the browser.
  Remux only, no decode. Highest-effort item.
- The stream kinds the ACL already names but nothing serves: `files`, `logcat`, `screen`,
  `forward`, `reverse`.
- `adb push` and `adb pull`. They need the current text-framed sync protocol, which
  `test/mockadbd` does not implement yet.
- Multi-factor auth, per-device grant expiry.
- Clustering more than one gateway node.

## 7. Open risks to spike before building on top

1. ~~Reaching `adbd` from the agent.~~ **Now resolved, and it changed the design.**
   On Android 11+ there is no loopback listener to reach. `internal/adbdloc`
   discovers the address by attempting connections — loopback first, then the
   device's own addresses, across the well-known ADB ports and then the dynamic
   range — because a normal app cannot read `/proc/net/tcp` and so cannot enumerate
   listeners. Onboarding must therefore enable wireless debugging (or
   `adb tcpip`) before the agent can run at all, and a reboot clears it — so the
   agent's startup probe is what tells an operator what to do.
2. ~~**Concurrent `adbd` connections.**~~ **Measured, and the opposite of what was
   assumed.** The gateway terminates ADB itself and normally needs a single stream per
   device, so the agent opens one connection per stream it is given. Per-stream dialing
   is therefore correct, not lazy. What the concern was really about is still worth
   bounding, so the agent caps concurrent dials at four and fails a stream that carries
   no bytes for five minutes instead of hanging. The inner framing layer `hs.Link` was
   **not** wired in: it is a standalone multiplexer that does not speak ADB, so placing
   it between the operator and adbd would mean reimplementing the multiplexing the
   adb protocol already provides. Dead code here is a rejected approach, not an
   unfinished one.
3. ~~**`adb connect 127.0.0.1:<port>`.**~~ **Obsolete.** There is no longer a per-device
   port for adb to connect to. `adb -P` talks to `ard-connect`'s single published port,
   and the gateway refuses `host:connect:` with a reason, since opening a TCP device is
   not its business.

## 7b. The device agent is an APK

The agent ships as `dev.ard.agent`, a single APK carrying the ARM64 Go binary
inside itself. Deployment is `adb install ard-agent.apk`; everything else is
discovered from the device.

Build without Gradle (`scripts/build-apk.sh`): aapt2, javac, d8, zipalign,
apksigner. No dependency resolution means a build that cannot break on a phone
with no network.

Four constraints found by testing on a real Android 14 phone, each of which
produced a failure that looked like something else:

1. **The agent must ship as a native library, not an asset.**
   `/data/user/<n>/<pkg>/files` is mounted `noexec`, so a binary extracted there
   dies with `error=13, Permission denied`. `nativeLibraryDir` is the one
   app-writable exec-mounted directory, because it is where the platform puts
   executables. Hence `lib/arm64-v8a/libardagent.so`; `execve` does not care
   about the suffix.
2. **A normal app cannot read `/proc/net/tcp`.** It sees only its own sockets, so
   any discovery method based on reading it always reports "not found". Discovery
   is done by attempting connections instead.
3. **Discovery must not run on the main thread.** Android throws
   `NetworkOnMainThreadException` before the first `connect()`, so a probe that
   ran synchronously from a button handler reported no adbd on a device that had
   one, and the error named a permissions problem that did not exist.
4. **`-ca` is a file path, not a directory.** It used to be a directory that was
   then passed through `filepath.Dir`, which looked one level too high and
   reported a missing file that was present.

The build script asserts the APK actually contains what the app reads at runtime:
`assets`/`lib` entry, uncompressed vs compressed as appropriate, ELF magic, and
`e_machine` for AArch64. It previously reported "APK ready" while shipping an APK
with no binary in it, and the failure only surfaced on a phone.

## 8. Repository layout

```
cmd/ard-agent      device agent, shipped inside the APK
cmd/ard-server     gateway: listeners, registry, ACL, audit, adb server protocol
cmd/ard-connect    operator-side client: one published port, mTLS per connection
cmd/ard-ca         certificate issuance and enrolment approval
cmd/mockadbd       adbd-protocol device simulator, for testing without hardware
cmd/probe          inspects one side of an adb protocol connection
internal/adbserverproto  the adb server protocol itself, and the host side of the exchange
internal/adbwire         ADB packet encoding: CNXN, OPEN, WRTE, CLSE
internal/registry        device registry keyed by UUID, presence, drain
internal/acl             roles, permissions, grants
internal/tlsx            CA and certificate issuance, and role checking
internal/transport       yamux session between one agent and the gateway
internal/hs              framing: handshake + ROUTE, plus an unused inner multiplexer
internal/enrol           the certificate-request mailbox
internal/adbdloc         discovering the address adbd listens on, on the device
internal/audit           append-only audit log
android/                 the agent APK
test/mockadbd            the mock's implementation and its tests
scripts/                 deploy, end-to-end runs, APK build, ssh and stop helpers
docs/ARCHITECTURE.md
```

There is no `test/e2e` package. The end-to-end paths are shell scripts that build the
binaries and drive the real `adb` binary: `scripts/e2e-local.sh`,
`scripts/e2e-enrol.sh` and `scripts/e2e-operator.sh`.

## 9. Phases

- **P1 — one operator, real ADB.** agent, server, CA, mockadbd, and the operator path.
  Risks 1-3 are settled; see section 7 for what the measurements said.
- **P2 — platform.** Roles and grants, audit, multi-operator, registry hardening.
- **P3 — the rest of adb.** push/pull, forward/reverse, install — all of it adb's own,
  once the mock speaks the protocols they need.
- **P4 — operator UI.** A web console: terminal, files, apps, logcat.
- **P5 — screen.** Video stream and input injection.