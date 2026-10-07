# ARD — Architecture

Remote ADB platform. Devices dial out to the gateway (they are unrouted, behind CGNAT).
Operators connect and drive those devices with the stock `adb` binary.

This describes the system as the code is today: shell, push, pull, forward and
reverse all work through the operator path. Work that is deliberately not done is in
[Deferred](#6-deferred-additive-cannot-break-v1).

---

## 1. Non-negotiable security rules

These are structural, not features. They constrain every component.

1. **`adbd` is never deliberately exposed.** ADB has no authentication: one
   `adb connect` to an exposed `adbd` is full control of the phone (files, install,
   shell, screen). The agent runs on the device and reaches adbd over an address
   the device's own debugging settings opened — see the measurement below. What
   ARD guarantees is that it never widens that exposure itself.

   > **Measured on a mid-range Android 14 handset.** **Nothing listens on 5555 at
   > all.** `/proc/net/tcp6` shows adbd bound only to the single port that
   > wireless debugging or `adb tcpip` opened, on an IPv6 wildcard. `ard-agent`
   > therefore discovers that port rather than assuming one, and the address is
   > optional rather than required, because a default that is wrong on every modern
   > device fails in a way that looks like a network problem.
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
   grant in the ACL — checked on every request, not once per connection, against the kind
   of stream the request actually carries rather than against the transport it arrived
   on. Forwarding adds no reachability of its own: `adb forward` binds the gateway's
   loopback and `adb reverse` reaches the gateway's loopback, so both are reachable
   only from the gateway host, and both name a service of their own.
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
answers the device-discovery, transport-switching and port-forwarding requests itself.
The operator learns nothing about devices from the transport and needs no serials in
advance.

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
| `ard-server` | gateway host | PKI, allowlist, registry, ACL, audit, yamux hub, adb server protocol, port forwards |
| `ard-connect` | operator side | publishes one local port and splices adb connections to the gateway over mTLS |
| `ard-ca` | offline or the gateway host, as root | issues device and operator certificates |

Two more exist for testing and are not deployed: `cmd/mockadbd` speaks adbd's wire
protocol as a device simulator, and `cmd/probe` sits on one side of a connection to
inspect it.

---

## 3. The single primitive: a stream

Everything is one primitive. **A stream is an authenticated, audited, bidirectional
byte pipe from an operator session to one device.** Shell, file transfer, video and
anything else an operator runs are typed streams on top of it. No feature adds a new
transport, so adding a feature cannot break the security model.

Two kinds open a stream: `adb`, a raw pipe to that device's `adbd`, and `device-open`,
a stream the device opened for itself (section 4.4). Every name in `hs` has code that
opens it, and `ard-agent` refuses any kind it does not have a route for rather than
opening a stream it cannot honour.

**A stream kind and a stream permission are different questions.** The kind is what the
agent dispatches on, so it says what the gateway asks the device for. The permission is
what the operator's role may do. A kind that reached the device as the permission's own
name would open a stream nothing on the device handles: the connection is accepted and
then nothing is ever read from it, and the shell request produces no output and no
error. So an attach is authorized with kind `operator-bridge` — which maps to `shell`,
because one ADB connection carries shell, install, file transfer and forwarding
together — and the stream opened is of kind `adb`.

What each request needs is decided from the service name the client's adb sends on the
transport it just switched onto, because that name is the only thing that says what the
request is for: everything after it is a command line or a socket specification, and the
gateway relays it without reading it. `internal/acl.KindForService` turns that name into
a kind and `KindToPermission` turns the kind into the permission it requires, so a new
service cannot ship without somebody deciding who may use it — a service with no
classified kind is refused rather than allowed by default.

The measured service names and the kinds they mean are listed at
`internal/acl.KindForService`. What that measurement settles about the vocabulary: there
is no permission for the device log or for the screen. `adb logcat` sends the shell
service with a command line attached, and `adb shell screenrecord` and `adb shell
screencap` arrive the same way, so both are governed by `shell` — the identical bytes
reach the device through `adb shell logcat`, and a permission separating them would
separate nothing. A check can only be made on a name.

No stream of kind `forward` or `reverse` is ever opened, because forwarding needs no
kind of its own: the gateway holds the ports and the device holds the device-side
listener, so both halves are answered on a transport already open under kind `adb`.

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
have to build a second multiplexer to avoid it. See entry 2 in section 7.

One device-initiated stream kind is served, and only one: `device-open`, a device
naming a socket specification it needs a connection to — which is how the callback half
of a reverse forward arrives (section 4.4). The agent relays the name as route metadata
and the gateway dials it on its own loopback. Every other device-initiated stream is
closed and the attempt recorded as `device.stream_rejected`, because a device able to
originate arbitrary streams could reach any operator's device: what the gateway opens
for a device is what an operator asked for, and the one exception names a port on the
gateway rather than a device.

### 4.2 Operator leg — operator → gateway

There is no ARD protocol on the operator leg. The gateway speaks **adb's own server
protocol** (`internal/adbserverproto`), on the same authenticated connection, after
mutual TLS has identified the operator:

```
ard-connect  -gateway gw:7100 ...   ← publishes 127.0.0.1:15000 and prints the port
adb         -P 15000 devices        ← asks which devices exist; the gateway answers
adb         -P 15000 -s <uuid> shell
adb         -P 15000 -s <uuid> push local.txt /data/local/tmp/
adb         -P 15000 -s <uuid> forward tcp:9930 tcp:9931
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
| `host:features` | the one visible device's own feature list, verbatim; `FAIL no devices/emulators found` with none, `FAIL more than one device/emulator` with several |
| `host:devices`, `host:devices-l` | the listing, filtered by ACL, `<serial>\t<device\|offline>` |
| `host-serial:<serial>:features` | that device's own feature list, verbatim |
| `host-serial:<serial>:get-state` | `device` or `offline`, from the registry |
| `host:list-forward`, `host:list-forward-all` | every bound forward, one `<serial> <local> <remote>\n` line each |
| `host-serial:<serial>:list-forward` | the same, for that device only |
| `host:tport:serial:<serial>` | `OKAY` plus a 64-bit transport id, then the connection *is* the device transport |
| `host:transport:<serial>` | bare `OKAY`, then the same, raw |
| `host:connect:<addr>` | `FAIL adb connect is not supported by this gateway` |
| anything else | `FAIL unknown host service '<name>'` |

Nothing is ever left unanswered: adb waits forever for a reply that does not come, so
an unknown service is a `FAIL` and never a silence.

**The feature list is the device's, not the gateway's.** The agent reads it out of the
device's own `CNXN` banner at session start and puts it in the registry, and the
protocol hands it to adb unchanged, because adb chooses the spelling of every command
it sends from that list: a list rebuilt here could differ from the device's in a way
nothing reports until a command takes a path because of it. The same applies to sync:
a device that advertises `sendrecv_v2_brotli` gets a compressed push, and a device that
advertises none gets an uncompressed one, and the gateway's relay carries either
because it never looks inside a sync frame.

The two refusals are the stock server's, measured: a union of several devices' lists
would be a list none of them has, so the question is answered per device instead, and
`host:features` refuses rather than guessing which one adb meant.

`shell_v2` in that list is what makes the exit status and the stdin close reach adb at
all. Without it adb sends `shell:cmd` instead of `shell,v2,...`, never writes the
close-stdin frame and never sends or reads a status, so `adb shell false` reports
success and `adb shell cat` hangs — neither symptom points at the transport, which is
why the list is passed through rather than trimmed to what the gateway is sure of.

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

### 4.4 File transfer and port forwarding

Both of these are adb's own protocols, and the gateway is the adb server on both ends
of them, so nothing here is a feature ARD adds — it is a statement of which half
lands where.

**`adb push` / `adb pull` travel as the device's `sync:` service**, on a stream of kind
`adb`, exactly as `shell:` does. The relay never looks inside a sync frame: it is
`STAT`/`LIST`/`SEND`/`RECV`, their `STA2`/`LIS2`/`SND2`/`RCV2` counterparts, `DATA`,
`DONE` and `OKAY`/`FAIL` bytes, and they reach the device intact in both spellings.
Which spelling adb uses is chosen per device from that device's feature list, so a
device advertising the v2 features gets the v2 forms and one advertising none gets the
v1 forms, and both are the same path as far as the gateway is concerned.

One number on this path is worth stating because the two are easy to confuse: the
window the gateway offers in its own `CNXN` is 4096, and the largest device packet it
will read is 65536. A stock adbd puts a whole 64 KiB sync `DATA` frame in one packet,
and a relay that read only what it advertised would truncate the pull of every file
larger than one frame while reporting nothing.

**`adb forward` and `adb reverse` are not the device's to answer**, and that is the
whole reason they are here. The "host" in a forward or a reverse is the machine
running the adb server, which is this gateway:

- `adb forward tcp:LOCAL tcp:REMOTE` — the gateway binds `LOCAL` and, for each
  connection to it, opens a stream to the device asking for `tcp:REMOTE`. The device's
  entire part is that service: connect to a port on its own loopback and splice.
- `adb reverse tcp:REMOTE tcp:LOCAL` — the device binds `REMOTE` on its own loopback
  and, for each connection to it, opens a stream back asking for `tcp:LOCAL`. The
  gateway answers that with a connection to a port on its own loopback.

Both halves therefore live in this gateway, and both reach only its loopback: `LOCAL`
is bound on `127.0.0.1` and the reverse's callback target is dialled on `127.0.0.1`,
so neither direction names a host anywhere. A socket specification is `tcp:` with a
numeric port and nothing else, because the side that chose the name would otherwise
choose where the connection lands.

Two consequences an operator should know:

- **A forward outlives the connection that asked for it.** adb closes that connection
  as soon as the request is answered, so the listener is held by the gateway and
  recorded with the operator who bound it, at binding time. It is released by
  `adb forward --remove` / `--remove-all`, not by quitting.
- **`adb reverse` keeps the device transport.** The device's listener lives on the
  transport it was created on, so that transport is handed to a loop that serves the
  device's own streams for as long as the device holds it.

Both services are refused by name rather than left unanswered when no forward set
exists, because a client that asked for a port and got silence would wait.

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
| Audit | Append-only JSON file, written before the action is granted: operator, device, stream ID, source address, time. Every adb server protocol request is also logged by name, so "asked and was refused" is distinguishable from "never asked". A port an operator binds is recorded with the operator who bound it, because the listener outlives the connection that asked for it. |
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

Everything on this list is genuinely absent. Anything adb can already do over one
switched transport — shell, push, pull, forward, reverse, install — is not on it,
because those are adb's own protocols and the gateway is the adb server on both ends
of them (sections 4.2 and 4.4).

- A web console. Nothing on the operator leg serves it — the leg speaks adb's
  protocol — so it would need a second protocol and a second TLS policy to keep in step
  with the first.
- Screen streaming. `scrcpy-server` → H.264 → remux to fMP4 → MSE in the browser.
  Remux only, no decode. Highest-effort item.
- A permission finer than ADB's own names. `adb logcat` and the screen services arrive
  as the shell service with a command line attached, so there is no name to check a
  narrower permission on. A cut below `shell` would be a fiction the policy file could
  express and the wire could not enforce.
- Multi-factor auth, per-device grant expiry.
- Clustering more than one gateway node.

## 7. Open risks to spike before building on top

Both entries here were spikes, and both are now answered by measurement. They are kept
because the answers constrain the design rather than because they are open.

1. **Reaching `adbd` from the agent — measured, and it changed the design.** On
   Android 11+ there is no loopback listener to reach. `internal/adbdloc` discovers the
   address by attempting connections — loopback first, then the device's own addresses,
   across the well-known ADB ports and then the dynamic range — because a normal app
   cannot read `/proc/net/tcp` and so cannot enumerate listeners. Onboarding must
   therefore enable wireless debugging (or `adb tcpip`) before the agent can run at all,
   and a reboot clears it, so the agent's startup probe is what tells an operator what
   to do rather than a dial timeout that looks like a network fault.
2. **Concurrent `adbd` connections — measured, and per-stream dialing is right.** The
   gateway terminates ADB itself and normally needs a single stream per device, so the
   agent opens one connection per stream it is given. The case that is not "normally
   one" is still worth bounding, so the agent caps concurrent dials at four and fails a
   stream that carries no bytes for five minutes instead of hanging. The inner framing
   layer `hs.Link` is a standalone multiplexer that does not speak ADB; placing it
   between the operator and adbd would mean reimplementing the multiplexing the adb
   protocol already provides, so it is a rejected approach rather than an unfinished one.

What is left of the original "the rest of adb" is therefore not protocol work. `install`
is `abb_exec:` on the same raw transport as everything else and is expected to work for
the same reason, and it is not covered by the operator test because `test/mockadbd`
does not implement it — that is a simulator gap, not a gateway gap.

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
4. **`-ca` is a file path, not a directory.** A directory passed through
   `filepath.Dir` looks one level too high and reports a missing file that is
   present, so the flag names the certificate itself.

The build script asserts the APK actually contains what the app reads at runtime:
`assets`/`lib` entry, uncompressed vs compressed as appropriate, ELF magic, and
`e_machine` for AArch64. A build that reports "APK ready" while shipping an APK with no
binary in it fails only on the phone, which is the one machine the build cannot test on.

## 8. Repository layout

```
cmd/ard-agent      device agent, shipped inside the APK
cmd/ard-server     gateway: listeners, registry, ACL, audit, adb server protocol, forwards
cmd/ard-connect    operator-side client: one published port, mTLS per connection
cmd/ard-ca         certificate issuance and enrolment approval
cmd/mockadbd       adbd-protocol device simulator, for testing without hardware
cmd/probe          inspects one side of an adb protocol connection
internal/adbserverproto  adb's server protocol, the packet encoding (CNXN, OPEN, WRTE,
                          CLSE) and the host side of the exchange, forwarding included
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
deploy/                  systemd unit, environment, operator policy, nftables rules
scripts/                 deploy, end-to-end runs, APK build, ssh and stop helpers
docs/ARCHITECTURE.md, docs/OPERATIONS.md
```

There is no `test/e2e` package. The end-to-end paths are shell scripts that build the
binaries and drive the real `adb` binary: `scripts/e2e-local.sh`,
`scripts/e2e-enrol.sh` and `scripts/e2e-operator.sh`.

## 9. Phases

- **P1 — one operator, real ADB.** agent, server, CA, mockadbd, and the operator path.
  The two spikes are settled; see section 7 for what the measurements said.
- **P2 — platform.** Roles and grants, audit, multi-operator, registry hardening.
- **P3 — the rest of adb.** Push, pull, forward and reverse all work over the operator
  path and are checked against real `adb`. What remains is coverage rather than
  protocol work: `install` and the remaining ADB services are not exercised because
  `test/mockadbd` does not implement them, so they are verified against real hardware
  instead.
- **P4 — operator UI.** A web console: terminal, files, apps, logcat.
- **P5 — screen.** Video stream and input injection.