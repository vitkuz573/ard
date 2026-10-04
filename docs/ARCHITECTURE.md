# ARD — Architecture

Remote ADB platform. Devices dial out to the server (they are unrouted, behind CGNAT).
Operators connect and control those devices over the real ADB protocol.

Status: design frozen for v1. Nothing here is "to be decided later" unless listed
in [Deferred](#deferred).

---

## 1. Non-negotiable security rules

These are structural, not features. They constrain every component.

1. **`adbd` never touches a network.** The agent runs *on the device* and reaches
   `127.0.0.1:5555` locally. ADB has no authentication: one `adb connect` to an
   exposed `adbd` is full control of the phone (files, install, shell, screen).
   So `adbd` is never bound to anything but loopback, on the device.
2. **Device and operator trust are separate roots.** A stolen operator cert must
   not be able to enroll a device, and a stolen device must not reach any device
   other than itself.
3. **Every operator action is attributable.** Auth says *which human*, not *which
   certificate*. Audit is written before the action starts, not after.
4. **No implicit reachability.** Nothing is reachable because it exists. Device
   ports are allowlisted by UUID, operator access by ACL, `adb forward` targets
   are a separate permission.
5. **Devices are inert by default.** A device may only be routed to by an operator
   who holds a grant for that device.
6. **A completed TLS handshake is not an authorization decision.** Under TLS 1.3 the
   client finishes its side of the handshake *before* the server has verified the
   client certificate, which travels in the second flight. A rejected certificate
   surfaces later, as an alert on the first application read or write. So every
   client must complete one authenticated application exchange before acting, and
   must treat failure of that exchange as "not authorized" rather than retrying on
   a new connection. The device handshake (`HELLO` → `WELCOME`/`ERR`) and the
   operator session (`hello` → device list) are the gates for this.

---

## 2. Components

```
  DEVICE SIDE (unrouted, dials out)        SERVER (VPS)                OPERATORS
  ┌──────────────────────┐          ┌───────────────────────┐    ┌──────────────┐
  │ ard-agent            │ ①mTLS    │ ard-server            │    │ ard-tap (CLI)│
  │  - device identity   │ yamux    │  - PKI + authz        │◄──►│  stock adb   │
  │  - yamux client      │─────────►│  - registry           │mTLS│  stock adb   │
  │  - pipe ↔ adbd       │◄──②stream│  - yamux sessions     │    ├──────────────┤
  │                      │          │  - audit log          │    │ Web console  │
  │ 127.0.0.1:5555 (adbd)│          │  - operator API (WSS) │◄──►│ (PWA, v3)    │
  └──────────────────────┘          │                       │WSS └──────────────┘
                                    │  127.0.0.1:1500X ◄─────┼── ard-proxy ── stock adb server
                                    └───────────────────────┘    (loopback bridge)
```

Five binaries:

| Binary | Runs on | Purpose |
|---|---|---|
| `ard-agent` | device | outbound mTLS session, exposes the device's `adbd` |
| `ard-server` | VPS | PKI, registry, authz, audit, operator API, yamux hub |
| `ard-proxy` | VPS | per-device loopback ports so stock `adb server` can attach |
| `ard-tap` | operator side | adb-protocol-aware bridge, so stock `adb` works unchanged |
| `ard-ca` | offline | issues device and operator certificates |

---

## 3. The single primitive: a stream

Everything is one primitive. **A stream is an authenticated, audited, bidirectional
byte pipe from an operator session to one device.** Terminal, file transfer,
logcat and video are all just typed streams on top of it. No feature adds a new
transport, so adding a feature cannot break the security model.

Device-side stream kinds: `adb` (raw pipe to `adbd`).

Operator-side stream kinds: `shell` (server-side PTY), `exec`, `logcat`,
`files`, `raw-adb`.

---

## 4. Wire protocols

### 4.1 Device leg — agent → server

TLS 1.3, mutual, server name pinned. Then:

```
agent → server : "ARD/1 HELLO {"device":..,"name":..,"agent":..}\n"
server → agent : "ARD/1 WELCOME {"session":..,"heartbeat":..}\n"   |  "ARD/1 ERR <reason>\n"
then           : yamux (server side opens streams)
```

Server-initiated stream, header then raw bytes:

```
"ARCS/1 ROUTE {"device":"<uuid>","kind":"adb","meta":{...}}\n"
<raw bytes, no framing, until EOF>
```

**Why two multiplexers.** yamux carries N operator streams over *one* TLS
connection per device. Inside, all `adb`-kind streams are framed onto *one* long
lived `adbd` connection, because `adbd` is the fragile resource: historically it
replaces an old host connection when a new one arrives, which would kill an
in-flight session on reconnect. If testing shows modern `adbd` accepts concurrent
connections, the inner framing layer is removed and every stream gets its own
`adbd` connection.

### 4.2 Operator leg — operator → server

HTTPS for auth, WebSocket for sessions. JSON control frames + binary data frames.

```
→ {"op":"hello"}                                  ← device list, filtered by ACL
→ {"op":"open","device":"<uuid>","kind":"shell","meta":{"cols":80,"rows":24,"term":"xterm-256color"}}
← {"op":"opened","stream":"<id>"}                  ← authz + audit passed, now a yamux stream exists
⇄ {"t":"bin","stream":"<id>","data":"<base64>"}   ← both directions, raw bytes
→ {"op":"resize","stream":"<id>","cols":120,"rows":40}
→ {"op":"signal","stream":"<id>","sig":"INT"}
→ {"op":"close","stream":"<id>"}
```

Auth: login → short-lived JWT + refresh token in a `Secure; HttpOnly; SameSite=Strict`
cookie. Client certificates are accepted as a second factor later, not required
for v1 — but the identity model already supports it.

### 4.3 Loopback bridge — stock `adb`, unmodified

`ard-proxy` on the server listens on `127.0.0.1:1500X`, one port per online
device, each port a pipe into that device's `adb`-kind stream. The real `adb
server` then does:

```
adb connect 127.0.0.1:15001     # serial becomes "127.0.0.1:15001"
adb -s 127.0.0.1:15001 shell
```

`adb` believes it attached to an ordinary TCP device. No fork, no patch. This is
how *all* ADB features work — including `adb forward` / `adb reverse`, because the
real `adb server` owns them and it runs on the server where the devices already are.
`forward` targets are still gated: `adb.forward` is a separate permission and the
operator-facing API never exposes raw port binds.

---

## 5. Multi-tenancy — what must be in v1

Each of these is expensive or impossible to retrofit cleanly. All are in v1.

| Concern | Decision |
|---|---|
| Identity | Operator accounts with a stable ID. `subject` in the JWT; certificate CN maps to the same account. Never "an operator" as a bare string. |
| Authorization | `operator → role → permissions`; `device → tags → ACL entries`. Checked on every `open`, never cached on the socket. |
| Device enrollment | Device generates a keypair, presents a one-time enrollment token, server assigns UUID and issues its cert. No pre-baked static certificates. |
| Device identity vs connection | A UUID survives reboot, reinstall and IP change. Registry keyed by UUID, not by socket. |
| Audit | Every `open` is logged before the stream is granted: operator, device, kind, source IP, time, stream ID. Closed with a duration on `close`. Append-only file, later shipped to a SIEM. |
| Concurrency | Multiple operators may hold streams to one device simultaneously. Streams are never shared between operators, so one operator cannot read another's terminal. |
| Isolation | Each operator's streams get separate yamux streams. A single operator session cannot address another session's streams. |
| Config | YAML + env only. dev / staging / prod differ by configuration, never by code. |

Device registry state is `online | draining | offline`, with `draining` used to
finish existing streams during graceful disconnect instead of cutting them.

---

## 6. Deferred (additive, cannot break v1)

- Web console UI (PWA). The operator leg already supports it; it is a client.
- Screen streaming. `scrcpy-server` → H.264 → remux to fMP4 → MSE in the browser.
  Remux only, no decode. Highest-effort item.
- File manager UI over the `files` stream.
- Multi-factor auth, per-device grant expiry.
- Clustering more than one gateway node.

## 7. Open risks to spike before building on top

1. **Reaching `adbd` from the agent.** Requires Developer options + USB debugging
   enabled once per device. On Android 11+ wireless debugging can be paired instead.
   If an OEM blocks loopback access from the agent's context, this changes the
   design.
2. **Concurrent `adbd` connections.** Decides whether the inner framing layer
   stays. Test empirically.
3. **`adb connect 127.0.0.1:<port>`.** The loopback bridge depends on this exact
   behaviour. Validate early; if it is not allowed, the bridge changes shape.

## 8. Repository layout

```
cmd/ard-agent      cmd/ard-server     cmd/ard-proxy
cmd/ard-tap        cmd/ard-ca         cmd/ardctl
internal/tlsx      CA and certificate issuance
internal/hs        framing: handshake + ROUTE + inner stream multiplex
internal/reg       device registry, presence, drain
internal/acl       roles, permissions, grants
internal/audit     append-only audit log
internal/ptysrv    server-side PTY allocation for shell streams
test/mockadbd      adbd-protocol mock device, for testing without hardware
test/e2e           end-to-end: agent → server → operator
docs/ARCHITECTURE.md
```

## 9. Phases

- **P1 — one operator, all of ADB.** agent, server, proxy, tap, CA, mockadbd, e2e.
  Proves risk 1-3 and gives real ADB over the phone. No multi-tenancy.
- **P2 — platform.** Identities, roles, ACL, audit, multi-operator, registry
  hardening, concurrent streams.
- **P3 — operator UI.** Web console: terminal, files, apps, logcat.
- **P4 — screen.** Video stream and input injection.