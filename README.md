# ARD — remote ADB

Stock `adb`, driven at devices you cannot reach directly.

```
adb ──> 127.0.0.1:15000 ──> ard-connect ──mTLS──> ard-server
          (operator's own machine)                      │
                                                   mTLS + yamux
                                                          │
                device ──ard-agent──mTLS + yamux───────────┘
```

`ard-connect` runs on the operator's machine and needs nothing else: no SSH, no
account on the gateway. That is not a convenience. The gateway publishes one port and
speaks adb's own server protocol on it, so the alternative was an operator logging into
the VPS over SSH to use it — which hands out all-or-nothing root on the machine that
holds the CA private keys, cannot be scoped per device, and cannot be revoked for one
person without disturbing the rest.

The device dials out. It sits behind NAT, usually carrier-grade NAT, so the
gateway can never connect to it. Every stream an operator opens is multiplexed
over the one inbound connection the device made.

`adb` itself decides what to do on the device, so an upstream ADB feature arrives
without anyone writing it again — the gateway's job ends at switching `adb` onto a
device and relaying the bytes. That is not quite "nothing is reimplemented": the
gateway does answer adb's server protocol (`internal/adbserverproto`), does the host
side of the `CNXN`/`OPEN` exchange with the device, and holds the ports that
`adb forward` binds. It implements no ADB service — `shell`, `sync` and `install` are
the device's own, and the gateway never looks inside them.

A local helper on the operator's machine is unavoidable rather than incidental. `adb`
speaks plaintext TCP to `host:port` and cannot do TLS at all, and the gateway accepts
nothing but mutual TLS. So something has to terminate TLS locally — `ssh -L` is one
such helper, which is exactly why SSH was in the requirements before `ard-connect`
existed.

## Deploy the gateway

```sh
scripts/deploy.sh                      # build, install, verify
scripts/deploy.sh --rotate-device <uuid>   # enrol another device
```

Idempotent. Preserves the PKI and the device allowlist. Prints what it verified.

## Connect as an operator

```sh
ard-connect -gateway gw.example:7100 \
            -ca server-ca.crt -cert operator.crt -key operator.key
```

It prints the local port it published, then point `adb` at that port:

```sh
adb -P 15000 devices
adb -P 15000 -s <device-uuid> shell
adb -P 15000 -s <device-uuid> push file.txt /data/local/tmp/
adb -P 15000 -s <device-uuid> pull /data/local/tmp/file.txt .
adb -P 15000 -s <device-uuid> forward tcp:9930 tcp:9931
```

`adb` asks the gateway which devices exist rather than being handed a list, so there is
no `adb connect` and no serial to remember between machines — the serial is the device
UUID. A device your role may see but not drive appears in the listing and is refused
when you try to drive it, with the reason on your own terminal. Roles, permissions and
per-device grants live in `deploy/operators.yaml`, and every attach is authorized on
the gateway — the client is never trusted about what it may reach, and holds no device
list of its own.

A port bound by `adb forward` is bound on the **gateway's** loopback, not on yours,
because the gateway is the machine the adb binary's server runs on. Reaching it means
reaching the gateway host; nothing about it is published on a network interface.
`adb reverse` is the mirror: the device binds the port, and what reaches it lands on
the gateway's loopback.

## Deploy to a device

```sh
adb install -r android/ard-agent.apk
```

Press **Enrol** first (below), then **Discover adbd**, then **Start**.

**Start matters more than it looks.** Android puts a backgrounded app into the
`APP_STANDBY` bucket and blocks its network. The agent is a long-lived client, so the app
holds a foreground service while it runs; press Start and leave it running. Starting the
binary by hand instead — Termux, `run-as` — works only while the phone is charging, and
the symptom is a dial timeout rather than anything that mentions standby.

If battery optimisation is aggressive, allow the app to run unrestricted. The device is
otherwise fine and nothing needs changing on it. You type the gateway address;
everything else the app works out for itself. There is no gateway baked into the
APK, so the same build works for every deployment and nobody has to publish an
address to use it.

### Certificates

The device generates its own key pair and asks for a certificate. No private key is ever
copied to or from the phone, and nothing has to be pushed to it to enrol it: the
request goes out over the gateway connection and the certificate comes back the same
way. Files, once a device is enrolled, go both ways with `adb push` and `adb pull`.

On the phone: install the APK, fill in the gateway address, press **Enrol**. The app
shows a code and waits.

On the gateway host:

```sh
sudo ard-ca enrol -code <CODE>      # prints the request, then asks before signing
```

That is the whole procedure. The device keeps the key it generated, the gateway never
signs anything, and `ard-ca` -- which holds the CA -- is the only party that can.

Three properties are worth stating, because they are the reason the flow is shaped this
way:

- **The key never moves.** The device generates it, stores it, and presents it. The CA
  only ever sees a signature request.
- **The gateway cannot mint identities.** It holds no CA key. It stores requests and
  forwards them; signing happens in `ard-ca`, wherever the CA lives.
- **The approval is specific.** The operator is shown which device, which request id and
  which CSR, and the code binds that approval to that one request. The device also
  reports the fingerprint of the gateway certificate it actually reached, which the
  signing side compares against the PKI -- so an interception attempt at first contact
  fails before anything is signed.

## Build the agent APK

```sh
scripts/build-apk.sh
```

No Gradle: aapt2, javac, d8, zipalign, apksigner. A build with no dependency
resolution cannot break on a device with no network, which is the deployment this
exists to serve.

The script asserts the APK contains what the app reads at runtime — the binary
entry, its ELF magic and `e_machine`, and how it is compressed. An APK with no binary in
it fails on the phone and nowhere else, so the build is where that has to be caught.

## Documentation

- `docs/ARCHITECTURE.md` — design, and the constraints real hardware imposed
- `docs/OPERATIONS.md` — gateway hardening, PKI permissions, maintenance lessons
- `deploy/README.md` — deployment notes and why each decision was made

## Testing

```sh
go test ./...                 # unit and protocol tests
scripts/e2e-local.sh          # full path against a mock device, real adb
scripts/e2e-enrol.sh          # certificate enrolment, device through gateway to a session
scripts/e2e-operator.sh       # the operator path: stock adb, no SSH, roles enforced
```

`e2e-enrol.sh` needs passwordless sudo, because `ard-ca enrol` signs with the CA key and
is restricted to uid 0 on the control socket. The gateway itself runs unprivileged, as
in production, and the script asserts that it does. The part unit tests cannot cover is
that a certificate obtained this way actually opens a mutual-TLS session.

The mock in `test/mockadbd` speaks adbd's wire protocol and is tested against the
actual `adb` binary. A mock that is merely plausible produces passing tests for
behaviour real adbd does not have, and the failures that interop catches present as a
silent hang rather than an error.

It also has a virtual filesystem, a property store, a 24-command shell, and
deterministic fault injection — latency, dropped and corrupted writes, truncation
mid-transfer, and a stall that hangs rather than errors. It stands on its own as a
device simulator; see [its README](test/mockadbd/README.md) for what it does and
does not implement.