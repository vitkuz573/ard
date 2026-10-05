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
account on the gateway. That is not a convenience. The gateway runs the real `adb
server` and binds each device to a loopback port, so the alternative was an operator
logging into the VPS over SSH to use it — which hands out all-or-nothing root on the
machine that holds the CA private keys, cannot be scoped per device, and cannot be
revoked for one person without disturbing the rest.

The device dials out. It sits behind NAT, usually carrier-grade NAT, so the
gateway can never connect to it. Every stream an operator opens is multiplexed
over the one inbound connection the device made.

Because the **real** `adb` binary is what talks to the device, nothing about ADB is
reimplemented: `shell`, `push`, `pull`, `install`, `logcat`, `forward` and `reverse`
all come from `adb` itself, so upstream features arrive without anyone writing them
again.

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

It prints one local port per device your role permits, then:

```sh
adb connect 127.0.0.1:15000
adb -s 127.0.0.1:15000 shell
```

Devices your role may see but not drive are listed without a port, and say so. Roles,
permissions and per-device grants live in `deploy/operators.yaml`, and every attach is
authorized on the gateway — the client is never trusted about what it may reach.

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
copied to or from the phone, and nothing has to be pushed with `adb`.

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
entry, its ELF magic and `e_machine`, and how it is compressed. It previously
reported success for an APK containing no binary at all.

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

`e2e-enrol.sh` runs the gateway as root, because enrolment is deliberately restricted to
uid 0 on the control socket. It asserts the part that unit tests cannot: that a
certificate obtained this way actually opens a mutual-TLS session.

The mock in `test/mockadbd` speaks adbd's wire protocol and is tested against the
actual `adb` binary. Several of its bugs were found only by that interop, and
each presented as a silent hang rather than an error — see the commit history.

It also has a virtual filesystem, a property store, a 26-command shell, and
deterministic fault injection — latency, dropped and corrupted writes, truncation
mid-transfer, and a stall that hangs rather than errors. It stands on its own as a
device simulator; see [its README](test/mockadbd/README.md) for what it does and
does not implement.