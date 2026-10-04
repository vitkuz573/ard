# ARD — remote ADB

Stock `adb`, driven at devices you cannot reach directly.

```
operator ──adb──> gateway loopback :15000 ──> ard-proxy ──unix──> ard-server
                    │                                              │
              operator browser                              mTLS + yamux
                                                                  │
                    device ──ard-agent──mTLS + yamux──────────────┘
```

The device dials out. It sits behind NAT, usually carrier-grade NAT, so the
gateway can never connect to it. Every stream an operator opens is multiplexed
over the one inbound connection the device made.

Because the gateway runs the **real** `adb server` and presents each device on a
loopback port, nothing about ADB is reimplemented: `shell`, `push`, `pull`,
`install`, `logcat`, `forward` and `reverse` all come from `adb` itself, so
upstream features arrive without anyone writing them again.

## Deploy the gateway

```sh
scripts/deploy.sh                      # build, install, verify
scripts/deploy.sh --rotate-device <uuid>   # enrol another device
```

Idempotent. Preserves the PKI and the device allowlist. Prints what it verified.

## Deploy to a device

```sh
adb install -r android/ard-agent.apk
```

Press **Enrol** first (below), then **Discover adbd**, then **Start**. You type the gateway address;
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
```

`e2e-enrol.sh` runs the gateway as root, because enrolment is deliberately restricted to
uid 0 on the control socket. It asserts the part that unit tests cannot: that a
certificate obtained this way actually opens a mutual-TLS session.

The mock in `test/mockadbd` speaks adbd's wire protocol and is tested against the
actual `adb` binary. Several of its bugs were found only by that interop, and
each presented as a silent hang rather than an error — see the commit history.