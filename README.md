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

Open it, press **Discover adbd**, then **Start**. You type the gateway address;
everything else the app works out for itself. There is no gateway baked into the
APK, so the same build works for every deployment and nobody has to publish an
address to use it.

### Known remaining step: certificates

The APK ships the agent but **not** a device identity. Until in-app enrolment
exists, the credentials are put in place once:

```sh
# on the gateway
ard-ca device -dir /etc/ard/pki -id <device-id>

# on the device
adb push <device-id>.crt /data/local/tmp/device.crt
adb push <device-id>.key /data/local/tmp/device.key
adb shell "run-as dev.ard.agent mkdir -p files/ard"
adb shell "cat /data/local/tmp/device.crt | run-as dev.ard.agent sh -c 'cat > files/ard/device.crt'"
adb shell "cat /data/local/tmp/device.key | run-as dev.ard.agent sh -c 'cat > files/ard/device.key'"
adb push <server-ca>.crt /data/local/tmp/ca.crt
adb shell "cat /data/local/tmp/ca.crt | run-as dev.ard.agent sh -c 'cat > files/ard/ca.crt'"
```

This is the part that is not yet "one step". The fix is a CSR flow: the app
generates its own key pair, sends a CSR to the gateway, and receives a
certificate. Nothing leaves the device that does not need to, and the operator
stops touching key material. The gateway side is a small addition; it is simply
not written yet.

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
```

The mock in `test/mockadbd` speaks adbd's wire protocol and is tested against the
actual `adb` binary. Several of its bugs were found only by that interop, and
each presented as a silent hang rather than an error — see the commit history.