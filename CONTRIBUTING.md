# Contributing

## Build and test

```sh
go build ./...
go test ./...
scripts/e2e-local.sh      # mock device, real adb, full path
scripts/e2e-enrol.sh      # certificate enrolment, end to end; needs passwordless sudo
scripts/e2e-operator.sh   # operator path: stock adb from another machine, no SSH
```

`e2e-operator.sh` is the one that proves the product shape. It drives a device with the
real `adb` binary from a machine that is not the gateway, reachable only over TLS, with no
SSH and no loopback — because the alternative is that every operator needs a login on the
VPS, which is all-or-nothing access to the host holding the CA keys.

`scripts/e2e-enrol.sh` needs passwordless sudo, because `ard-ca enrol` signs with the CA
key and is restricted to uid 0 on the control socket. The gateway runs unprivileged, as
in production, and the script asserts that it does. It exists to check the one thing unit
tests cannot: that a certificate obtained through the CSR flow actually opens a
mutual-TLS session. An enrolment bug can be perfectly self-consistent and still produce
an identity the agent cannot use, and that shows up as a handshake error on the first
real connection.

`scripts/e2e-local.sh` is the other one that matters. The mock in `test/mockadbd`
speaks adbd's wire protocol and is checked against the actual `adb` binary; a change
that passes `go test ./...` but breaks the mock's protocol behaviour will be caught
by that script and nowhere else, and it tends to present as a silent hang rather than
an error.

There is no CI on this repository by request. Run them locally and say so in the PR.

### One thing about stdin in interop tests

`TestInteropStdinRoundTrip` gives `adb shell cat` a real `*os.File` as stdin, not a
pipe, and that is load-bearing rather than incidental: `os/exec` feeds a piped stdin
from a background goroutine, adb's shell client does not notice the write side closing,
the device is never sent `kIdCloseStdin`, and `cat` blocks forever. Shell redirection
from a file — or from a shell pipeline — closes correctly. Keep it that way, and treat
`adb shell cat hung after 15s` as this until you have ruled it out.

## Testing against real devices

Ask first, and use the mock otherwise.

Do not run load, transfers or repeated connection tests against hardware you did
not set up. A relay that fans many streams onto one connection will drain a phone
faster than a laptop's USB port can charge it. Read-only inspection is fine without
asking.

## Code conventions

**Comments explain why, not what.** The code says what it does. A comment earns
its place by recording something the reader would otherwise get wrong: a
constraint, a measurement, a rejected alternative, an invariant.

```go
// Bad: increments the counter
counter++

// Good: the counter is not a byte count. It counts packets, because the retry
// budget is per packet and a byte budget silently starves large transfers.
counter++
```

Prefer a comment that records a measurement, including one that contradicts an
assumption the code was written on. The measurements are the most useful part of
this codebase — see section 7 of `docs/ARCHITECTURE.md` and the protocol notes in
`test/mockadbd`.

**No new dependencies without a note** on why the standard library is not enough.
The agent ships as a single native library inside an APK, so every dependency is
weight on a device that may have no network.

**Keep the gateway free of CA private keys.** `internal/tlsx` enforces this in
the type system. Do not add an API that hands a gateway process a signing key.

## Secrets

This is the rule most likely to be broken by accident, so it is short:

- Nothing identifying a real deployment goes in the repository. No IP address,
  hostname, IPv6 address, device serial or model.
- No gateway address is compiled into the APK. The UI asks for it.
- Credentials live outside the tree, in `~/.ard-secrets/`.

`.gitignore` is a convenience, not a boundary: it does not apply to already
tracked files, and history keeps copies. If a secret does land in a commit,
rewriting history is the only real fix — deleting the file in a later commit is
not.

## Commit messages

Say what the change fixes and what it cost. When a previous belief was wrong,
say so and say what measurement showed it — that is the part a future reader
needs and cannot reconstruct.

## Pull requests

Fill in the template. The two fields that matter most:

- **Why** — including the alternatives you rejected.
- **How it was tested** — and what was *not* tested. An honest gap is useful; a
  checkbox ticked without running anything is not.