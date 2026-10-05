# mockadbd

An Android device simulator that speaks adbd's wire protocol, with no emulator, no
emulator image, and no KVM.

It exists so that a tool which talks to a phone over ADB can be tested end to end on a
machine that has no phone. The mock is checked against the **real `adb` binary** in this
repository's own test suite, because a mock that is merely plausible is worse than none: it
produces passing tests for behaviour real adbd does not have.

```sh
go run ./cmd/mockadbd -addr 127.0.0.1:5555
adb connect 127.0.0.1:5555
adb -s 127.0.0.1:5555 shell ls -l /system/bin
```

## What it implements

| Area | |
|---|---|
| Transport | CNXN negotiation, AUTH with an RSA host key, OPEN/WRTE/OKAY/CLSE, device-initiated streams |
| `shell` | 26 commands over a real in-memory filesystem and property store |
| `host:` | `version`, `devices`, `transport` |
| `sync:` | the v1 binary protocol, complete; the v2 text protocol, partially |
| Filesystem | a seeded Android tree, read/write, `stat`, modes, mtimes, path confinement |
| Properties | `getprop`/`setprop` with presence distinguished from emptiness, and the `ro.` prefix query |
| Faults | latency, jitter, dropped writes, corrupted writes, truncation mid-stream, stalling |

## Using it from a test

```go
l, err := mockadbd.Listen("127.0.0.1:0", mockadbd.Config{
    FS: mockadbd.NewVFS(),
})
if err != nil {
    return err
}
defer l.Close()
// device is l.Addr(); adb connect to it
```

`Config.Shell` replaces the command interpreter, so a test can script the device:

```go
Config{Shell: func(argv []string, in io.Reader, out, errOut io.Writer) int {
    if argv[0] == "getprop" && len(argv) > 1 {
        fmt.Fprintln(out, "sandboxed")
        return 0
    }
    return 1
}}
```

## Fault injection

The reason this is more than a stub. "Does the path work when a transfer is cut in half,
when a packet is lost, or when the device stops answering mid-command?" cannot be answered
by a device that behaves, and answering it against real hardware drains somebody's phone.

```go
mockadbd.Listen(addr, mockadbd.Config{Faults: &mockadbd.Faults{
    Latency:              200 * time.Millisecond,
    DropEveryNthWrite:    17,
    TruncateStream:       64 << 10,  // cut mid-transfer
    StallAfterBytes:      1 << 20,   // go silent, connection open
    CorruptEveryNthWrite: 9,
}})
```

Randomised rules are **deterministic when seeded**. A relay test that fails one run in five
gets ignored, and a coin flip is the worst thing to add to a suite that has already been
hard to diagnose.

`StallAfterBytes` is the interesting one: it produces a hang rather than an error, which is
what a watchdog on the other side exists for. It is also why the mock has a stall watchdog
of its own in the relay.

## What it does not do

Stated plainly, because a simulator that overstates itself is worse than a stub.

- **`adb push` and `adb pull` do not work.** The v1 binary sync protocol is implemented and
  unit-tested. A current adb uses the v2 text protocol, and this implements enough of it to
  parse `STA2` and reply correctly -- after which adb stops rather than continuing. The
  remaining mismatch is one command away:

  ```sh
  MOCKADBD_FORCE_SYNC=1 MOCKADBD_TRACE=/tmp/t.log \
    go test ./test/mockadbd/ -run TestInteropPushLands
  ```

  The seven push and pull tests skip with that reason attached. They are the specification,
  and they enable themselves when it works.

- **No PTY.** `adb shell` without `-t` gets a pipe. `adb shell -t` is not implemented.

- **No `adb reverse` or `adb forward`.** The services are not served.

- **The shell is not `/system/bin/sh`.** It is a Go interpreter over the commands in the
  table above. Behaviour matches on exit statuses -- 0, 1 for a lookup failure, 2 for
  misuse, 127 for an unknown command -- because tests assert on them.

- **State is per-process.** Every `adb shell` invocation is a fresh session with `cwd` at
  `/`, as on a real device. Nothing persists across the connection.

## MOCKADBD_TRACE

Fault diagnosis is guesswork without it: the symptom of a framing bug is a hang, and a hang
tells you nothing about what arrived.

```sh
MOCKADBD_TRACE=/tmp/t.log go test ./test/mockadbd -run TestWhatever
```

Logs every frame the device receives and every byte it sends. Gate it behind an environment
variable so it costs nothing when nobody is debugging -- it was added after a hang had
already been misdiagnosed twice, once as an adb bug and once as a client bug, both times
wrongly.

## Running the tests

```sh
go test ./...                        # everything, including the adb interop tests
go test ./test/mockadbd -run Interop -v   # just the ones that use real adb
```

The interop tests require `adb` on `PATH` and are skipped without it. They start a private
adb server, so they do not disturb a running one.