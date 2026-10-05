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

## Seeing what adb itself is doing

`MOCKADBD_TRACE` shows the device. `ADB_TRACE=all` on the adb server shows the server. The
third party -- the `adb` client, and the adb server when the server is what you need -- is
only reachable through a debugger, and `ptrace` and `gdb` are both refused on many hosts:

```
kernel.yama.ptrace_scope = 1
```

`LD_PRELOAD` gets around that, because it needs no privileges. This intercepts `read`,
`write`, `poll` and `epoll_wait`, prints a timestamp for each, and changes nothing:

```c
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <poll.h>
#include <sys/epoll.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>

static ssize_t (*r_read)(int, void *, size_t);
static ssize_t (*r_write)(int, const void *, size_t);
static int (*r_poll)(struct pollfd *, nfds_t, int);
static int (*r_epoll_wait)(int, struct epoll_event *, int, int);
static double t0;

static double now(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec + tv.tv_usec / 1e6;
}

static void init(void) {
    if (!t0) t0 = now();
    if (!r_read)  r_read  = dlsym(RTLD_NEXT, "read");
    if (!r_write) r_write = dlsym(RTLD_NEXT, "write");
    if (!r_poll)  r_poll  = dlsym(RTLD_NEXT, "poll");
    if (!r_epoll_wait) r_epoll_wait = dlsym(RTLD_NEXT, "epoll_wait");
}

ssize_t read(int fd, void *buf, size_t n) {
    init();
    ssize_t r = r_read(fd, buf, n);
    fprintf(stderr, "SHIM +%7.3f read fd=%d -> %zd\n", now() - t0, fd, r);
    fflush(stderr);
    return r;
}

ssize_t write(int fd, const void *buf, size_t n) {
    init();
    ssize_t r = r_write(fd, buf, n);
    fprintf(stderr, "SHIM +%7.3f write fd=%d n=%zu -> %zd\n", now() - t0, fd, n, r);
    fflush(stderr);
    return r;
}

int poll(struct pollfd *fds, nfds_t nfds, int timeout) {
    init();
    int r = r_poll(fds, nfds, timeout);
    fprintf(stderr, "SHIM +%7.3f poll(n=%zu,to=%d)=%d\n", now() - t0, (size_t)nfds, timeout, r);
    fflush(stderr);
    return r;
}

int epoll_wait(int ep, struct epoll_event *ev, int maxev, int timeout) {
    init();
    double t = now() - t0;
    int r = r_epoll_wait(ep, ev, maxev, timeout);
    fprintf(stderr, "SHIM +%7.3f epoll_wait(to=%d)=%d [blocked %.3fs]\n",
            now() - t0, timeout, r, now() - t);
    for (int i = 0; i < r; i++)
        fprintf(stderr, "SHIM +%7.3f   fd=%d events=0x%x\n", now() - t0, ev[i].data.fd, ev[i].events);
    fflush(stderr);
    return r;
}
```

```sh
gcc -shared -fPIC -O1 -o /tmp/shim.so /tmp/shim.c -ldl

# the client
LD_PRELOAD=/tmp/shim.so adb -s SERIAL push FILE REMOTE

# the adb server
adb kill-server
LD_PRELOAD=/tmp/shim.so setsid adb nodaemon server >/tmp/srv.log 2>&1 &
```

It is not built by the Go tooling and is not part of this repository, because a diagnostic
that needs a C compiler is worth documenting rather than shipping. What it bought, in the
push that never finishes: the client's reads are fast and the device answers immediately, so
both of the obvious suspects are innocent, and the server's thirty seconds are silence --
no `read`, no `write`, not one `epoll_wait` -- which means the server's threads are blocked
in calls this does not intercept. `recv`, `send`, `accept` and the futex waits are the next
ones to add.

## Running the tests

```sh
go test ./...                        # everything, including the adb interop tests
go test ./test/mockadbd -run Interop -v   # just the ones that use real adb
```

The interop tests require `adb` on `PATH` and are skipped without it. They start a private
adb server, so they do not disturb a running one.