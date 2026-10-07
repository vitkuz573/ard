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
| `shell` | 24 commands over a real in-memory filesystem and property store |
| interactive shell | sessions: line at a time, state carried across lines, last command's status; `-t`/`-T` pipes, `-tt` a real pty |
| `host:` | `version`, `devices`, `transport` |
| `sync:` | the text-framed protocol, in both its spellings: `STAT`/`LIST`/`SEND`/`RECV` and `STA2`/`LIS2`/`SND2`/`RCV2`. A client picks between them from the feature list it was given for the device, so `-banner` selects the path |
| `tcp:` | the device half of `adb forward`: connect to a port on this device's own loopback and splice |
| `reverse:` | the device half of `adb reverse`: bind a port here, and open a stream back to the host for every connection that reaches it. `forward:`, `killforward:`, `killforward-all`, `list-forward` |
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

- **The sync transfer is not compressed, and `adb push` and `adb pull` depend on that.** The
  exchange itself matches a real adbd: the 72-byte stat reply in one packet, the zeroed body
  for a missing file, the 8-byte DONE reply in one packet.

  Compression is the one protocol feature deliberately not implemented, and the banner says
  so: `sendrecv_v2_brotli`, `sendrecv_v2_lz4` and `sendrecv_v2_zstd` are absent, so adb
  compresses nothing and there is nothing here to decompress. That is not a formality. adb
  reads the feature list before it chooses, and above its own size threshold it will pick the
  best one it is told about, so putting those features back into `Config.Banner` makes every
  push over that size arrive zstd-framed and unreadable.

  ```sh
  MOCKADBD_TRACE=/tmp/t.log go test ./test/mockadbd/ -run TestInteropPushLands
  ```

- **The shell is not `/system/bin/sh`.** It is a Go interpreter over the commands in the
  table above. Behaviour matches on exit statuses -- 0, 1 for a lookup failure, 2 for
  misuse, 127 for an unknown command -- because tests assert on them.

- **State is per-process.** Every `adb shell COMMAND` invocation is a fresh session with `cwd`
  at `/`, as on a real device. State *within* one interactive session does carry: `cd` in one
  line is visible to the next. Nothing persists across invocations.

- **A command inside an interactive session gets no stdin.** `cat` with no argument in a
  session sees end of input immediately rather than consuming the lines after it. The session
  owns stdin: the lines arriving there are commands, and a command that read them would leave
  no way to run the next one. `adb shell cat FILE` reads the filesystem and is what a test
  wants.

- **The shell prompt is `localhost:/ $ `**, following the working directory. A device prints
  its own hostname there; this mock has none, and inventing one would be claiming a detail it
  does not have. The prompt is printed only when a terminal was allocated, as on a device.

- **A terminal is a real pty, and only on linux.** `/dev/ptmx` is opened with `TIOCSPTLCK` and
  `TIOCGPTN` and the slave is used as the interpreter's stdin and stdout, so echo, CRLF line
  endings, canonical input buffering and the window size are the kernel's rather than
  something this code writes out to look like them. On any other platform `adb shell -t` falls
  back to a pipe and says so on stderr; the package still builds. `TIOCSWINSZ` is applied from
  `kIdWindowSizeChange` and read back with `TIOCGWINSZ`, because that ioctl reports no error for
  a size it disliked.

## Interactive shell

`adb shell` with no command opens a session rather than running one empty command:

```sh
printf 'cd /system/bin\npwd\nexit\n' | adb -s 127.0.0.1:5555 shell
```

Each line runs in turn, output comes back as it is produced, and the status reported is the
last command's. One runner serves the whole session, which is what makes `cd` visible to the
line after it.

`-T` and `-t` differ. Both are a pipe when the client's own stdin is not a terminal -- adb
refuses a remote terminal in that case and says so -- and both work the same way as a plain
`adb shell`: no prompt, no echo. `-tt` forces a pty regardless, and is how you get a prompt out
of adb without a terminal on this side:

```sh
printf 'echo one\nexit\n' | adb -s 127.0.0.1:5555 shell -tt | od -c
```

which produces a prompt, the typed line echoed back, and CRLF line endings. On a device the
prompt is the device's own hostname and the carriage returns come from the terminal's `ONLCR`;
here they come from this host's pty, which is why the byte sequence matches a device but the
prompt text does not.

End of input ends a piped session and its status is the last command's. A terminal session
does not end that way, matching a device: a terminal has no end of input, so `exit` is the way
out, and a test that forgets it hangs rather than fails.

Behaviours taken from a real device rather than reasoned about, since they are what the
`TestInteropShell*` tests assert:

| | |
|---|---|
| status of a session | the last command's: `false` then EOF gives 1 |
| `exit` | the last command's status; `exit N` gives N; `exit 300` gives 44 (one byte) |
| `exit abc` | a message on stderr, status 1 |
| end of input | ends a piped session cleanly; a session with no lines exits 0 |
| blank line | runs nothing, prints nothing |
| `# comment` | a comment, not an unknown command |
| prompt with no terminal | none |
| prompt with a terminal | printed per line, tracks `cd` |

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

## Port forwarding: what the protocol actually is

The two directions are not the same exchange, and only one of them is visible to this
process. The notes below were captured from a real adbd rather than guessed, because
guessing cost a debugging round for `sync` and there is no reason to repeat it.

`adb forward` never mentions the device at setup time. The adb server binds the host-side
port itself, and the device is only involved later, when a connection arrives and the
server opens a stream asking it to connect out. The device's whole part is that one
service:

    host -> device  OPEN  arg0=11 arg1=0  "tcp:9911\0"

so `tcp:` here dials `127.0.0.1:9911` on this device and splices the stream onto the
socket. Binding the host-side port is outside this transport entirely, which is why it
lives in the adb server and not here.

`adb reverse` is answered by the device, and in one exchange:

    adb reverse tcp:9911 tcp:9910

    host -> device  OPEN   arg0=6 arg1=0  "reverse:forward:tcp:9911;tcp:9910"
    device -> host  OKAY   arg0=114 arg1=6
    device -> host  WRTE   arg0=114 arg1=6  "OKAY00049911"

The reply is the daemon service acknowledgement: `OKAY`, then a four-hex-digit field, then
the port. `0004` is the width of what follows and `9911` is the device port that was opened.
The port is four ASCII digits behind the width, not a 4-byte integer, and the `OKAY` word
is not optional: a client reads four bytes as a status before it reads the length, so a
reply without the word is read as a status that is neither OKAY nor FAIL, and the bytes it
reports are the port reinterpreted.

What makes `reverse` more than a case in the service switch is what follows. Every
connection that reaches the device-side listener has to become a *new* stream back to the
host, opened by this device -- so the transport carries device-initiated OPENs, and each
one is completed by the same read loop that carries everything else, because two readers on
one socket is how a connection ends up with each of them holding half a packet.

## Seeing what adb itself is doing

`MOCKADBD_TRACE` shows the device. `ADB_TRACE=all` on the adb server shows the server. The
third party -- the `adb` client, and the adb server when the server is what you need -- is
only reachable through a debugger, and `ptrace` and `gdb` are both refused on many hosts:

```
kernel.yama.ptrace_scope = 1
```

`LD_PRELOAD` gets around that, because it needs no privileges. This intercepts `read`,
`write`, `writev`, `poll` and `epoll_wait`, prints a timestamp for each, and changes nothing.

`writev` is not optional. The adb server hands a reply to the client with
`local_socket_flush_incoming()`, which calls `adb_writev`, so without that one symbol the
trace shows the device's reply being ingested and never reaching the client -- which reads
exactly like a dropped packet and is not one. It is also worth logging the thread id: adb's
server has a looper thread, a read thread and a write thread, and without it the three are
indistinguishable.

```c
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <poll.h>
#include <sys/epoll.h>
#include <sys/uio.h>
#include <time.h>
#include <sys/time.h>
#include <pthread.h>
#include <unistd.h>

static ssize_t (*r_read)(int, void *, size_t);
static ssize_t (*r_write)(int, const void *, size_t);
static ssize_t (*r_writev)(int, const struct iovec *, int);
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
    if (!r_writev) r_writev = dlsym(RTLD_NEXT, "writev");
    if (!r_poll)  r_poll  = dlsym(RTLD_NEXT, "poll");
    if (!r_epoll_wait) r_epoll_wait = dlsym(RTLD_NEXT, "epoll_wait");
}

static void say(const char *what, int fd, ssize_t r) {
    fprintf(stderr, "SHIM +%7.3f [tid %d] %s fd=%d -> %zd\n", now() - t0,
            (int)pthread_self() % 100000, what, fd, r);
    fflush(stderr);
}

ssize_t read(int fd, void *buf, size_t n) {
    init();
    ssize_t r = r_read(fd, buf, n);
    say("read", fd, r);
    return r;
}

ssize_t write(int fd, const void *buf, size_t n) {
    init();
    ssize_t r = r_write(fd, buf, n);
    say("write", fd, r);
    return r;
}

ssize_t writev(int fd, const struct iovec *iov, int c) {
    init();
    ssize_t r = r_writev(fd, iov, c);
    say("writev", fd, r);
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