package mockadbd

import (
	"bufio"
	"fmt"
	"io"
	"strings"
	"sync"
)

// An interactive `adb shell`: the case where the service request carried no command.
//
// This used to run one empty command, print "shell: empty command" and close. That is what
// a device does not do, and it made the shape untestable: a relay hands an operator a
// stream, the operator types several things, and every one of them has to come back before
// the stream closes. Here a session reads a line, runs it, writes what it produced, and
// reads the next line until the input ends.
//
// The behaviours below were each checked against a real device rather than reasoned about,
// because the details are the ones a test asserts on:
//
//   - The exit status is the last command's, not zero. `false` then end of input exits 1; a
//     bare `exit` does the same; `exit 7` exits 7; `exit 300` exits 44, because the status
//     is one byte on the wire.
//   - State carries across the session, so `cd /system/bin` followed by `pwd` prints
//     `/system/bin`.
//   - With no terminal there is no prompt, exactly as on a device: `printf 'echo one\n' | adb
//     shell` prints one line and nothing else. A prompt there would be a difference every
//     such test would have to work around.
//   - With a terminal there is a prompt, and it tracks the working directory.
//   - End of input ends the session cleanly, and a session that never received a line exits
//     0 rather than failing.
//
// A very long line is not a special case here and is not treated as one: the reader has no
// line-length limit of its own, so a 200KB argument behaves like a short one. What could
// break framing is on the transport side, and the v2 decoder accumulates a frame across
// packets for exactly that reason.

// maxInteractiveLine bounds how much one line may grow to.
//
// Not a limit on what the host may send -- a real session has none, and imposing one would
// make the mock fail a case a device handles. It bounds a single buffer so a peer that never
// sends a newline cannot make the mock allocate without limit. Past it the rest of the line
// is treated as the next line, which keeps the session alive and bounded rather than turning
// a long argument into a hang.
//
// 1 MiB is far beyond any plausible command line and comfortably inside maxPayload, so a
// line this long still fits one v2 frame.
const maxInteractiveLine = 1 << 20

// runInteractive serves one session and returns the status to report for it.
func runInteractive(fs *VFS, s *stream, opts serviceOpts) int {
	// One runner for the whole session. This is what makes `cd` in one line visible to the
	// next, and the reason a session is not a loop of runOneShot.
	runner := newShellRunnerFor(fs)

	if opts.pty {
		if code, ok := runInteractiveTerminal(s, runner); ok {
			return code
		}
		// No terminal could be allocated. Fall through to the pipe session rather than
		// failing the request, because a working session beats an error and the message on
		// stderr says what happened. A test that needs a terminal asserts on the prompt and
		// fails here, which is the honest failure.
	}
	return runInteractivePipe(s, runner)
}

// runInteractiveTerminal serves a session with a real terminal behind it, and reports
// whether it managed to.
//
// The shape mirrors what a device does. The interpreter's stdin and stdout are the slave end
// of a pty; the host's bytes are written to the master; everything the terminal produces is
// read back from the master and forwarded to the host. The echo of typed input and the \r
// before each \n are therefore the kernel's, not this file's, which is why the output matches
// a device without anything here adding a carriage return of its own.
func runInteractiveTerminal(s *stream, runner *shellRunner) (int, bool) {
	term, err := openPTY()
	if err != nil {
		fmt.Fprintf(s.stderr(), "mockadbd: %v; running without a terminal\n", err)
		return 0, false
	}
	defer term.Close()

	// A size before any window size frame arrives, so the session has a terminal with a
	// plausible size rather than a 0x0 one. A real pty starts at 0x0 and adb corrects that
	// within the first packet; the default is what makes `stty size` assertable when the
	// host never sends one.
	if err := term.resize(24, 80); err != nil {
		fmt.Fprintf(s.stderr(), "mockadbd: pty window: %v\n", err)
	}
	s.onWindowSize = func(payload []byte) {
		rows, cols, ok := parseWindowSize(payload)
		if !ok {
			// Refused rather than applied: a size decoded from a payload that is not a size
			// is a number from nowhere, and this is the only place it would be used.
			tracef("window size frame not understood (%d bytes)", len(payload))
			return
		}
		if err := term.resize(rows, cols); err != nil {
			tracef("pty resize to %dx%d failed: %v", cols, rows, err)
		}
	}
	defer func() { s.onWindowSize = nil }()

	// Output. The terminal's output is read from the master, and echoed input comes back
	// with it because the terminal wrote that to the master too.
	outDone := make(chan struct{})
	go func() {
		defer close(outDone)
		_, _ = io.Copy(s.stdout(), term.master)
	}()

	// Input. The host's bytes go to the master, where the terminal echoes them and buffers
	// them until a newline. A goroutine because the interpreter reads the slave, and a
	// terminal's two directions are separate queues.
	inDone := make(chan struct{})
	go func() {
		defer close(inDone)
		_, _ = io.Copy(term.master, s)
		// End of the host's input. VEOF is how a terminal is told: the next read on the
		// slave returns end of file, which is what ends the session. Without it the session
		// waits forever for a line that is never coming.
		_, _ = term.master.Write([]byte{4})
	}()

	// The slave is the interpreter's stdin and its stdout both, because on a terminal that
	// is what they are.
	code := serveLines(runner, term.slave, term.slave, term.slave, term.slave)

	// Tear down, in this order and for these reasons.
	//
	// The input pump is reading the transport, and a client that has not closed its end leaves
	// that read waiting forever. setEOF ends it: it is a local condition, closes no packets, and
	// is exactly what the pump would have seen had the client closed stdin.
	//
	// A write already in progress is not unblocked by that. The terminal's input queue is
	// bounded, so a host that keeps typing while the session ends leaves the pump blocked inside
	// a write. Closing the slave unblocks it, because the master reports EIO once every slave is
	// gone.
	//
	// Closing the slave flushes as well. Anything the terminal still holds is delivered to the
	// master, which the output pump forwards, and only then does the master's read report end of
	// input. That is why the slave is closed and the master is not: closing the master first
	// would discard output the host has not received.
	s.setEOF()
	_ = term.slave.Close()
	<-inDone
	<-outDone
	_ = term.master.Close()
	return code, true
}

// runInteractivePipe serves a session with no terminal, which is what both `adb shell` and
// `adb shell -T` get on a real device.
func runInteractivePipe(s *stream, runner *shellRunner) int {
	return serveLines(runner, s, s.stdout(), s.stderr(), nil)
}

// serveLines is the session loop: read a line, run it, write what it produced, repeat.
//
// term is the terminal the session reads from and, when it is not nil, the place a prompt
// and a command's output go. It is nil for a pipe session, which reads the transport and
// writes frames. A terminal's stderr is the same place its stdout goes, which is why there
// is no separate error stream here rather than one being dropped.
func serveLines(runner *shellRunner, in io.Reader, out, errOut io.Writer, term io.Writer) int {
	br, ok := in.(*bufio.Reader)
	if !ok {
		br = bufio.NewReaderSize(in, 64<<10)
	}

	for {
		if term != nil {
			// Written to the terminal rather than to out, so it travels the same path command
			// output does and picks up the same line-ending handling.
			if _, err := io.WriteString(term, runner.prompt()); err != nil {
				return runner.last
			}
		}

		line, err := readLine(br)
		if err != nil {
			// End of input, or the stream went away. Either way the session is over and the
			// last command's status is the answer.
			return runner.last
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			// A blank line runs nothing and reports nothing, as on a device.
			continue
		}
		// A line starting with '#' is a comment, which is what makes a script fed to
		// `adb shell` readable at all.
		if strings.HasPrefix(trimmed, "#") {
			continue
		}

		runner.run(splitArgv(trimmed), emptyReader{}, out, errOut)
		if runner.exited {
			return runner.exitCode
		}
	}
}

// readLine reads one line, without a length limit of its own.
//
// bufio.Reader.ReadString is what makes that possible: it grows as it reads, so a 200KB
// argument arrives in one piece. A fixed-size read would fail there, and the failure mode of
// getting it wrong is a session returning an error where a device prints the output.
//
// The cap is applied afterwards, once, so it can be explained and bounded rather than being a
// side effect of a buffer size nobody chose deliberately. Past it the line is truncated: the
// session stays alive and bounded, which is the pair of properties worth having, and a line
// that long is not something a device runs either.
func readLine(br *bufio.Reader) (string, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		// Whatever arrived before the error is still a line. A host that sends "echo hi" with
		// no trailing newline gets it run, exactly as a device runs the last line of a script
		// that does not end in one.
		if line == "" {
			return "", err
		}
		return truncateLine(line), nil
	}
	return truncateLine(line), nil
}

// truncateLine drops the line ending and enforces the cap.
//
// Also drops a trailing NUL. A pty in canonical mode is not the only thing feeding these lines,
// and a NUL at the end of a line is one a peer can send and one a device's shell discards
// silently; keeping it would make a path argument end in a byte no test message would render.
func truncateLine(line string) string {
	line = strings.TrimRight(line, "\n")
	// A carriage return is dropped too. A host's line ending arriving as CRLF is a real
	// possibility -- a pty's echo of a newline is CRLF, so a terminal session reads back its
	// own echoes -- and leaving it in would make a path argument end in "\r", which is a
	// confusing way to fail.
	line = strings.TrimRight(line, "\r")
	line = strings.TrimRight(line, "\x00")
	if len(line) > maxInteractiveLine {
		line = line[:maxInteractiveLine]
	}
	return line
}

// emptyReader is stdin for a command inside a session.
//
// A command that reads stdin in an interactive session gets end of input immediately rather
// than the rest of the session's lines, and that is deliberate. The session owns stdin: the
// lines arriving there are commands, and handing them to `cat` would mean `cat` swallowed
// the rest of the script and no further command could ever run. On a device `cat` in a
// session gets the terminal and returns when it reaches end of input; here it returns at
// once. A `cat` that wants a script's contents is `adb shell cat file`, which reads the
// filesystem and is what a test should use.
type emptyReader struct{}

func (emptyReader) Read([]byte) (int, error) { return 0, io.EOF }

// stdout wraps a stream as an io.Writer that frames bytes as kIdStdout.
func (s *stream) stdout() io.Writer {
	return &frameWriter{id: v2Stdout, s: s}
}

// stderr routes a command's diagnostics to the host's stderr.
//
// Under v2 that is the kIdStderr frame, which is what lets a test separate the two streams.
// Under the original shell protocol there is no such frame, so stderr is merged into stdout,
// which is the only thing a session can do there and what a real adbd does too.
func (s *stream) stderr() io.Writer {
	if !s.v2 {
		return s.stdout()
	}
	return &frameWriter{id: v2Stderr, s: s}
}

// frameWriter sends everything written to it as one kind of v2 frame.
//
// The lock is per writer, and each call to stdout() or stderr() returns a new one, so it
// serialises a single direction rather than the pair. That is enough: the transport takes
// its own lock for the whole packet, so two writers of different frame ids cannot interleave
// a packet, and two writers of the same id cannot exist.
type frameWriter struct {
	id byte
	s  *stream
	mu sync.Mutex
}

func (w *frameWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.s.writeFrame(w.id, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

var (
	_ io.Writer = (*frameWriter)(nil)
	_ io.Reader = emptyReader{}
)
