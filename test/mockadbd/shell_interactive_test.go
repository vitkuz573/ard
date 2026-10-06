package mockadbd_test

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vitkuz573/ard/test/mockadbd"
)

// `adb shell` with no command.
//
// This is the case that used to answer "shell: empty command" and exit 1: the service
// request carried no argument, one empty command was run, and the stream closed. A relay
// hands an operator a stream and the operator types several things into it, so the whole
// shape was untestable.
//
// Every expectation here was taken from a real device rather than reasoned about, because
// the details are exactly the ones a test asserts on and the differences between a pipe and
// a terminal are not guessable.

// feedShell runs `adb shell` with no command, writing script to its stdin.
//
// extraArg is inserted before the (absent) command, so it is a flag: "-T", "-t", "-tt".
//
// A real file rather than a pipe, for the reason TestInteropStdinRoundTrip documents:
// os/exec feeds a non-file stdin from a goroutine that does not report the end of the write
// side, so adb never learns that input is over and the session never ends. Redirecting from
// a file closes correctly.
//
// The context-free shape here is deliberate. A session that hangs is a test that hangs, and
// the whole point of the feature is that many commands survive one invocation, so every test
// gets a deadline.
func feedShell(t *testing.T, serial, extraArg, script string) (string, string, int) {
	t.Helper()
	adb := requireAdb(t)
	return feedShellAdb(t, adb, serial, extraArg, script)
}

func feedShellAdb(t *testing.T, adb, serial, extraArg, script string) (string, string, int) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "script")
	if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
		t.Fatalf("write script: %v", err)
	}
	in, err := os.Open(path)
	if err != nil {
		t.Fatalf("open script: %v", err)
	}
	defer in.Close()

	args := []string{"-s", serial, "shell"}
	if extraArg != "" {
		args = append(args, extraArg)
	}
	cmd := adbCmd(t, adb, args...)
	cmd.Stdin = in
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr

	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		t.Fatalf("adb shell: %v", err)
	}
	go func() { done <- cmd.Wait() }()

	select {
	case err := <-done:
		code := 0
		if err != nil {
			var ee *exec.ExitError
			if !errors.As(err, &ee) {
				t.Fatalf("adb shell: %v (stdout %q stderr %q)", err, stdout.String(), stderr.String())
			}
			code = ee.ExitCode()
		}
		return stdout.String(), stderr.String(), code
	case <-time.After(20 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatalf("adb shell hung; got stdout %q stderr %q", stdout.String(), stderr.String())
		return "", "", 0
	}
}

// Several commands in one invocation, and no command in between them.
//
// This is the bug in one test: before, the second command never ran because the session
// closed after the first.
func TestInteropShellRunsEveryLineInOneSession(t *testing.T) {
	serial, _ := connectMock(t)

	out, _, code := feedShell(t, serial, "",
		"echo one\necho two\necho three\n")
	if code != 0 {
		t.Errorf("session exited %d, want 0", code)
	}
	for _, want := range []string{"one", "two", "three"} {
		if !strings.Contains(out, want) {
			t.Errorf("output does not contain %q:\n%s", want, out)
		}
	}
	// The exact text matters as much as the presence: a session that printed each line twice,
	// or with the commands echoed into the output, would pass a Contains check and be wrong.
	if got := strings.TrimSpace(out); got != "one\ntwo\nthree" {
		t.Errorf("session output is %q, want %q", got, "one\ntwo\nthree")
	}
}

// Many commands in one invocation.
//
// Ten, because the failure this guards against is a per-session resource that runs out: a
// stream slot, a goroutine, a buffer. Three commands would not notice any of those.
func TestInteropShellSurvivesManyCommands(t *testing.T) {
	serial, _ := connectMock(t)

	var script strings.Builder
	for i := 0; i < 10; i++ {
		script.WriteString("echo line")
		script.WriteString(string(rune('a' + i)))
		script.WriteString("\n")
	}
	out, _, code := feedShell(t, serial, "", script.String())
	if code != 0 {
		t.Errorf("session exited %d, want 0", code)
	}
	for i := 0; i < 10; i++ {
		want := "line" + string(rune('a'+i))
		if !strings.Contains(out, want) {
			t.Errorf("output is missing %q:\n%s", want, out)
		}
	}
}

// State carries across the lines of one session, which is the difference between a session
// and ten separate invocations.
func TestInteropShellSessionStateCarries(t *testing.T) {
	serial, _ := connectMock(t)

	out, _, code := feedShell(t, serial, "", "cd /system/bin\npwd\n")
	if code != 0 {
		t.Errorf("session exited %d, want 0", code)
	}
	if !strings.Contains(out, "/system/bin") {
		t.Errorf("pwd after cd in the same session did not report the new directory:\n%s", out)
	}
	// And the contrast: a second invocation starts fresh, as a separate process would.
	out, _, _ = feedShell(t, serial, "", "pwd\n")
	if got := strings.TrimSpace(out); got != "/" {
		t.Errorf("a new session started in %q, want /", got)
	}
}

// The exit status is the last command's.
//
// Every exit status here was checked against a device. They are not guesses: 127 and 1 both
// come back on a real device for the two commands below, and a session that reported 0 for
// both would hide every failure a relay test is trying to see.
func TestInteropShellSessionExitStatus(t *testing.T) {
	serial, _ := connectMock(t)

	cases := []struct {
		name   string
		script string
		want   int
	}{
		{"a failing last command", "echo one\nfalse\n", 1},
		{"an unknown last command", "echo one\nnosuchcommand\n", 127},
		{"exit with a status", "echo one\nexit 7\n", 7},
		{"exit alone after a failure", "false\nexit\n", 1},
		{"all succeeding", "echo one\ntrue\n", 0},
		{"no commands at all", "", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _, code := feedShell(t, serial, "", c.script)
			if code != c.want {
				t.Errorf("session %q exited %d, want %d", c.script, code, c.want)
			}
		})
	}
}

// End of input ends the session, and it ends it cleanly rather than as an error.
//
// The distinction is worth a test on its own: a session that exited 0 when the input ran out
// and a session that hung both look plausible from the outside, and only one of them is what
// a device does.
func TestInteropShellEndOfInputEndsTheSession(t *testing.T) {
	serial, _ := connectMock(t)

	out, _, code := feedShell(t, serial, "", "echo one\necho two\n")
	if code != 0 {
		t.Errorf("a session that ran to the end of its input exited %d, want 0", code)
	}
	if got := strings.TrimSpace(out); got != "one\ntwo" {
		t.Errorf("output is %q, want %q", got, "one\ntwo")
	}
	// feedShell kills the process if it has not exited, so reaching here at all is the
	// assertion that it did.
}

// The device is usable afterwards.
//
// A session that wedged the transport would satisfy every test above on the first run and
// fail every one after it, because the next command would never be answered. Running a fresh
// session afterwards is what catches that, and it is the failure mode most likely to be
// introduced by whatever the session does at teardown.
func TestInteropShellDeviceWorksAfterASession(t *testing.T) {
	serial, _ := connectMock(t)

	if _, _, code := feedShell(t, serial, "", "echo one\nexit\n"); code != 0 {
		t.Fatalf("first session exited %d", code)
	}
	// Several times, because the teardown resources a session leaks are cumulative.
	for i := 0; i < 3; i++ {
		out, _, code := feedShell(t, serial, "", "echo again\nexit\n")
		if code != 0 {
			t.Fatalf("session %d after another exited %d", i, code)
		}
		if !strings.Contains(out, "again") {
			t.Fatalf("session %d did not run its command:\n%s", i, out)
		}
	}
}

// A client that disconnects mid-session must not take the device with it.
//
// The client here is killed while the session is open, which is what a relay does when its
// operator goes away or when the process is restarted under a supervisor. What matters is
// afterwards: the transport has to still be usable, and the device must not be accumulating
// goroutines for sessions nobody is reading.
func TestInteropShellDisconnectMidSessionLeavesTheDeviceUsable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("process signals differ on windows")
	}
	adb := requireAdb(t)
	serial, _ := connectMock(t)

	path := filepath.Join(t.TempDir(), "never-finishes")
	// A line that runs long enough to still be running when the client dies, and a command
	// after it so the session has somewhere to be.
	if err := os.WriteFile(path, []byte("sleep 3\necho unreached\n"), 0o600); err != nil {
		t.Fatalf("write script: %v", err)
	}
	in, err := os.Open(path)
	if err != nil {
		t.Fatalf("open script: %v", err)
	}
	defer in.Close()

	cmd := adbCmd(t, adb, "-s", serial, "shell")
	cmd.Stdin = in
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	// Wait until the device has the session and the prompt's worth of output, so the kill
	// lands on a live session rather than on a connection still being set up.
	time.Sleep(700 * time.Millisecond)
	if err := cmd.Process.Kill(); err != nil {
		t.Fatalf("kill: %v", err)
	}
	_ = cmd.Wait()

	// The next session is the assertion. A transport left wedged by the disconnect fails
	// here, and fails by hanging rather than by returning an error.
	out, _, code := feedShell(t, serial, "", "echo after-disconnect\nexit\n")
	if code != 0 {
		t.Errorf("session after a mid-session disconnect exited %d, want 0", code)
	}
	if !strings.Contains(out, "after-disconnect") {
		t.Errorf("session after a disconnect did not run its command:\n%s", out)
	}
}

// Repeated mid-session disconnects must not accumulate goroutines on the device.
//
// One disconnect leaking a goroutine is invisible. Twenty is not: the mock runs in the test
// binary, so the count is observable, and a leak here is what a relay under load would hit as
// steadily rising memory rather than as a failure.
func TestInteropShellRepeatedDisconnectsDoNotLeakGoroutines(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("process signals differ on windows")
	}
	if testing.Short() {
		t.Skip("goroutine counting needs a quiet moment to settle")
	}
	adb := requireAdb(t)

	// A listener of its own, so the goroutine count belongs to this test alone: the mock runs
	// in this binary alongside every other test, and a shared one would make the before and
	// after numbers meaningless.
	l, err := mockadbd.Listen("127.0.0.1:0", mockadbd.Config{})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()
	startPrivateServer(t, adb)
	serial := l.Addr().String()
	if out, err := adbCmd(t, adb, "connect", serial).CombinedOutput(); err != nil {
		t.Fatalf("adb connect: %v\n%s", err, out)
	}
	waitForState(t, adb, serial, "device")

	disconnect := func() {
		path := filepath.Join(t.TempDir(), "script")
		if err := os.WriteFile(path, []byte("sleep 2\n"), 0o600); err != nil {
			t.Fatalf("write script: %v", err)
		}
		in, err := os.Open(path)
		if err != nil {
			t.Fatalf("open script: %v", err)
		}
		defer in.Close()
		cmd := adbCmd(t, adb, "-s", serial, "shell")
		cmd.Stdin = in
		if err := cmd.Start(); err != nil {
			t.Fatalf("start: %v", err)
		}
		time.Sleep(150 * time.Millisecond)
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}

	// Warm up first: the first session of any kind allocates, and connection setup is not what
	// is being measured.
	disconnect()
	time.Sleep(2 * time.Second)
	before := runtime.NumGoroutine()

	const sessions = 20
	for i := 0; i < sessions; i++ {
		disconnect()
	}
	// The sessions that were killed leave a `sleep` goroutine behind briefly, so the count is
	// taken after they have finished rather than immediately.
	time.Sleep(4 * time.Second)
	after := runtime.NumGoroutine()

	if after > before+4 {
		buf := make([]byte, 1<<16)
		n := runtime.Stack(buf, true)
		t.Errorf("goroutines went from %d to %d over %d killed sessions; stacks:\n%s",
			before, after, sessions, buf[:n])
	}
}

// -T asks for no terminal, and gets a pipe: the same session, with no prompt and no echo.
//
// The prompt's absence is the point of asserting. A device prints no prompt without a
// terminal, and a mock that printed one anyway would make every plain `adb shell` assertion in
// this suite carry a surprise.
func TestInteropShellDashTNeedsNoTerminal(t *testing.T) {
	serial, _ := connectMock(t)

	out, stderr, code := feedShell(t, serial, "-T", "echo one\necho two\nexit\n")
	if code != 0 {
		t.Errorf("-T session exited %d, want 0", code)
	}
	if got := strings.TrimSpace(out); got != "one\ntwo" {
		t.Errorf("-T output is %q, want %q", got, "one\ntwo")
	}
	if strings.Contains(out, "$") {
		t.Errorf("a session with no terminal printed a prompt:\n%s", out)
	}
	if strings.Contains(out, "one\r") {
		t.Errorf("a session with no terminal produced a carriage return:\n%q", out)
	}
	_ = stderr
}

// -t asks for a terminal.
//
// The client itself refuses a remote terminal when its own stdin is not one -- "Remote PTY will
// not be allocated because stdin is not a terminal" -- so this is really a test of the fallback
// path: the request is still a pty request on the wire, and the session must work.
func TestInteropShellDashTFallsBackWhenStdinIsNotATerminal(t *testing.T) {
	serial, _ := connectMock(t)

	out, stderr, code := feedShell(t, serial, "-t", "echo one\necho two\nexit\n")
	if code != 0 {
		t.Errorf("-t session exited %d, want 0", code)
	}
	if got := strings.TrimSpace(out); got != "one\ntwo" {
		t.Errorf("-t output is %q, want %q", got, "one\ntwo")
	}
	if !strings.Contains(stderr, "not a terminal") {
		t.Logf("adb did not report a pty refusal; stderr was %q", stderr)
	}
}

// -tt forces a terminal even though the client's stdin is a pipe, which is the only way to get
// one out of adb without a real terminal on this side.
//
// What a real device sends back, captured over USB with a pty on the client's side, is a
// prompt, the typed line echoed, and CRLF line endings. All three come from the kernel's line
// discipline rather than from the mock: the echo because the terminal is in echo mode, the
// carriage returns because it has ONLCR set. A mock that wrote "\r" itself would produce the
// same bytes and would be a lie about where they came from.
func TestInteropShellForcedTerminalEchoesAndEndsLinesWithCRLF(t *testing.T) {
	serial, _ := connectMock(t)

	out, _, code := feedShell(t, serial, "-tt", "echo one\nexit\n")
	if code != 0 {
		t.Errorf("forced-terminal session exited %d, want 0", code)
	}

	// A prompt, before the first command. The exact text is the mock's own: a real device
	// prints its own hostname here and this mock must not claim to be one.
	if !strings.Contains(out, "localhost:/ $ ") {
		t.Errorf("no prompt in the terminal session:\n%q", out)
	}
	// The typed line comes back, which is the terminal echoing it.
	if !strings.Contains(out, "echo one\r\n") {
		t.Errorf("the typed line was not echoed with CRLF:\n%q", out)
	}
	// And the command's own output ends lines the same way.
	if !strings.Contains(out, "one\r\n") {
		t.Errorf("command output did not end with CRLF:\n%q", out)
	}
	// A prompt before each command, so two commands means two prompts. Not "ends with a prompt":
	// the session here ends with `exit`, and a shell that has been told to exit prints nothing
	// more. That was checked on a device, where `exit` as the last line likewise leaves the
	// echoed `exit` as the last thing on the wire.
	if got := strings.Count(out, "localhost:/ $ "); got != 2 {
		t.Errorf("saw %d prompts for 2 commands, want 2:\n%q", got, out)
	}
}

// The terminal's own state is a working directory that follows the session, so the prompt
// tracks it.
func TestInteropShellTerminalPromptFollowsTheWorkingDirectory(t *testing.T) {
	serial, _ := connectMock(t)

	out, _, code := feedShell(t, serial, "-tt", "cd /system/bin\nexit\n")
	if code != 0 {
		t.Errorf("forced-terminal session exited %d, want 0", code)
	}
	if !strings.Contains(out, "localhost:/system/bin $ ") {
		t.Errorf("the prompt did not follow cd:\n%q", out)
	}
}

// The exit status survives a terminal session, which is where it is easiest to lose: the
// terminal is a second stream with its own teardown.
func TestInteropShellTerminalSessionExitStatus(t *testing.T) {
	serial, _ := connectMock(t)

	_, _, code := feedShell(t, serial, "-tt", "echo one\nfalse\nexit\n")
	if code != 1 {
		t.Errorf("terminal session with a failing command exited %d, want 1", code)
	}
}

// A terminal session ends on `exit` even though the input has not run out.
//
// The distinction from the pipe case matters and was checked on a device: with a terminal, a
// device's shell ignores end of input and waits, because its input is a terminal and end of
// input is not a thing a terminal has. `exit` is the way out. The mock therefore does not treat
// end of input as the end of a terminal session, and this test asserts that `exit` is what
// ends it.
func TestInteropShellTerminalExitEndsTheSession(t *testing.T) {
	serial, _ := connectMock(t)

	out, _, code := feedShell(t, serial, "-tt", "echo one\nexit 3\n")
	if code != 3 {
		t.Errorf("terminal session exited %d, want 3", code)
	}
	if !strings.Contains(out, "one\r\n") {
		t.Errorf("output before exit was lost:\n%q", out)
	}
}

// A line longer than any terminal line buffer must not break the framing.
//
// Two things are asserted. The command runs, so the long line arrived intact. And the session
// survives it, so the frames around it were still decoded afterwards: a truncated frame would
// leave the decoder mid-stream and everything after the long line would be garbage.
func TestInteropShellVeryLongLineDoesNotBreakFraming(t *testing.T) {
	serial, _ := connectMock(t)

	const size = 200 * 1024
	long := strings.Repeat("x", size)
	out, _, code := feedShell(t, serial, "",
		"echo "+long+"\necho after-the-long-line\nexit\n")
	if code != 0 {
		t.Errorf("session with a %d-byte line exited %d, want 0", size, code)
	}
	if !strings.Contains(out, strings.Repeat("x", 1000)) {
		t.Errorf("the long line's output is missing or truncated; got %d bytes of output", len(out))
	}
	if !strings.Contains(out, "after-the-long-line") {
		t.Errorf("the command after the long line did not run:\n%s", truncate(out))
	}
}

// The same, with a terminal, because the two paths differ: a pty's input queue is small and
// bounded, and a host that fills it is exercising a different piece of the code from a pipe.
func TestInteropShellVeryLongLineThroughATerminal(t *testing.T) {
	serial, _ := connectMock(t)

	const size = 64 * 1024
	long := strings.Repeat("y", size)
	out, _, code := feedShell(t, serial, "-tt", "echo "+long+"\necho after\nexit\n")
	if code != 0 {
		t.Errorf("terminal session with a %d-byte line exited %d, want 0", size, code)
	}
	if !strings.Contains(out, "after\r\n") {
		t.Errorf("the command after the long line did not run through a terminal:\n%s", truncate(out))
	}
}

// Blank lines and comments run nothing, and do not stop the session.
//
// Both were checked on a device: a script of nothing but blank lines exits 0, and a `#` line is
// a comment rather than an unknown command. A mock that reported 127 for a comment would make
// every commented script fail.
func TestInteropShellBlankLinesAndComments(t *testing.T) {
	serial, _ := connectMock(t)

	out, stderr, code := feedShell(t, serial, "", "\n   \n# a comment\n#another\necho after\n")
	if code != 0 {
		t.Errorf("session exited %d, want 0 (stderr %q)", code, stderr)
	}
	if got := strings.TrimSpace(out); got != "after" {
		t.Errorf("output is %q, want %q", got, "after")
	}
	if strings.Contains(stderr, "command not found") {
		t.Errorf("a comment was treated as a command:\n%s", stderr)
	}
}

// The output of a session's failing command reaches stderr, not stdout, because a test that
// captures only stdout would otherwise see a session that looks clean.
func TestInteropShellSessionSeparatesStderr(t *testing.T) {
	serial, _ := connectMock(t)

	stdout, stderr, code := feedShell(t, serial, "", "echo out-there\nnosuchcommand\n")
	if code != 127 {
		t.Errorf("session exited %d, want 127", code)
	}
	if !strings.Contains(stdout, "out-there") {
		t.Errorf("stdout is missing the successful command's output:\n%s", stdout)
	}
	if strings.Contains(stdout, "command not found") {
		t.Errorf("the failure message went to stdout:\n%s", stdout)
	}
	if !strings.Contains(stderr, "command not found") {
		t.Errorf("stderr is missing the failure message:\n%s", stderr)
	}
}

// A session's command output arrives as the session runs, not in one lump at the end.
//
// A relay streams this to an operator, so output that only appears when the session ends is
// output an operator cannot see. The check is indirect because it cannot be done with a single
// `adb shell` invocation: it feeds one line, checks that its output has arrived while the
// session is still open, then feeds the next.
func TestInteropShellOutputArrivesWhileTheSessionIsOpen(t *testing.T) {
	adb := requireAdb(t)
	serial, _ := connectMock(t)

	// The ends, named for what they are: the read end is what the client reads its input from, and
	// the write end is what the test writes the script to.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer r.Close()

	cmd := adbCmd(t, adb, "-s", serial, "shell")
	// A pipe, not a file, because the session has to stay open between the two writes. The end
	// of the write side is closed explicitly below, which is what makes adb send the frame that
	// ends input.
	cmd.Stdin = r
	var out lockedBuffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	if _, err := w.WriteString("echo streamed\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	if !out.waitFor("streamed", 10*time.Second) {
		_ = cmd.Process.Kill()
		t.Fatalf("output did not arrive while the session was open; got %q", out.String())
	}
	if _, err := w.WriteString("exit\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Closing the write side is what tells adb the input has ended. Without it the session
	// waits, correctly, for a line that is never coming.
	if err := w.Close(); err != nil {
		t.Fatalf("close stdin: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("adb shell: %v (output %q)", err, out.String())
		}
	case <-time.After(20 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatalf("session hung after exit; output %q", out.String())
	}
}

// A device configured with a custom Config.Shell still serves a session.
//
// Config.Shell replaces the interpreter for `adb shell COMMAND`. A session builds its own
// runner so that state carries across lines, and the risk of that is that a device with a
// custom interpreter stops honouring it -- or stops working at all. Asserted from both sides:
// the session runs, and the configured interpreter is still reached for a one-shot command
// afterwards.
func TestInteropShellRunsAgainstACustomConfiguredDevice(t *testing.T) {
	adb := requireAdb(t)

	var mu sync.Mutex
	var served []string
	l, err := mockadbd.Listen("127.0.0.1:0", mockadbd.Config{
		Shell: func(argv []string, stdin io.Reader, stdout, stderr io.Writer) int {
			mu.Lock()
			served = append(served, strings.Join(argv, " "))
			mu.Unlock()
			return 0
		},
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()
	startPrivateServer(t, adb)
	serial := l.Addr().String()
	if out, err := adbCmd(t, adb, "connect", serial).CombinedOutput(); err != nil {
		t.Fatalf("adb connect: %v\n%s", err, out)
	}
	waitForState(t, adb, serial, "device")

	// The session uses the built-in interpreter, which is the only one that can carry state
	// across lines; the output says so.
	out, _, code := feedShellAdb(t, adb, serial, "", "echo one\nexit\n")
	if code != 0 {
		t.Errorf("session on a custom device exited %d, want 0", code)
	}
	if !strings.Contains(out, "one") {
		t.Errorf("the session on a custom device ran nothing:\n%s", out)
	}

	// And a one-shot command still goes through the configured interpreter.
	oneShot := adbCmd(t, adb, "-s", serial, "shell", "served-command")
	if err := oneShot.Run(); err != nil {
		t.Fatalf("one-shot on a custom device: %v", err)
	}
	mu.Lock()
	got := strings.Join(served, "|")
	mu.Unlock()
	if !strings.Contains(got, "served-command") {
		t.Errorf("the configured interpreter did not see the one-shot command; saw %q", got)
	}
}

// lockedBuffer collects a process's output while another goroutine waits on it.
type lockedBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// waitFor waits for text to appear, returning false if it does not within the deadline.
//
// Polling rather than a channel, because what is being waited for is text written by another
// process: there is no point at which a test can be told it has arrived except by looking.
func (b *lockedBuffer) waitFor(want string, within time.Duration) bool {
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if strings.Contains(b.String(), want) {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

// truncate keeps a failure message readable.
func truncate(s string) string {
	const limit = 400
	if len(s) <= limit {
		return s
	}
	return s[:limit] + "\n... (truncated)"
}
