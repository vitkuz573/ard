package mockadbd_test

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vitkuz573/ard/test/mockadbd"
)

// These tests drive the real adb binary against the mock device. That is the only
// way to know the mock speaks adbd's dialect rather than merely its own: the
// framing, the service specs and the auth exchange are all implemented by the
// other side, so a mismatch shows up as a hang or a protocol error here instead
// of in production.

const testServerPort = "5038"

// There is deliberately no test for ADB RSA authentication here.
//
// ARD never performs it: the agent reaches a device's adbd over that device's
// loopback interface, and adbd is already authorised to the phone it lives on.
// Authentication is between the adb host and adbd, and in this topology both live
// on the device. Implementing it in the mock would have modelled a path the
// product does not take.

func requireAdb(t *testing.T) string {
	t.Helper()
	adb, err := exec.LookPath("adb")
	if err != nil {
		t.Skip("adb not installed, skipping interop test")
	}
	return adb
}

// adbCmd builds an adb invocation pinned to a private server instance, so tests
// never collide with a developer running adb against a real device.
func adbCmd(t *testing.T, adb string, args ...string) *exec.Cmd {
	t.Helper()
	// adb ignores ADB_SERVER_PORT; the port is selected by -P, and the daemon
	// itself is told via ANDROID_ADB_SERVER_PORT.
	args = append([]string{"-P", testServerPort}, args...)
	cmd := exec.Command(adb, args...)
	cmd.Env = append(os.Environ(), "ANDROID_ADB_SERVER_PORT="+testServerPort)
	return cmd
}

func startPrivateServer(t *testing.T, adb string) {
	t.Helper()
	kill := adbCmd(t, adb, "kill-server")
	_ = kill.Run()
	if out, err := startServerCmd(t, adb).CombinedOutput(); err != nil {
		t.Fatalf("adb start-server: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = adbCmd(t, adb, "kill-server").Run() })
}

func startServerCmd(t *testing.T, adb string) *exec.Cmd {
	return adbCmd(t, adb, "start-server")
}

func TestInteropWithRealAdbNoAuth(t *testing.T) {
	adb := requireAdb(t)
	l, err := mockadbd.Listen("127.0.0.1:0", mockadbd.Config{})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()

	startPrivateServer(t, adb)

	serial := l.Addr().String()
	connect := adbCmd(t, adb, "connect", serial)
	out, err := connect.CombinedOutput()
	if err != nil {
		t.Fatalf("adb connect: %v\n%s", err, out)
	}
	t.Logf("adb connect said: %s", strings.TrimSpace(string(out)))

	// adb connect reports success before the transport is necessarily usable,
	// so wait for the device to leave "offline"/"unauthorized".
	waitForState(t, adb, serial, "device")

	got := runShell(t, adb, serial, "echo hello-from-mock")
	if !strings.Contains(got, "hello-from-mock") {
		t.Fatalf("shell output %q does not contain the echoed text", got)
	}

	devices := run(t, adb, "devices")
	if !strings.Contains(devices, serial) {
		t.Fatalf("adb devices does not list %s:\n%s", serial, devices)
	}
}

// stdin must survive the round trip: a relay that corrupts or reorders the WRTE
// direction breaks every interactive shell and every file push, so this is worth
// asserting separately from simple command output.
func TestInteropStdinRoundTrip(t *testing.T) {
	adb := requireAdb(t)
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

	// Stdin must be an *os.File, not a strings.Reader.
	//
	// os/exec pipes a non-file Stdin from a background goroutine, and adb's
	// shell client does not notice the write side closing. The device therefore
	// never receives kIdCloseStdin, a command reading stdin blocks forever, and
	// the client hangs. Shell redirection from a real file — or from a shell
	// pipeline — closes correctly.
	stdinFile, err := os.CreateTemp(t.TempDir(), "stdin")
	if err != nil {
		t.Fatalf("temp stdin: %v", err)
	}
	if _, err := stdinFile.WriteString("payload-through-stdin"); err != nil {
		t.Fatalf("write stdin: %v", err)
	}
	if _, err := stdinFile.Seek(0, io.SeekStart); err != nil {
		t.Fatalf("rewind stdin: %v", err)
	}
	cmd := adbCmd(t, adb, "-s", serial, "shell", "cat")
	cmd.Stdin = stdinFile
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	done := make(chan error, 1)
	go func() { done <- cmd.Run() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("adb shell cat: %v (output %q)", err, stdout.String())
		}
	case <-time.After(15 * time.Second):
		cmd.Process.Kill()
		t.Fatal("adb shell cat hung")
	}
	if !strings.Contains(stdout.String(), "payload-through-stdin") {
		t.Fatalf("stdin did not reach the device: %q", stdout.String())
	}
}

func TestUnknownCommandReturnsFailure(t *testing.T) {
	adb := requireAdb(t)
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

	cmd := adbCmd(t, adb, "-s", serial, "shell", "definitely-not-a-command")
	out, err := cmd.CombinedOutput()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("unknown command should fail, got err=%v out=%q", err, out)
	}
	if got := exitErr.ExitCode(); got != 127 {
		t.Errorf("exit code = %d, want 127 (output %q)", got, out)
	}
	if !strings.Contains(string(out), "command not found") {
		t.Errorf("stderr should mention the failure, got %q", out)
	}
}

func waitForState(t *testing.T, adb, serial, want string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	var last string
	for time.Now().Before(deadline) {
		out := run(t, adb, "devices")
		last = out
		for _, line := range strings.Split(out, "\n") {
			if !strings.HasPrefix(line, serial) {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[1] == want {
				return
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("device %s never reached state %q; last devices output:\n%s", serial, want, last)
}

func runShell(t *testing.T, adb, serial, shellCmd string) string {
	t.Helper()
	cmd := adbCmd(t, adb, "-s", serial, "shell", shellCmd)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	done := make(chan error, 1)
	go func() { done <- cmd.Run() }()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		cmd.Process.Kill()
		t.Fatalf("adb shell %q hung", shellCmd)
	}
	return stdout.String()
}

func run(t *testing.T, adb string, args ...string) string {
	t.Helper()
	cmd := adbCmd(t, adb, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("adb %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

var _ = sync.Once{}
