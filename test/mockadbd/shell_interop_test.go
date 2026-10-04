package mockadbd_test

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// shell runs one command on the mock device and returns stdout, stderr and the status.
//
// The status is returned rather than asserted inside the helper, because a test that
// cannot see it would have to choose between checking output and checking the exit code,
// and both matter.
func shell(t *testing.T, serial, command string) (string, string, int) {
	t.Helper()
	adb := requireAdb(t)
	cmd := adbCmd(t, adb, "-s", serial, "shell", command)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("adb shell %q: %v", command, err)
		}
		// The status is the whole point of several of these commands, so it is read out
		// rather than treated as a failure.
		code = ee.ExitCode()
	}
	return stdout.String(), stderr.String(), code
}

// The filesystem has to be visible from a shell, or it is only reachable through a push,
// and a relay test that writes a file and then looks at it would have no way to check.
func TestShellListsTheSeededTree(t *testing.T) {
	serial, _ := connectMock(t)

	out, _, code := shell(t, serial, "ls /system")
	if code != 0 {
		t.Fatalf("ls exited %d", code)
	}
	for _, want := range []string{"bin", "etc", "lib"} {
		if !strings.Contains(out, want) {
			t.Errorf("ls /system is missing %q:\n%s", want, out)
		}
	}

	out, _, _ = shell(t, serial, "ls /system/etc")
	if !strings.Contains(out, "hosts") {
		t.Errorf("ls /system/etc is missing the seeded file:\n%s", out)
	}
}

// The long form is what a test reads to learn a size and a mode, so both have to be there
// and in a predictable place.
func TestShellLsLongShowsSizeAndMode(t *testing.T) {
	serial, fs := connectMock(t)
	if err := fs.WriteFile("/data/local/tmp/sized.txt", []byte("0123456789"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	out, _, code := shell(t, serial, "ls -l /data/local/tmp")
	if code != 0 {
		t.Fatalf("ls -l exited %d", code)
	}
	line := ""
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "sized.txt") {
			line = l
		}
	}
	if line == "" {
		t.Fatalf("sized.txt missing from long listing:\n%s", out)
	}
	if !strings.HasPrefix(line, "-rw-r--r--") {
		t.Errorf("long listing shows the wrong mode: %q", line)
	}
	if !strings.Contains(line, "10") {
		t.Errorf("long listing does not show the size: %q", line)
	}
}

// A push writes the tree, so cat has to read what a push wrote. That is the join between
// the sync service and the shell, and it is the reason both exist.
func TestShellCatReadsWhatAPushWrote(t *testing.T) {
	serial, fs := connectMock(t)

	// Push goes through the legacy protocol, so it is written directly here rather than
	// via adb; the point of the test is that cat sees whatever landed in the tree.
	if err := fs.WriteFile("/data/local/tmp/pushed.txt", []byte("from a push\n"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	out, _, code := shell(t, serial, "cat /data/local/tmp/pushed.txt")
	if code != 0 {
		t.Fatalf("cat exited %d", code)
	}
	if strings.TrimSpace(out) != "from a push" {
		t.Fatalf("cat returned %q", out)
	}
}

// Properties are the reason getprop exists, and a test that greps the output needs them to
// be stable and the lookup rules to hold.
func TestShellGetprop(t *testing.T) {
	serial, _ := connectMock(t)

	out, _, code := shell(t, serial, "getprop ro.build.version.sdk")
	if code != 0 {
		t.Fatalf("getprop exited %d", code)
	}
	if strings.TrimSpace(out) != "34" {
		t.Fatalf("getprop returned %q, want 34", out)
	}

	// An unknown property prints nothing and still succeeds, which is what makes
	// `getprop | grep` usable.
	out, _, code = shell(t, serial, "getprop ro.nothing.here")
	if code != 0 {
		t.Fatalf("getprop of an unknown key exited %d, want 0", code)
	}
	if strings.TrimSpace(out) != "" {
		t.Fatalf("getprop of an unknown key printed %q", out)
	}

	// The whole listing has to contain the properties a test looks for.
	out, _, _ = shell(t, serial, "getprop")
	for _, want := range []string{"ro.product.model=", "ro.build.version.release="} {
		if !strings.Contains(out, want) {
			t.Errorf("getprop listing is missing %q", want)
		}
	}
}

func TestShellSetpropIsVisibleToGetprop(t *testing.T) {
	serial, _ := connectMock(t)

	if _, _, code := shell(t, serial, "setprop debug.mock.on 1"); code != 0 {
		t.Fatalf("setprop exited %d", code)
	}
	out, _, _ := shell(t, serial, "getprop debug.mock.on")
	if strings.TrimSpace(out) != "1" {
		t.Fatalf("getprop after setprop returned %q", out)
	}
	// A default is what makes setprop safe in a script: the property is only touched if
	// it is not already set.
	shell(t, serial, "setprop debug.mock.on 2")
	shell(t, serial, "setprop debug.other default")
	out, _, _ = shell(t, serial, "getprop debug.other")
	if strings.TrimSpace(out) != "default" {
		t.Fatalf("getprop with a default returned %q", out)
	}
}

// Exit statuses are load-bearing: a test distinguishes "no such command" from "the command
// failed", and a simulator that returns 0 for everything hides both.
func TestShellExitStatuses(t *testing.T) {
	serial, _ := connectMock(t)

	cases := []struct {
		command string
		want    int
	}{
		{"true", 0},
		{"false", 1},
		{"nosuchcommand", 127},
		{"cat /nothing/here", 1},
		{"ls /nothing/here", 1},
		{"stat /nothing/here", 1},
		{"rm /nothing/here", 1},
		{"mv onlyonearg", 2},
		{"mkdir", 2},
	}
	for _, c := range cases {
		_, _, code := shell(t, serial, c.command)
		if code != c.want {
			t.Errorf("%q exited %d, want %d", c.command, code, c.want)
		}
	}
}

// Filesystem mutation through a shell is how a test sets up and cleans up, and it has to
// survive being wrong.
func TestShellMutatesTheTree(t *testing.T) {
	serial, fs := connectMock(t)

	if _, _, code := shell(t, serial, "mkdir -p /data/local/tmp/a/b/c"); code != 0 {
		t.Fatalf("mkdir -p exited %d", code)
	}
	if !fs.IsDir("/data/local/tmp/a/b/c") {
		t.Fatal("mkdir -p did not create the whole chain")
	}
	// Without -p an existing directory is an error, as it is on a device.
	if _, _, code := shell(t, serial, "mkdir -p /data/local/tmp/a/b/c"); code != 0 {
		t.Fatalf("re-creating with -p exited %d", code)
	}
	if _, _, code := shell(t, serial, "mkdir /data/local/tmp/a/b/c"); code != 1 {
		t.Fatalf("mkdir over an existing directory exited %d, want 1", code)
	}

	if err := fs.WriteFile("/sdcard/m.txt", []byte("body"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, _, code := shell(t, serial, "mv /sdcard/m.txt /sdcard/renamed.txt"); code != 0 {
		t.Fatalf("mv exited %d", code)
	}
	if fs.Exists("/sdcard/m.txt") || !fs.Exists("/sdcard/renamed.txt") {
		t.Fatal("mv did not move the file")
	}

	if _, _, code := shell(t, serial, "cp /sdcard/renamed.txt /sdcard/copied.txt"); code != 0 {
		t.Fatalf("cp exited %d", code)
	}
	if got, err := fs.ReadFile("/sdcard/copied.txt"); err != nil || string(got) != "body" {
		t.Fatalf("cp produced %q, %v", got, err)
	}

	// rm without -r refuses a populated directory, and with -r removes it.
	if err := fs.WriteFile("/data/local/tmp/a/b/c/f", []byte("x"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, _, code := shell(t, serial, "rm /data/local/tmp/a"); code == 0 {
		t.Error("rm removed a populated directory without -r")
	}
	if _, _, code := shell(t, serial, "rm -r /data/local/tmp/a"); code != 0 {
		t.Errorf("rm -r exited %d", code)
	}
	if fs.Exists("/data/local/tmp/a") {
		t.Error("rm -r left the directory")
	}
}

// cd changes the session's working directory, so a relative path in a following command
// resolves against it.
func TestShellCdResolvesRelativePaths(t *testing.T) {
	serial, fs := connectMock(t)
	if err := fs.WriteFile("/data/local/tmp/rel.txt", []byte("relative"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Each adb shell is its own process, so the working directory cannot carry across
	// invocations -- and pretending otherwise would make a test pass that cannot work on
	// a real device. Assert that instead of a false promise.
	if _, _, code := shell(t, serial, "cd /data/local/tmp"); code != 0 {
		t.Fatalf("cd exited %d", code)
	}
	out, _, _ := shell(t, serial, "pwd")
	if strings.TrimSpace(out) != "/" {
		t.Fatalf("pwd after a separate cd invocation is %q; a shell session must not "+
			"pretend to remember", strings.TrimSpace(out))
	}
	// But cd into a missing directory has to fail.
	if _, _, code := shell(t, serial, "cd /nowhere"); code != 1 {
		t.Fatalf("cd into a missing directory exited %d, want 1", code)
	}
}

// The fixed-process listing is what makes ps assertable; a test that greps for a process
// needs the same answer twice.
func TestShellPsIsStable(t *testing.T) {
	serial, _ := connectMock(t)
	first, _, code := shell(t, serial, "ps")
	if code != 0 {
		t.Fatalf("ps exited %d", code)
	}
	second, _, _ := shell(t, serial, "ps")
	if first != second {
		t.Fatal("ps output differs between runs, so nothing can be asserted against it")
	}
	if !strings.Contains(first, "PID") || !strings.Contains(first, "adbd") {
		t.Fatalf("ps output does not look like a process table:\n%s", first)
	}
}

func TestShellReportsDiskAndIdentity(t *testing.T) {
	serial, _ := connectMock(t)

	out, _, code := shell(t, serial, "df")
	if code != 0 {
		t.Fatalf("df exited %d", code)
	}
	if !strings.Contains(out, "Filesystem") || !strings.Contains(out, "/") {
		t.Errorf("df output is not recognisable:\n%s", out)
	}

	out, _, _ = shell(t, serial, "id")
	if !strings.Contains(out, "uid=0(root)") {
		t.Errorf("id output = %q", out)
	}
	out, _, _ = shell(t, serial, "whoami")
	if strings.TrimSpace(out) != "shell" {
		t.Errorf("whoami = %q", out)
	}
	out, _, _ = shell(t, serial, "uname -a")
	if !strings.Contains(out, "android") {
		t.Errorf("uname -a = %q", out)
	}
}

// stdin must still work, because that is how a relay test checks the reverse direction.
func TestShellCatReadsStdin(t *testing.T) {
	serial, _ := connectMock(t)
	adb := requireAdb(t)

	f := filepath.Join(t.TempDir(), "in")
	if err := os.WriteFile(f, []byte("through-stdin"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cmd := adbCmd(t, adb, "-s", serial, "shell", "cat")
	cmd.Stdin, _ = os.Open(f)
	var out strings.Builder
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("adb shell cat: %v", err)
	}
	if strings.TrimSpace(out.String()) != "through-stdin" {
		t.Fatalf("cat from stdin returned %q", out.String())
	}
}

// stat has to describe something, and du has to add something up, or they are decoration.
func TestShellStatAndDu(t *testing.T) {
	serial, fs := connectMock(t)
	if err := fs.WriteFile("/data/local/tmp/f", []byte("0123456789"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	out, _, code := shell(t, serial, "stat /data/local/tmp/f")
	if code != 0 {
		t.Fatalf("stat exited %d", code)
	}
	if !strings.Contains(out, "Size: 10") {
		t.Errorf("stat does not report the size:\n%s", out)
	}
	if !strings.Contains(out, "regular file") {
		t.Errorf("stat does not report the type:\n%s", out)
	}
	if !strings.Contains(out, "-rw-------") {
		t.Errorf("stat does not report the mode:\n%s", out)
	}

	out, _, code = shell(t, serial, "du /data/local/tmp")
	if code != 0 {
		t.Fatalf("du exited %d", code)
	}
	if !strings.Contains(out, "/data/local/tmp") {
		t.Errorf("du output = %q", out)
	}
}
