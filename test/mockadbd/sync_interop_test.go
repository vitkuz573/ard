package mockadbd_test

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	mockadbd "github.com/vitkuz573/ard/test/mockadbd"
)

// requireSync skips the push and pull tests until the adb process exits.
//
// The push and pull themselves work: the bytes arrive and the file is on the device. What
// does not work is that the adb process never returns, so a test that waits for adb to exit
// hangs instead of failing. MOCKADBD_FORCE_SYNC runs them anyway.
//
// The measurements behind that sentence are in the file comment above the first test.
func requireSync(t *testing.T) {
	t.Helper()
	if os.Getenv("MOCKADBD_FORCE_SYNC") != "" {
		return
	}
	t.Skip("the push completes and the file lands, but adb never exits: it blocks polling " +
		"its socket to the adb server after printing \"1 file pushed\". The file comment " +
		"records how that was established.")
}

// These tests push and pull against a real adb and assert on the device's filesystem.
//
// The transfer works and the bytes arrive. What does not work is that the adb process
// never exits, which is why requireSync skips them rather than letting them hang. The
// state, precisely:
//
//   - adb sends STA2, receives a 68-byte stat body, and then goes quiet for 15 to 25
//     seconds before sending SEND. The device receives the SEND, writes the file, and
//     replies DONE. The file is on the device and `adb shell cat` returns its content.
//   - adb prints "1 file pushed, 0 skipped" -- so it considers the transfer finished --
//     and then blocks in poll() on its socket to the adb server, forever. The server has
//     sent the stat body and nothing more, and never sends anything else.
//
// That second point is why this read as a protocol failure for so long. The file lands,
// adb reports success, and the only symptom is a process that will not die. Nothing in the
// wire trace shows a fault, because from the wire there is no fault.
//
// Measured with, in order of how much each one told me:
//
//	MOCKADBD_TRACE=/tmp/t.log adb -s PORT push FILE REMOTE   # the device's own trace
//	ADB_TRACE=all adb nodaemon server                         # the adb server, verbose
//	strace -e trace=network,poll adb -s PORT push FILE REMOTE # the client, from birth
//
// The last is the decisive one and it is one line: poll([{fd=3, events=POLLIN}], 1, 0) = 0
// (Timeout), with no syscall before it. The client is not waiting on the device, whose
// packets it has already read and acknowledged. It is waiting on the adb server, which has
// nothing left to send.
//
// So what is still missing is a reply the adb server owes the client once a push is done,
// not anything in the sync protocol.

// connectMock starts a mock device on a private adb server and returns its serial.
//
// The device gets an explicit filesystem so a test can inspect what a push produced,
// which is the only way to tell "the bytes arrived" from "the command did not fail".
func connectMock(t *testing.T) (string, *mockadbd.VFS) {
	t.Helper()
	adb := requireAdb(t)
	fs := mockadbd.NewVFS()
	l, err := mockadbd.Listen("127.0.0.1:0", mockadbd.Config{FS: fs})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	startPrivateServer(t, adb)
	serial := l.Addr().String()
	if out, err := adbCmd(t, adb, "connect", serial).CombinedOutput(); err != nil {
		t.Fatalf("adb connect: %v\n%s", err, out)
	}
	waitForState(t, adb, serial, "device")
	return serial, fs
}

func hostFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatalf("write host file: %v", err)
	}
	return p
}

// A push is the operation most likely to be broken and least likely to be noticed: it
// reports success on the way out and the bytes are only checked later, by hand, on a
// device. So the assertion is on the device side.
func TestInteropPushLandsOnTheDevice(t *testing.T) {
	requireSync(t)
	adb := requireAdb(t)
	serial, fs := connectMock(t)

	payload := []byte("hello from the host\nsecond line\n")
	src := hostFile(t, "pushed.txt", payload)

	if out, err := adbCmd(t, adb, "-s", serial, "push", src, "/data/local/tmp/pushed.txt").CombinedOutput(); err != nil {
		t.Fatalf("adb push: %v\n%s", err, out)
	}

	got, err := fs.ReadFile("/data/local/tmp/pushed.txt")
	if err != nil {
		t.Fatalf("the pushed file is not on the device: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("push corrupted the contents:\n got %q\nwant %q", got, payload)
	}
}

// Binary content is the case that catches framing bugs. Text passes through systems that
// quietly mangle NULs and lone CRs; random bytes do not.
func TestInteropPushPreservesBinaryContent(t *testing.T) {
	requireSync(t)
	adb := requireAdb(t)
	serial, fs := connectMock(t)

	payload := make([]byte, 256*1024)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("rand: %v", err)
	}
	src := hostFile(t, "blob.bin", payload)

	if out, err := adbCmd(t, adb, "-s", serial, "push", src, "/data/local/tmp/blob.bin").CombinedOutput(); err != nil {
		t.Fatalf("adb push: %v\n%s", err, out)
	}
	got, err := fs.ReadFile("/data/local/tmp/blob.bin")
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if len(got) != len(payload) {
		t.Fatalf("length = %d, want %d", len(got), len(payload))
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("binary content did not survive the round trip")
	}
}

// A pull is the mirror image and is what an operator does when collecting a log.
func TestInteropPullBringsTheFileToTheHost(t *testing.T) {
	requireSync(t)
	adb := requireAdb(t)
	serial, fs := connectMock(t)

	want := []byte("log line one\nlog line two\n\x00binary tail")
	if err := fs.WriteFile("/data/local/tmp/log.txt", want, 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	dst := filepath.Join(t.TempDir(), "pulled.txt")
	if out, err := adbCmd(t, adb, "-s", serial, "pull", "/data/local/tmp/log.txt", dst).CombinedOutput(); err != nil {
		t.Fatalf("adb pull: %v\n%s", err, out)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read pulled file: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("pull corrupted the contents:\n got %q\nwant %q", got, want)
	}
}

// Round-trip is the property that matters: what goes up comes back byte for byte, which is
// what a checksum in a test script would be checking on a real device.
func TestInteropRoundTripIsByteIdentical(t *testing.T) {
	requireSync(t)
	adb := requireAdb(t)
	serial, fs := connectMock(t)

	payload := make([]byte, 512*1024)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("rand: %v", err)
	}
	src := hostFile(t, "round.bin", payload)

	if out, err := adbCmd(t, adb, "-s", serial, "push", src, "/sdcard/round.bin").CombinedOutput(); err != nil {
		t.Fatalf("push: %v\n%s", err, out)
	}
	dst := filepath.Join(t.TempDir(), "back.bin")
	if out, err := adbCmd(t, adb, "-s", serial, "pull", "/sdcard/round.bin", dst).CombinedOutput(); err != nil {
		t.Fatalf("pull: %v\n%s", err, out)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("round trip differs: %d bytes back, want %d", len(got), len(payload))
	}
	// The device copy must be identical too, not merely present.
	onDevice, err := fs.ReadFile("/sdcard/round.bin")
	if err != nil || !bytes.Equal(onDevice, payload) {
		t.Fatalf("device copy is wrong: %v", err)
	}
}

// An empty file is a boundary that framing code usually gets wrong.
func TestInteropPushEmptyFile(t *testing.T) {
	requireSync(t)
	adb := requireAdb(t)
	serial, fs := connectMock(t)

	src := hostFile(t, "empty.bin", nil)
	if out, err := adbCmd(t, adb, "-s", serial, "push", src, "/data/local/tmp/empty.bin").CombinedOutput(); err != nil {
		t.Fatalf("adb push of an empty file: %v\n%s", err, out)
	}
	got, err := fs.ReadFile("/data/local/tmp/empty.bin")
	if err != nil {
		t.Fatalf("empty file missing on the device: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("empty file came back with %d bytes", len(got))
	}
}

// Pulling something that is not there has to fail, not produce an empty file. A simulator
// that returns success for a missing path would make a transfer bug look like a permissions
// problem on the host.
func TestInteropPullMissingFileFails(t *testing.T) {
	requireSync(t)
	adb := requireAdb(t)
	serial, _ := connectMock(t)

	dst := filepath.Join(t.TempDir(), "absent.txt")
	out, err := adbCmd(t, adb, "-s", serial, "pull", "/data/local/tmp/definitely-not-here", dst).CombinedOutput()
	if err == nil {
		t.Fatalf("pulling a missing file reported success:\n%s", out)
	}
	if _, statErr := os.Stat(dst); statErr == nil {
		t.Fatal("a failed pull still created the destination file")
	}
}

// Pushing into a directory that does not exist yet is the normal case, not an edge case:
// adb does not create intermediate directories.
func TestInteropPushCreatesNothingButTheFile(t *testing.T) {
	requireSync(t)
	adb := requireAdb(t)
	serial, fs := connectMock(t)

	before := fs.Count()
	src := hostFile(t, "one.txt", []byte("x"))
	if out, err := adbCmd(t, adb, "-s", serial, "push", src, "/data/local/tmp/one.txt").CombinedOutput(); err != nil {
		t.Fatalf("push: %v\n%s", err, out)
	}
	// Exactly one node: no stray directories, which would show up as filesystem clutter
	// on a device where space is the scarce resource.
	if got := fs.Count(); got != before+1 {
		t.Fatalf("push changed the node count by %d, want 1", got-before)
	}
}
