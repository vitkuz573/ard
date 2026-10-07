package mockadbd_test

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	mockadbd "github.com/vitkuz573/ard/test/mockadbd"
)

// These tests push and pull against a real adb and assert on the device's filesystem.
//
// Why they used to be skipped, and why they are not any more.
//
// The transfer worked and the bytes arrived, but the adb process never returned, so a test
// that waits for adb hangs rather than fails, and the whole file was skipped for that reason.
// The delay was in the adb server, and it was this repository's fault after all.
//
// The server is not a pipe. It proxies the client's sync socket to the device stream
// through asocket, and local_socket_flush_outgoing() in adb's sockets.cpp stops reading the
// client as soon as it has forwarded a chunk: it deletes FDE_READ and waits. Only
// local_socket_ack() puts that read back, and it runs when an A_OKAY arrives from the
// device. adbd raises that packet from local_socket_flush_incoming(), in the same
// sockets.cpp the server shares, once the bytes are in the command's socket.
//
// This mock never answered a WRTE with an OKAY. So the server forwarded the client's stat
// request, delivered the stat reply it got back, deleted FDE_READ, and waited for an ack
// that could not arrive. The client, holding the stat reply, sent the rest of the push and
// waited for a reply the server was no longer allowed to ask for. Both waited forever.
//
// The server's own trace shows it, and only the last two lines matter:
//
//	sockets.cpp:128 LS(8) local_socket_flush_incoming: rc = 72   # the stat reply reaches the client
//	sockets.cpp:237 LS(8): acks not deferred, blocking          # and the client socket stops being read
//	                                                                  ... and nothing else
//
// `adb shell` passed throughout, which is the prediction that identifies it: a shell
// command needs no second write from the client after the device speaks, so it never asks
// for the ack again. Every sync request after the first does, because the next command
// cannot be sent until the previous reply has arrived.
//
// Three explanations were checked against the reference and dropped, each by measurement:
//
//   - The CNXN Arg1 window is 0x100000 on this mock and on the phone, identical.
//   - The stream id does not matter: the phone picks 112 and this mock picked 1, and
//     forcing 112 changed nothing.
//   - The server's write thread blocking in pthread_cond_wait is not it. That is
//     BlockingConnectionAdapter's write queue waiting for work, which it does for the phone
//     too. The client socket going unread is the FDE_READ deletion above, not a condition
//     variable, and the two appear in one trace at a glance.
//
// What the reference settled before that, and what is fixed here: a real adbd sends the
// whole 72-byte stat reply as one packet and the whole 8-byte DONE reply as one packet, and
// it leaves every byte after the errno zero for a path that does not exist.
//
// Three more things the wire turned up once the hang was gone, all of them invisible
// while it was there because adb never got far enough to exercise them:
//
//   - SND2 and RCV2 are written as one buffer: id, length, path, then the same id again
//     before the mode and the flags. Reading the two setup words without the repeated id
//     left the flags word where the DATA frames were expected, and a flags word of zero
//     turned a 256 KiB push into `unexpected sync command 0x00000000`. Small pushes missed
//     it because adb sends the v1 SEND form for those.
//   - The banner offered sendrecv_v2_brotli, sendrecv_v2_lz4 and sendrecv_v2_zstd, and
//     nothing here compresses. adb reads the feature list and picks the best one it knows,
//     so above its own size threshold it compressed the payload and the mock read a zstd
//     frame as sync framing -- the same error, with 0x00000004 instead of zero. Those three
//     features are gone from the default banner.
//   - The device reads the send stream in 64 KiB chunks rather than framing exactly, so
//     the handler for one file held the next file's request in the chunk it had just read
//     and dropped it. adb writes those requests back to back -- a directory push is one
//     long run of them -- so the stream desynchronised at the second file. It is handed
//     back now; TestHostTwoSyncSendsInOnePacket is the guard, because reproducing the
//     coalescing through adb would depend on how fast adb writes.
//
// The tools, in order of what each was worth:
//
//	ADB_TRACE=sockets,transport,sync adb nodaemon server   # "acks not deferred, blocking",
//	                                                             and the silence after it
//	MOCKADBD_TRACE=/tmp/t.log ...       # the device's own view
//	LD_PRELOAD=shim.so adb ...          # the client's own reads, byte for byte
//	LD_PRELOAD=shim.so adb nodaemon ... # the server; needs writev as well as read and
//	                                     write, because that is how the reply arrives
//	cmd/probe                           # the wire, from either side
//
// ptrace and gdb are both refused on this host -- kernel.yama.ptrace_scope is 1 -- so the
// shim is what made either process visible without privileges. It is roughly forty lines of
// C that intercept read, write, poll and epoll_wait and print a timestamp; it is not part
// of the repository because it needs a C compiler to build, and a diagnostic that cannot
// be built with the tools the project already assumes is worth documenting rather than
// shipping. Reproduce it from test/mockadbd/README.md.
//
// The line numbers above come from platform/packages/modules/adb: adb moved out of
// platform_system_core, and sockets.cpp, transport.cpp and adb.cpp sit at the top level of
// that tree. The adb installed here is 37.0.0-android-tools, built from vendor/adb, which
// matches that tree rather than any older layout -- it imports no splice(2) and it does
// have BlockingConnectionAdapter.

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

// More than one file in a single push, end to end through a real adb.
//
// Whether adb coalesces both requests into one packet is a matter of how fast it writes,
// so this is an assertion about the whole path rather than the guard for the chunked-read
// bug. TestHostTwoSyncSendsInOnePacket is that guard: it puts both requests in one packet
// on purpose, so the outcome does not depend on timing.
func TestInteropPushSeveralFiles(t *testing.T) {
	adb := requireAdb(t)
	serial, fs := connectMock(t)

	// Both files at least one 64 KiB DATA frame, so the device's chunked read ends
	// mid-transfer rather than on a framing boundary.
	sizes := []int{65536, 100_000}
	srcs := make([]string, 0, len(sizes))
	want := make(map[string][]byte, len(sizes))
	for i, n := range sizes {
		payload := make([]byte, n)
		if _, err := rand.Read(payload); err != nil {
			t.Fatalf("rand: %v", err)
		}
		name := fmt.Sprintf("many-%d.bin", i)
		srcs = append(srcs, hostFile(t, name, payload))
		want["/data/local/tmp/"+name] = payload
	}

	args := append([]string{"-s", serial, "push"}, srcs...)
	args = append(args, "/data/local/tmp/")
	if out, err := adbCmd(t, adb, args...).CombinedOutput(); err != nil {
		t.Fatalf("adb push: %v\n%s", err, out)
	}

	for path, payload := range want {
		got, err := fs.ReadFile(path)
		if err != nil {
			t.Fatalf("%s is not on the device: %v", path, err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("%s: length %d, want %d", path, len(got), len(payload))
		}
	}
}

// Large enough that adb uses SND2's two-request form rather than the v1 SEND, and that
// the payload arrives as several DATA frames. A small push takes the v1 path and never
// sees either.
func TestInteropPushPreservesBinaryContent(t *testing.T) {
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

// The pull counterpart of the large push, and the size at which the device answers with
// DATA frames rather than one body. RCV2 has the same two-request shape as SND2, so it has
// its own way to be mis-parsed; the pull above already reaches it, and this pins the
// multi-frame case.
func TestInteropPullLargeBinary(t *testing.T) {
	adb := requireAdb(t)
	serial, fs := connectMock(t)

	want := make([]byte, 256*1024)
	if _, err := rand.Read(want); err != nil {
		t.Fatalf("rand: %v", err)
	}
	if err := fs.WriteFile("/data/local/tmp/blob.bin", want, 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	dst := filepath.Join(t.TempDir(), "blob.bin")
	if out, err := adbCmd(t, adb, "-s", serial, "pull", "/data/local/tmp/blob.bin", dst).CombinedOutput(); err != nil {
		t.Fatalf("adb pull: %v\n%s", err, out)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read pulled file: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("pull corrupted the contents: %d bytes, want %d", len(got), len(want))
	}
}

// Round-trip is the property that matters: what goes up comes back byte for byte, which is
// what a checksum in a test script would be checking on a real device.
func TestInteropRoundTripIsByteIdentical(t *testing.T) {
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

// A directory pull end to end on the v1 sync path, which is the path a device whose banner
// advertises neither stat_v2 nor ls_v2 puts a client on.
//
// It is a separate test from the directory pull above because the two take different code
// through this device: which commands the client sends is decided by the feature list, so
// the banner is what selects the path, and the reply widths differ along it. A device
// without those features is not hypothetical -- it is every device predating them, and one
// whose answer is wrong costs the operator the directory rather than an error.
//
// The nested file is larger than one DATA frame, so the transfer inside the directory is
// not passing because everything fits in a single packet. The assertion is on the bytes,
// not on adb's own count of what it pulled: a listing answered in the wrong shape ends the
// walk early and adb reports what it collected.
func TestInteropPullDirectoryOnTheV1Path(t *testing.T) {
	adb := requireAdb(t)
	fs := mockadbd.NewVFS()
	l, err := mockadbd.Listen("127.0.0.1:0", mockadbd.Config{
		FS:     fs,
		Banner: v1OnlyBanner,
	})
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

	contents := map[string][]byte{
		"/data/local/tmp/tree/one.txt": []byte("first file"),
		// Larger than one DATA frame, so the transfer inside the directory spans
		// several and the reassembly is part of what this checks.
		"/data/local/tmp/tree/nested/two.txt":   []byte("second file"),
		"/data/local/tmp/tree/nested/three.bin": make([]byte, 200_000),
	}
	if _, err := rand.Read(contents["/data/local/tmp/tree/nested/three.bin"]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	for path, data := range contents {
		if err := fs.WriteFile(path, data, 0o644); err != nil {
			t.Fatalf("seed %s: %v", path, err)
		}
	}

	dst := t.TempDir()
	if out, err := adbCmd(t, adb, "-s", serial, "pull", "/data/local/tmp/tree", dst).CombinedOutput(); err != nil {
		t.Fatalf("adb pull of a directory: %v\n%s", err, out)
	}

	for path, want := range contents {
		got, err := os.ReadFile(filepath.Join(dst, "tree", strings.TrimPrefix(path, "/data/local/tmp/tree/")))
		if err != nil {
			t.Fatalf("%s did not come back: %v", path, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s: %d bytes back, want %d", path, len(got), len(want))
		}
	}
	// The shape as well as the contents: a walk that stopped after the first entry
	// returns a directory with one file in it and no error, and a per-file comparison
	// alone would pass if the missing file's own comparison never ran.
	entries, err := os.ReadDir(filepath.Join(dst, "tree", "nested"))
	if err != nil {
		t.Fatalf("the nested directory did not come back: %v", err)
	}
	if len(entries) != 2 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("the nested directory holds %v, want two files", names)
	}
}

// v1OnlyBanner is a device banner with no sync features beyond shell_v2 and cmd.
//
// The features that select the sync path are stat_v2, ls_v2 and sendrecv_v2. Their absence
// is what makes the client send STAT, LIST and SEND rather than the v2 spellings, so a
// banner carrying them would put this device on the v2 path and TestInteropPullDirectoryOnTheV1Path
// would not be testing what its name says.
const v1OnlyBanner = "device::ro.product.name=ard_mock_v1;ro.product.model=MockV1;" +
	"ro.build.type=user;features=shell_v2,cmd,"
