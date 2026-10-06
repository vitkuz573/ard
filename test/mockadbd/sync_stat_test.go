package mockadbd_test

// The bytes a STAT reply is made of, checked against the wire rather than against the code
// that produces them.
//
// Every constant here is a hex string taken off a captured exchange between a stock adb and
// this device. That is the only kind of reference a wire-format test can have: a test written
// from the same constants as the implementation agrees with the implementation whatever the
// implementation does, and agrees with nothing else at all.
//
// A STAT reply is 16 bytes:
//
//	53544154  a4 81 00 00  0e 00 00 00  9e 28 c5 6a
//	"STAT"    mode       size       mtime
//
// mode is a stat(2) mode word with the file type folded in -- 0x81a4 is 0100644, a regular
// file with rw-r--r-- -- size is the file's length in bytes, and mtime is seconds. A real
// adbd leaves every one of them zero for a path that is not there, and the reply is still 16
// bytes: the word is present with a zero mode, which is what a client tests to mean "not
// here".
//
// Both of those were measured. The first is the reply for a file that exists, taken from a
// pull of a 14-byte file; the second is the reply for a push to a path that does not exist
// yet, which is the reply the very first request of a push gets and therefore the one that
// decides whether a push gets off the ground at all.

import (
	"bytes"
	"testing"
	"time"

	mockadbd "github.com/vitkuz573/ard/test/mockadbd"
)

// statReplyWords is the number of 4-byte words a STAT reply is: the command word and three
// body words.
const statReplyWords = 4

// requestSyncStat opens a sync stream, asks for one path, and returns the reply as the host
// receives it: the bytes of the WRTE payloads in order, with the transport around them removed.
func requestSyncStat(t *testing.T, l *mockadbd.Listener, path string) []byte {
	t.Helper()
	h := dialHost(t, l.Addr().String())
	h.handshake()
	id := h.open("sync:")

	var body []byte
	body = append(body, syncWord("STAT")...)
	body = append(body, encWord(uint32(len(path)))...)
	body = append(body, path...)

	const cmdWRTE = 0x45545257
	h.writePacket(cmdWRTE, id, h.streams[id], body)

	var out []byte
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		_ = h.conn.SetReadDeadline(deadline)
		p := h.readPacket()
		if p.cmd != cmdWRTE || p.arg1 != id {
			continue
		}
		out = append(out, p.data...)
		if len(out) >= statReplyWords*4 {
			return out
		}
	}
	t.Fatalf("no STAT reply for %q within the deadline; got %d bytes", path, len(out))
	return nil
}

// A file that exists: the reply names its mode, its size and its time.
func TestStatV1ReplyIsSixteenBytesCarryingModeSizeAndTime(t *testing.T) {
	fs := mockadbd.NewVFS()
	// A fixed clock, installed before the file is created so the node records it: the
	// reply's third word is then a constant rather than whatever the time was while the
	// test ran. The value is the one the capture carried, 0x6ac5289e.
	const mtime = 0x6ac5289e
	fs.Now = func() time.Time { return time.Unix(int64(mtime), 0) }

	const path = "/data/local/tmp/stat-present.bin"
	const size = 14
	if err := fs.WriteFile(path, []byte("hello-v1-stat\n"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	l, err := mockadbd.Listen("127.0.0.1:0", mockadbd.Config{FS: fs})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()

	got := requestSyncStat(t, l, path)

	if len(got) != statReplyWords*4 {
		t.Fatalf("STAT reply is %d bytes, want %d: %x", len(got), statReplyWords*4, got)
	}
	// 0x81a4 is 0100644: the file type bits of a regular file, then rw-r--r--.
	want := []byte{
		'S', 'T', 'A', 'T',
		0xa4, 0x81, 0x00, 0x00,
		size, 0x00, 0x00, 0x00,
		0x9e, 0x28, 0xc5, 0x6a,
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("STAT reply for an existing file:\n got %x\nwant %x", got, want)
	}
}

// A path that is not there: the reply is the word and three zero words.
//
// Not a FAIL. A client that reads a FAIL where it expected a stat reply stops the command
// with a protocol fault that quotes the failure word as a decimal number -- 1279869254, which
// is 0x4C494146 -- and tells the operator nothing about the file. The zero mode is what a
// client tests for, and it has to arrive as a stat reply for the test to be possible.
func TestStatV1ReplyForAMissingPathIsSixteenZeroBytesAfterTheWord(t *testing.T) {
	fs := mockadbd.NewVFS()
	l, err := mockadbd.Listen("127.0.0.1:0", mockadbd.Config{FS: fs})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()

	got := requestSyncStat(t, l, "/data/local/tmp/definitely-not-here")

	if len(got) != statReplyWords*4 {
		t.Fatalf("STAT reply for a missing path is %d bytes, want %d: %x",
			len(got), statReplyWords*4, got)
	}
	want := []byte{'S', 'T', 'A', 'T', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	if !bytes.Equal(got, want) {
		t.Fatalf("STAT reply for a missing path:\n got %x\nwant %x", got, want)
	}
}

// A directory's mode word carries the directory bit, which is what a client tests to decide
// whether to recurse. Reported without it, a directory is pulled as an empty file.
func TestStatV1ReplyMarksADirectory(t *testing.T) {
	fs := mockadbd.NewVFS()
	if err := fs.WriteFile("/data/local/tmp/dir-inside/f.txt", []byte("x"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	l, err := mockadbd.Listen("127.0.0.1:0", mockadbd.Config{FS: fs})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()

	got := requestSyncStat(t, l, "/data/local/tmp/dir-inside")

	if len(got) != statReplyWords*4 {
		t.Fatalf("STAT reply is %d bytes, want %d: %x", len(got), statReplyWords*4, got)
	}
	// 0x41ed is 040755: S_IFDIR with rwxr-xr-x.
	mode := le32(got[4:8])
	if want := uint32(0o040755); mode != want {
		t.Fatalf("directory mode word = %#o, want %#o (a client tests this bit to recurse)",
			mode, want)
	}
}
