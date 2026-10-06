package mockadbd_test

// The bytes a directory listing is made of, checked against the wire.
//
// A listing is the reply where a client and a device can agree on nothing and both
// look like they worked. The reply is a run of entries and a terminator, every entry has
// its own width, and a client reads the run with the widths it expects rather than with
// anything the device says: a width that is short leaves the client waiting for bytes
// that never come, and one that is long makes it read the next reply's first bytes as
// part of this one. Neither produces an error. A listing that is one word too wide is a
// directory pull that silently pulls nothing.
//
// So the shapes here are hex strings off captures, not expressions of the code's own
// constants. Each measurement says which read sizes the client made, because the read
// sizes are the widths: a client that asks for 16 bytes after DENT is telling us the
// body is 16 bytes.

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	mockadbd "github.com/vitkuz573/ard/test/mockadbd"
)

// requestSyncRaw opens a sync stream, writes one request, and returns every WRTE payload
// the device sends in reply, in order and with the transport around them removed.
//
// It stops on a quiet period rather than on a byte count. A listing's length is what the
// test is measuring, so a count cannot be the stopping condition -- asking for N bytes and
// waiting for N would fail on the very reply whose width is wrong. The quiet period is
// short enough to keep the test quick and long enough that a reply written as several
// packets is not cut in half.
func requestSyncRaw(t *testing.T, l *mockadbd.Listener, req []byte) []byte {
	t.Helper()
	h := dialHost(t, l.Addr().String())
	h.handshake()
	id := h.open("sync:")

	const cmdWRTE = 0x45545257
	h.writePacket(cmdWRTE, id, h.streams[id], req)

	var out []byte
	deadline := time.Now().Add(10 * time.Second)
	quiet := 300 * time.Millisecond
	for time.Now().Before(deadline) {
		_ = h.conn.SetReadDeadline(time.Now().Add(quiet))
		p, err := h.tryReadPacket()
		if err != nil {
			if len(out) == 0 {
				t.Fatalf("no reply within %s: %v", deadline, err)
			}
			return out
		}
		if p.cmd != cmdWRTE || p.arg1 != id {
			continue
		}
		out = append(out, p.data...)
	}
	t.Fatalf("reply did not settle within %s; got %d bytes: %x", deadline, len(out), out)
	return nil
}

// syncLenRequest frames a request as the sync protocol does: the command word, then a
// 4-byte path length, then the path.
func syncLenRequest(cmd string, path string) []byte {
	var out []byte
	out = append(out, cmd...)
	out = append(out, encWord(uint32(len(path)))...)
	return append(out, path...)
}

// seedTree creates one directory holding one file and one subdirectory holding one file,
// which is the smallest tree a listing has to describe twice over.
func seedTree(t *testing.T) *mockadbd.VFS {
	t.Helper()
	fs := mockadbd.NewVFS()
	const mtime = 0x6ac5289e
	fs.Now = func() time.Time { return time.Unix(int64(mtime), 0) }
	if err := fs.WriteFile("/data/local/tmp/tree/a.txt", []byte("aaa"), 0o644); err != nil {
		t.Fatalf("seed a.txt: %v", err)
	}
	if err := fs.WriteFile("/data/local/tmp/tree/sub/b.txt", []byte("bbb"), 0o644); err != nil {
		t.Fatalf("seed b.txt: %v", err)
	}
	return fs
}

// The v2 listing: DNT2 entries whose body is 68 bytes and whose name is length-prefixed,
// then a DONE carrying the same 72-byte shape with no name in it.
//
// The DONE width is the load-bearing part and it is not a convention. Measured by
// sweeping it one byte at a time against a stock client: 72 ends the listing and the
// files come back; 0, 4, 8, 16, 20, 68 and 71 leave the client blocked in a read that
// never completes; 73 desynchronises the reply that follows.
//
// 72 is the width of one entry's header -- the 68-byte stat body plus the 4-byte name
// length -- so the terminator is read with the same read the entries are. A DONE
// carrying only the 16 bytes a v1 DONE carries leaves the client 56 bytes short of a
// whole read, and it waits rather than reporting anything: that is a directory pull that
// hangs rather than one that fails.
func TestListV2ReplyEndsWithADoneCarryingAWholeEntryHeader(t *testing.T) {
	fs := seedTree(t)
	l, err := mockadbd.Listen("127.0.0.1:0", mockadbd.Config{FS: fs})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()

	got := requestSyncRaw(t, l, syncLenRequest("LIS2", "/data/local/tmp/tree"))

	// Both entries, then the terminator: 4+72+5, 4+72+3, 4+72.
	// Each entry is the word, a 72-byte header and a name; the terminator is the word
	// and the same 72 bytes with no name.
	const entryHeader = 4 + 72
	wantLen := entryHeader + len("a.txt") + entryHeader + len("sub") + entryHeader
	if len(got) < wantLen {
		t.Fatalf("reply is %d bytes, want at least %d: %x", len(got), wantLen, got)
	}

	if word := string(got[0:4]); word != "DNT2" {
		t.Fatalf("first reply word is %q, want DNT2", word)
	}
	// The 72-byte body starts after the word, so the name length is at 4+68 and the
	// name follows it.
	nameLen := binary.LittleEndian.Uint32(got[4+68 : 4+72])
	if int(nameLen) != len("a.txt") {
		t.Fatalf("name length is %d, want %d", nameLen, len("a.txt"))
	}
	if name := string(got[76 : 76+nameLen]); name != "a.txt" {
		t.Fatalf("first entry's name is %q, want a.txt", name)
	}

	// The terminator: DONE followed by the entry header's width, all zeros. A client
	// reads 76 bytes here and finds 72, so this is the whole shape with nothing in it.
	doneAt := wantLen - entryHeader
	if word := string(got[doneAt : doneAt+4]); word != "DONE" {
		t.Fatalf("terminator word at %d is %q, want DONE", doneAt, word)
	}
	tail := got[doneAt+4 : doneAt+entryHeader]
	if !bytes.Equal(tail, make([]byte, 72)) {
		t.Fatalf("DONE payload is %d bytes and not all zeros: %x", len(tail), tail)
	}
}

// The v2 listing's timestamps are seconds, like the stat reply's and unlike what the
// field's name suggests.
//
// This is the reason an existing file is re-pulled on every `adb pull <dir>`: a client
// compares the entry's mtime against the local file's, and nanoseconds read as seconds
// is a date in the year 2554 that never compares equal to anything already on disk.
func TestListV2ReplyCarriesSecondCountTimestamps(t *testing.T) {
	fs := seedTree(t)
	l, err := mockadbd.Listen("127.0.0.1:0", mockadbd.Config{FS: fs})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()

	got := requestSyncRaw(t, l, syncLenRequest("LIS2", "/data/local/tmp/tree"))

	// The three timestamps sit at 44, 52 and 60 of the body, which starts after the
	// command word.
	const mtime = 0x6ac5289e
	for _, at := range []int{4 + 44, 4 + 52, 4 + 60} {
		if v := binary.LittleEndian.Uint64(got[at : at+8]); v != mtime {
			t.Fatalf("timestamp at offset %d is %#x (%d), want %#x: a client reading this as "+
				"seconds sees %d, which is not a date", at, v, v, mtime, v)
		}
	}
}

// The v1 listing: DENT entries whose body is 16 bytes -- mode 4, size 4, mtime 8 -- and
// whose name is NUL-terminated.
//
// Two things here are measured rather than derived. The reply word is DENT, not DNT2: a
// DNT2 read as a DENT puts the entry's 72-byte body where a 16-byte one is expected, the
// directory bit lands somewhere else, and `adb pull <dir>` reports nothing and exits
// without an error.
//
// And the body is 16 bytes with a 64-bit mtime in the middle of two 32-bit fields. From
// the sizes of the reads a stock client makes on this reply: 4 bytes for DENT, then 16,
// then the name to its NUL. A body of twelve bytes -- which is what STAT uses, and so the
// obvious thing to reuse -- puts the name four bytes early, and the reads show the client
// taking the first four letters of the name as the end of the body.
func TestListV1ReplyIsDENTWithA16ByteBodyAndANulTerminatedName(t *testing.T) {
	fs := seedTree(t)
	l, err := mockadbd.Listen("127.0.0.1:0", mockadbd.Config{FS: fs})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()

	got := requestSyncRaw(t, l, syncLenRequest("LIST", "/data/local/tmp/tree"))

	if word := string(got[0:4]); word != "DENT" {
		t.Fatalf("first reply word is %q, want DENT: a client told DNT2 here reads the entry "+
			"at the wrong offsets and stops without saying why", word)
	}

	const mtime = 0x6ac5289e
	want := []byte{
		'D', 'E', 'N', 'T',
		0xa4, 0x81, 0x00, 0x00, // 0100644: a regular file, rw-r--r--
		0x03, 0x00, 0x00, 0x00, // size 3
		0x9e, 0x28, 0xc5, 0x6a, 0x00, 0x00, 0x00, 0x00, // mtime, 64 bits
		'a', '.', 't', 'x', 't', 0x00,
	}
	if !bytes.HasPrefix(got, want) {
		t.Fatalf("first v1 entry:\n got %x\nwant %x", got[:len(want)], want)
	}
	if v := binary.LittleEndian.Uint64(got[12:20]); v != mtime {
		t.Fatalf("entry mtime is %#x, want %#x", v, mtime)
	}

	// The second entry names the subdirectory and carries the directory bit, which is
	// what a client tests to decide whether to recurse into it. It starts after the
	// first: word, body, and "a.txt" with its NUL.
	const firstEntry = 4 + 16 + len("a.txt") + 1
	second := got[firstEntry : firstEntry+4+16+len("sub")+1]
	if word := string(second[0:4]); word != "DENT" {
		t.Fatalf("second reply word is %q, want DENT", word)
	}
	if mode := binary.LittleEndian.Uint32(second[4:8]); mode != 0o040755 {
		t.Fatalf("subdirectory mode is %#o, want %#o", mode, 0o040755)
	}
	if name := string(second[20:24]); name != "sub\x00" {
		t.Fatalf("second entry's name is %q, want \"sub\\x00\"", name)
	}

	doneAt := firstEntry + 4 + 16 + len("sub") + 1
	if word := string(got[doneAt : doneAt+4]); word != "DONE" {
		t.Fatalf("terminator word at %d is %q, want DONE", doneAt, word)
	}
}

// The pull's DONE is 4 bytes and the listing's is 72, and the two are not
// interchangeable.
//
// Measured by sweeping the pull's width against a stock client pulling a directory: 4
// ends every file's transfer; 0 and 5 through 11 leave the client blocked; 12 and above
// make it read the next file's reply as part of this one's, so the first file arrives and
// the second is reported as missing.
//
// 4 is the width of the sync protocol's own reply header -- a command word and a length
// -- so a pull's DONE is that header with a zero length. That is why the two terminators
// differ: the listing's is read with the entry-shaped read, and this one is not.
func TestRecvV2ReplyEndsWithADoneCarryingFourBytes(t *testing.T) {
	fs := mockadbd.NewVFS()
	const mtime = 0x6ac5289e
	fs.Now = func() time.Time { return time.Unix(int64(mtime), 0) }
	if err := fs.WriteFile("/data/local/tmp/recv.bin", []byte("four"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	l, err := mockadbd.Listen("127.0.0.1:0", mockadbd.Config{FS: fs})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()

	// RCV2 is two requests: the path, then the command word again and the flags.
	req := syncLenRequest("RCV2", "/data/local/tmp/recv.bin")
	req = append(req, syncWord("RCV2")...)
	req = append(req, encWord(0)...)

	got := requestSyncRaw(t, l, req)

	// DATA, a 4-byte length, the payload, then DONE with four bytes behind it.
	want := append([]byte{}, "DATA"...)
	want = append(want, encWord(4)...)
	want = append(want, []byte("four")...)
	want = append(want, []byte("DONE\x00\x00\x00\x00")...)
	if !bytes.HasPrefix(got, want) {
		t.Fatalf("pull reply:\n got %x\nwant %x", got[:len(want)], want)
	}
}
