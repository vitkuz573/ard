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

// statV2BodyLen is the body of a v2 stat record, after its command word.
const statV2BodyLen = 68

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

// The v1 listing: DENT entries of twenty bytes -- the word, then mode, size, timestamp
// and the name's length, each a 4-byte little-endian word -- followed by the name.
//
// The widths are the client's, and they are the only evidence for them. Measured from the
// sizes of the reads a stock client makes on the reply to LIST, on a device advertising
// neither stat_v2 nor ls_v2 so the client takes the v1 path:
//
//	read  4  "DENT"
//	read 16  <mode u32> <size u32> <mtime u32> <namelen u32>
//	read  6  "nested"     <- namelen from the word above, not up to a NUL
//	read 20  "DENT" + the same 16 words
//	read  7  "one.txt"
//	read 20  "DONE" + 16 zero bytes
//
// A client asking for sixteen bytes after DENT is saying there are four words to read, and
// one asking for twenty at DONE is saying the terminator is a whole entry's width with no
// name in it.
//
// Two shapes carry the listing and both are invisible when wrong. The timestamp is 32 bits
// like every other word here: with it in eight, the name-length word reads the timestamp's
// high half, which is zero, so the entry arrives nameless and the client's next read takes
// the first four letters of a name as a command word -- not one, and the pull stops having
// printed `pull: building file list...`. And the name is length-prefixed with nothing after
// it: a NUL in that position is read as the first byte of the name's length.
func TestListV1EntryIsFourWordsThenTheName(t *testing.T) {
	fs := seedTree(t)
	l, err := mockadbd.Listen("127.0.0.1:0", mockadbd.Config{FS: fs})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()

	got := requestSyncRaw(t, l, syncLenRequest("LIST", "/data/local/tmp/tree"))

	const mtime = 0x6ac5289e
	// The whole first entry as the client reads it: the word, four words, the name and
	// nothing else. The name's length is the fourth word, which is what makes the name
	// end where it ends.
	want := []byte{
		'D', 'E', 'N', 'T',
		0xa4, 0x81, 0x00, 0x00, // mode 0100644: a regular file, rw-r--r--
		0x03, 0x00, 0x00, 0x00, // size 3
		0x9e, 0x28, 0xc5, 0x6a, // mtime, 32 bits -- four bytes, not eight
		0x05, 0x00, 0x00, 0x00, // name length 5
		'a', '.', 't', 'x', 't',
	}
	if !bytes.HasPrefix(got, want) {
		t.Fatalf("first v1 entry:\n got %x\nwant %x", got[:len(want)], want)
	}
	if v := binary.LittleEndian.Uint32(got[12:16]); v != mtime {
		t.Fatalf("entry mtime is %#x, want %#x: eight bytes here puts the name length where "+
			"the timestamp's high half is, and every entry arrives nameless", v, mtime)
	}
	if v := binary.LittleEndian.Uint32(got[16:20]); v != uint32(len("a.txt")) {
		t.Fatalf("name length is %d, want %d", v, len("a.txt"))
	}

	// The second entry names the subdirectory and carries the directory bit, which is
	// what a client tests to decide whether to recurse into it. It starts where the
	// first name ended, with no terminator in between.
	second := got[len(want):]
	secondEntry := 20 + len("sub")
	if word := string(second[0:4]); word != "DENT" {
		t.Fatalf("second reply word is %q, want DENT", word)
	}
	if mode := binary.LittleEndian.Uint32(second[4:8]); mode != 0o040755 {
		t.Fatalf("subdirectory mode is %#o, want %#o", mode, 0o040755)
	}
	if name := string(second[20:secondEntry]); name != "sub" {
		t.Fatalf("second entry's name is %q, want sub: a NUL here is read as part of the "+
			"length that precedes it", name)
	}

	doneAt := len(want) + secondEntry
	if word := string(got[doneAt : doneAt+4]); word != "DONE" {
		t.Fatalf("terminator word at %d is %q, want DONE", doneAt, word)
	}
}

// The v1 listing's terminator is twenty bytes: the word and an entry's width with nothing
// in it.
//
// Measured from the same reads as the entries above: the client's read at DONE is twenty
// bytes, which is the word plus the four words an entry carries. A terminator of four
// bytes -- the sync reply header with a zero length, which is what a pull's DONE carries
// and what the v2 listing's terminator is not -- leaves the client waiting out a read it
// has already begun, and a directory pull hangs there having reported nothing.
func TestListV1ReplyEndsWithADoneCarryingAnEntryWidth(t *testing.T) {
	fs := seedTree(t)
	l, err := mockadbd.Listen("127.0.0.1:0", mockadbd.Config{FS: fs})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()

	got := requestSyncRaw(t, l, syncLenRequest("LIST", "/data/local/tmp/tree"))

	const entry = 20
	wantLen := entry + len("a.txt") + entry + len("sub") + entry
	if len(got) != wantLen {
		t.Fatalf("reply is %d bytes, want %d: %x", len(got), wantLen, got)
	}

	doneAt := wantLen - entry
	if word := string(got[doneAt : doneAt+4]); word != "DONE" {
		t.Fatalf("terminator word at %d is %q, want DONE", doneAt, word)
	}
	if tail := got[doneAt+4:]; !bytes.Equal(tail, make([]byte, entry-4)) {
		t.Fatalf("DONE carries %d bytes and not all zeros: %x", len(tail), tail)
	}
}

// LST2 is a v2 stat request, not a listing.
//
// A client told a listing request answered with one record stops there: it reads the reply
// word, sees no DNT2 entry and no DONE, and the walk is over with nothing collected. So
// LST2 answers with a stat record, sharing STA2's path -- which is also what makes the two
// spellings one case rather than two.
func TestListV2IsAskedForWithLIS2(t *testing.T) {
	fs := seedTree(t)
	l, err := mockadbd.Listen("127.0.0.1:0", mockadbd.Config{FS: fs})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()

	got := requestSyncRaw(t, l, syncLenRequest("LST2", "/data/local/tmp/tree"))

	// One record and nothing else: the word, then the 68-byte stat body. A directory
	// listing here would be a run of DNT2 entries and a DONE, and its first word would
	// be DNT2 rather than the request's own.
	if len(got) != 4+statV2BodyLen {
		t.Fatalf("LST2 answered with %d bytes, want one %d-byte record: %x", len(got), 4+statV2BodyLen, got)
	}
	if word := string(got[0:4]); word != "LST2" {
		t.Fatalf("reply word is %q, want the request's own LST2", word)
	}
	if mode := binary.LittleEndian.Uint32(got[4+20 : 4+24]); mode != 0o040755 {
		t.Fatalf("recorded mode is %#o, want the directory's %#o", mode, 0o040755)
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
