package mockadbd

// The sync service: `adb push` and `adb pull`.
//
// Layout, from file_sync_protocol.h, and every element confirmed against a stock adb:
//
//   - A command is four ASCII characters read as a little-endian word, via MKID. STA2 is
//     therefore 0x32415453, which is the word that opens a push.
//   - A request is id, then a 4-byte path length, then exactly that many bytes of path. The
//     path is not NUL-terminated; the length makes a terminator redundant. This holds for
//     every spelling, including the ones without a version suffix: a client sends
//     `STAT` + length + path and `SEND` + length + "path,mode" exactly as it sends STA2.
//   - There is no envelope. A reply begins with its own id word, which is why a reply
//     written as anything else is read as the reply's code and stops the transfer.
//   - The v2 commands are two requests: SND2 carries the path, then a second message with
//     the same id carries mode and flags. RCV2 carries the path, then flags.
//   - The version is chosen per message and not by the service name: adb opens "sync:" and
//     then decides per command from the features it was given for this device, so the
//     service answers both the versioned and the unversioned spelling of each command.
//
// The v2 stat body is 68 bytes, laid out IQQIIIIQqqq:
//
//	error u32, dev u64, ino u64, mode u32, nlink u32, uid u32, gid u32,
//	size u64, atime i64, mtime i64, ctime i64
//
// so STA2's reply is 72 bytes in total. Its unversioned counterpart is 16: the word and
// mode, size and mtime, with a zero mode meaning the path is not there. A DNT2 directory
// entry is the same 72 bytes with a name length at offset 68, followed by the name.

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Words are vars: mkid is a function, and a typed constant cannot be built from a call.
var (
	snd2  uint32 = mkid('S', 'N', 'D', '2')
	rcv2  uint32 = mkid('R', 'C', 'V', '2')
	sta2  uint32 = mkid('S', 'T', 'A', '2')
	lst2  uint32 = mkid('L', 'S', 'T', '2')
	lis2  uint32 = mkid('L', 'I', 'S', '2')
	dnt2  uint32 = mkid('D', 'N', 'T', '2')
	lsta1 uint32 = mkid('S', 'T', 'A', 'T')
	list1 uint32 = mkid('L', 'I', 'S', 'T')
	dent1 uint32 = mkid('D', 'E', 'N', 'T')
	send1 uint32 = mkid('S', 'E', 'N', 'D')
	recv1 uint32 = mkid('R', 'E', 'C', 'V')

	doneW uint32 = mkid('D', 'O', 'N', 'E')
	dataW uint32 = mkid('D', 'A', 'T', 'A')
	okayW uint32 = mkid('O', 'K', 'A', 'Y')
	failW uint32 = mkid('F', 'A', 'I', 'L')
	quitW uint32 = mkid('Q', 'U', 'I', 'T')
)

// syncFlagDryRun is the one setup-word bit this mock understands. The other three from
// file_sync_protocol.h are compression requests -- 1 brotli, 2 lz4, 4 zstd -- and nothing
// here compresses, so a word carrying any of them is refused rather than ignored.
const syncFlagDryRun uint32 = 0x80000000

func mkid(a, b, c, d byte) uint32 {
	return uint32(a) | uint32(b)<<8 | uint32(c)<<16 | uint32(d)<<24
}

// statV2Len is the body of a STA2 reply, and DNT2 is the same plus a name length.
const statV2Len = 68

// Errors reported through the v2 stat body's error field. They are the numbers from
// <errno.h>, because that is what a client turns back into a message.
const (
	errNoEnt   = 2
	errIsDir   = 21
	errTooLong = 36
)

func idString(v uint32) string {
	return string([]byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)})
}

// runSync2 serves one sync stream, speaking whichever version the client opens with.
//
// The service name alone does not say: adb opens "sync:" and then uses STA2/SND2, so the
// version is per-message. Both are accepted because a client is free to use either.
func runSync2(cfg Config, s *stream) {
	// Close the stream when the service ends.
	//
	// Without this the goroutine returned and the stream stayed open, so nothing ever
	// told the host the sync session was over. adb had already received the OKAY that
	// completes a push, printed "1 file pushed", and then sat waiting for a close it was
	// never going to get: the file arrived, the command reported success, and the process
	// stayed alive until something killed it. Every test that waits for adb to exit hung
	// on that, which is why the failure looked like a protocol problem when the transfer
	// had in fact completed.
	defer s.close(nil)

	for {
		cmd, err := readWord(s)
		if err != nil {
			if err != io.EOF {
				cfg.debug("sync: read command: %v", err)
			}
			return
		}
		tracef("sync2 %s (0x%08x)", idString(cmd), cmd)

		switch cmd {
		case quitW:
			return

		case sta2, lst2:
			path, err := readLenString(s)
			if err != nil {
				return
			}
			statV2(cfg, s, path, cmd)

		case lsta1:
			path, err := readLenString(s)
			if err != nil {
				return
			}
			statV1(cfg, s, path)

		case lis2, list1:
			path, err := readLenString(s)
			if err != nil {
				return
			}
			listV2(cfg, s, path)

		case snd2, send1:
			path, err := readLenString(s)
			if err != nil {
				return
			}
			mode := os.FileMode(0o644)
			flags := uint32(0)
			if cmd == snd2 {
				// The setup request repeats the command word before its mode and
				// flags, so the words after the path are three and not two.
				//
				// Reading two leaves the trailing flags word where the DATA frames
				// are expected, and it desynchronises the stream for good: the next
				// "command" the transfer sees is that word. A flags word of zero
				// turned a 256 KiB push into `unexpected sync command 0x00000000`.
				// Small pushes never noticed, because adb sends the v1 form for them.
				if err := expectSetupID(s, cmd); err != nil {
					return
				}
				modeWord, err := readWord(s)
				if err != nil {
					return
				}
				flags, err = readWord(s)
				if err != nil {
					return
				}
				if !compressionSupported(flags) {
					failMsg(s, "%s: compression flag %#x is not supported", path, flags)
					return
				}
				mode = os.FileMode(modeWord & 0o7777)
			} else {
				// The v1 form folds the mode into the path as ",mode".
				if p, m, ok := splitSendV1(path); ok {
					path, mode = p, m
				}
			}
			sendFile(cfg, s, path, mode, flags)

		case rcv2, recv1:
			path, err := readLenString(s)
			if err != nil {
				return
			}
			if cmd == rcv2 {
				// As with SND2, the setup request repeats the command word, and
				// only the flags follow it.
				if err := expectSetupID(s, cmd); err != nil {
					return
				}
				flags, err := readWord(s)
				if err != nil {
					return
				}
				if !compressionSupported(flags) {
					failMsg(s, "%s: compression flag %#x is not supported", path, flags)
					return
				}
			}
			recvFile(cfg, s, path)

		default:
			failMsg(s, "unknown sync command %q", idString(cmd))
			return
		}
	}
}

func readWord(r io.Reader) (uint32, error) {
	var b [4]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	v := binary.LittleEndian.Uint32(b[:])
	tracef("  <- %q 0x%08x", string([]byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)}), v)
	return v, nil
}

// expectSetupID consumes the repeated command word that opens the second half of a v2
// request. adb writes SND2 and RCV2 as one buffer of id, length, path, then the same id
// again followed by the setup words, so the repeat is part of the framing rather than a
// second command to dispatch.
func expectSetupID(r io.Reader, want uint32) error {
	got, err := readWord(r)
	if err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("sync: setup request id %q, want %q", idString(got), idString(want))
	}
	return nil
}

// compressionSupported reports whether a setup word asks for something this mock can do.
//
// Nothing here decompresses or compresses, and the banner does not offer the features
// that would make adb ask (see Config.withDefaults), so the only acceptable word is zero
// apart from the dry-run bit. Accepting a real compression request and then writing the
// bytes as they arrived would corrupt the file without saying so.
func compressionSupported(flags uint32) bool {
	return flags & ^syncFlagDryRun == 0
}

func readLenString(r io.Reader) (string, error) {
	n, err := readWord(r)
	if err != nil {
		return "", err
	}
	if n > 1024 {
		// The header says paths are at most 1024. Refusing a larger one rather than
		// allocating it keeps a bad length from becoming a large allocation.
		return "", fmt.Errorf("sync: path length %d exceeds the 1024 the protocol allows", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

// putWord writes one command word.
//
// It takes a *stream rather than an io.Writer precisely so it can reach writeRaw: going
// through stream.Write would frame the word as shell-v2 stdout, and the client would be
// reading a protocol this is not.
func putWord(s *stream, v uint32) error {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	tracef("  -> %q", string([]byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)}))
	return s.writeRaw(b[:])
}

func failMsg(s *stream, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	tracef("  -> FAIL %q", msg)
	_ = putWord(s, failW)
	var n [4]byte
	binary.LittleEndian.PutUint32(n[:], uint32(len(msg)))
	_ = s.writeRaw(append(n[:], msg...))
}

// writeStatV2 emits id followed by the 68-byte body.
//
// The id and the body go out in one write, not two. They used to be two, because putWord
// and writeRaw were separate steps, and a client coped with the split -- adb acknowledged
// both packets -- but then sat idle for the better part of a minute before sending anything
// at all. Coalescing them removed the wait. A real adbd assembles the reply and writes it
// once, so one write is both what the device does and what the client is shaped for; the
// split was a quirk of how this code was written, not of the protocol.
func writeStatV2(s *stream, id, errno uint32, n *Node) error {
	var head [4]byte
	binary.LittleEndian.PutUint32(head[:], id)
	tracef("  -> %q", idString(id))
	var b [statV2Len]byte
	le32(b[0:], errno)

	if errno != 0 {
		// Everything else stays zero.
		//
		// This is what a real adbd sends, checked against one: for a path that does not
		// exist the whole 68-byte body after the errno is zero -- dev, ino, mode, nlink,
		// size and all three timestamps. Not "plausible values", zeros. A client decides
		// "no such file" by mode == 0, so it needs nothing else, and it reads the rest
		// as a stat structure it might compare against.
		//
		// Writing plausible values here was worse than writing nothing. dev=1, ino=1 and
		// nlink=1 described a file that does not exist, and the timestamps came from a
		// synthesised node whose zero time, written as seconds, is -62135596800: a
		// client that treats it as an unsigned 64-bit second count gets a timestamp in
		// the far future, and a push then compares a real file against it and decides
		// something other than what it should.
		return s.writeRaw(append(head[:], b[:]...))
	}

	le64(b[4:], 1)         // dev
	le64(b[12:], inoOf(n)) // ino
	le32(b[20:], statMode(n.Dir, n.Mode))
	le32(b[24:], 1)                   // nlink
	le32(b[28:], 0)                   // uid
	le32(b[32:], 0)                   // gid
	le64(b[36:], uint64(len(n.Data))) // size
	// Seconds, not nanoseconds: these three are time_t on the wire.
	secs := uint64(n.ModTime.Unix())
	le64(b[44:], secs) // atime
	le64(b[52:], secs) // mtime
	le64(b[60:], secs) // ctime
	// The id and the body go out as one 72-byte packet.
	//
	// A real adbd sends them together, and a host reads them as one message: its stat
	// read wants 72 bytes and is satisfied by exactly that. Written as two packets --
	// four bytes then sixty-eight -- the host got the id, waited, and only produced the
	// rest of the exchange twenty seconds later. Splitting them was correct-looking and
	// it cost the push its entire stream.
	return s.writeRaw(append(head[:], b[:]...))
}

func le32(b []byte, v uint32) { binary.LittleEndian.PutUint32(b, v) }
func le64(b []byte, v uint64) { binary.LittleEndian.PutUint64(b, v) }

// inoOf derives a stable inode number from the path, so the same file reports the same one
// twice and a client can tell that a listing did not reorder underneath it.
var (
	inoMu     sync.Mutex
	inoByPath        = map[string]uint64{}
	inoNext   uint64 = 1000
)

func inoOf(n *Node) uint64 {
	if n == nil {
		return 0
	}
	if n.Name == "" {
		return 1
	}
	inoMu.Lock()
	defer inoMu.Unlock()
	key := n.Name
	if v, ok := inoByPath[key]; ok {
		return v
	}
	inoNext++
	inoByPath[key] = inoNext
	return inoNext
}

func statV2(cfg Config, s *stream, path string, id uint32) {
	n, err := cfg.FS.Stat(path)
	if err != nil {
		// A missing file is reported in the body, not as a FAIL: that is the difference
		// between "the protocol went wrong" and "there is nothing there", and a client
		// turns the errno into its own message.
		// The errno goes in the error field and mode is left zero, because mode == 0 is
		// what a client tests for "not here".
		//
		// Whether the error field should be zero instead was tried, on the theory that a
		// client reads it as a failed request. It made no difference to the observed
		// behaviour, so it went back to carrying the errno, which is what the field is
		// for.
		_ = writeStatV2(s, id, errNoEnt, &Node{Mode: 0})
		return
	}
	_ = writeStatV2(s, id, 0, n)
}

// statV1 answers STAT: the reply is the command word followed by three 4-byte little-endian
// words -- mode, size and mtime -- so 16 bytes in total where STA2's reply is 72.
//
// It has to be one write. A client reads the sixteen bytes as one message, so a reply split
// across two packets leaves the reader holding four bytes and waiting, which it does for as
// long as the transfer takes to finish.
//
// A path that is not there is answered with the word and three zero words rather than a
// FAIL. mode == 0 is how a client tests "not here", and that test has to have something to
// read: a FAIL in this position is read as a stat reply whose message id is wrong, and the
// transfer stops with a protocol fault naming a number the operator has no way to interpret.
func statV1(cfg Config, s *stream, path string) {
	var body [12]byte
	if n, err := cfg.FS.Stat(path); err == nil {
		le32(body[0:], statMode(n.Dir, n.Mode))
		le32(body[4:], uint32(len(n.Data)))
		le32(body[8:], uint32(n.ModTime.Unix()))
	}
	var head [4]byte
	le32(head[:], lsta1)
	_ = s.writeRaw(append(head[:], body[:]...))
}

func listV2(cfg Config, s *stream, path string) {
	entries, err := cfg.FS.ReadDir(path)
	if err != nil {
		failMsg(s, "%s: no such directory", path)
		return
	}
	for _, e := range entries {
		if err := putWord(s, dnt2); err != nil {
			return
		}
		var b [72]byte
		le32(b[0:], 0)
		le64(b[4:], 1)
		le64(b[12:], inoOf(e))
		le32(b[20:], statMode(e.Dir, e.Mode))
		le32(b[24:], 1)
		le32(b[28:], 0)
		le32(b[32:], 0)
		le64(b[36:], uint64(len(e.Data)))
		le64(b[44:], uint64(e.ModTime.UnixNano()))
		le64(b[52:], uint64(e.ModTime.UnixNano()))
		le64(b[60:], uint64(e.ModTime.UnixNano()))
		le32(b[68:], uint32(len(e.Name)))
		if err := s.writeRaw(append(b[:], e.Name...)); err != nil {
			return
		}
	}
	// DONE carries 16 bytes, not an empty payload.
	_ = putWord(s, doneW)
	_ = s.writeRaw(make([]byte, 16))
}

// splitSendV1 parses the v1 push form, "path,mode".
//
// The mode is decimal, not octal, and it carries the file type bits. adb sends 33188 for
// a plain 0644 file because that is 0100644 in octal written out as a decimal number, and
// reading it as octal gave 013220 -- a different number, and one with type bits set that
// Go's FileMode reads as something that is not a regular file.
//
// Only the permission bits are kept. The type is implied by the operation: a SEND creates
// a regular file whatever the client asked for, so honouring type bits would let a client
// talk this mock into creating something that is not a file.
func splitSendV1(arg string) (string, os.FileMode, bool) {
	i := strings.LastIndex(arg, ",")
	if i < 0 {
		return arg, 0o644, false
	}
	m, err := strconv.ParseUint(arg[i+1:], 10, 32)
	if err != nil {
		return arg, 0o644, false
	}
	return arg[:i], os.FileMode(m & uint64(os.ModePerm)), true
}

// sendFile receives a push.
//
// The host frames the content: DATA with a length, repeated, then DONE with the source's
// mtime. Treating everything between SEND and DONE as raw bytes looked equivalent and was
// not -- it wrote the DATA word and its length into the file, and a payload containing the
// four bytes "DONE" would have ended the transfer early. Reading the framing is not more
// code, it is the protocol.
func sendFile(cfg Config, s *stream, path string, mode os.FileMode, flags uint32) {
	if err := cfg.FS.EnsureFile(path, mode); err != nil {
		failMsg(s, "%s: %v", path, err)
		return
	}
	var pending []byte
	buf := make([]byte, syncChunk)
	for {
		n, err := s.Read(buf)
		if n > 0 {
			pending = append(pending, buf[:n]...)
			var done bool
			if pending, done = drainSend(s, cfg, path, pending); done {
				return
			}
		}
		if err != nil {
			failMsg(s, "%s: %v", path, err)
			return
		}
	}
}

// drainSend consumes the send stream as far as it is complete and returns the remainder.
//
// A word can straddle a read, so anything short of a whole command is handed back for the
// next one. It reports whether the transfer is over.
func drainSend(s *stream, cfg Config, path string, b []byte) ([]byte, bool) {
	for {
		if len(b) < 4 {
			return b, false
		}
		switch cmd := binary.LittleEndian.Uint32(b[:4]); cmd {
		case dataW:
			if len(b) < 8 {
				return b, false
			}
			n := int(binary.LittleEndian.Uint32(b[4:8]))
			if len(b) < 8+n {
				return b, false
			}
			if err := cfg.FS.AppendFile(path, b[8:8+n]); err != nil {
				failMsg(s, "%s: %v", path, err)
				return nil, true
			}
			b = b[8+n:]

		case doneW:
			if len(b) < 8 {
				return b, false
			}
			_ = cfg.FS.Touch(path, time.Unix(int64(binary.LittleEndian.Uint32(b[4:8])), 0))
			// OKAY and its zero length go out as one write.
			//
			// Written separately they were two packets, and the host tears the stream
			// down on its own CLSE as soon as it has sent DONE -- which it does without
			// waiting for this reply. Two packets gave the host's server a chance to
			// process the close in between and drop the reply on the floor, and a client
			// that never sees the reply never returns from the command. One write is both
			// what a real adbd sends and what leaves no gap to be cut in.
			var reply [8]byte
			binary.LittleEndian.PutUint32(reply[:4], okayW)
			tracef("  -> %q", idString(okayW))
			// Whatever follows DONE belongs to the next request. adb sends them
			// back to back -- a directory push is one long run of them -- and this
			// handler is the only thing holding those bytes, because it reads in
			// 64 KiB chunks. Hand them back rather than dropping them.
			s.unread(b[8:])
			if err := s.writeRaw(reply[:]); err != nil {
				return nil, true
			}
			return nil, true

		default:
			failMsg(s, "%s: unexpected sync command 0x%08x", path, cmd)
			return nil, true
		}
	}
}

// recvFile answers a pull: DATA with a length each, then DONE.
func recvFile(cfg Config, s *stream, path string) {
	data, err := cfg.FS.ReadFile(path)
	if err != nil {
		failMsg(s, "%s: no such file", path)
		return
	}
	for off := 0; off < len(data); off += syncChunk {
		end := off + syncChunk
		if end > len(data) {
			end = len(data)
		}
		if err := putWord(s, dataW); err != nil {
			return
		}
		if err := putWord(s, uint32(end-off)); err != nil {
			return
		}
		if err := s.writeRaw(data[off:end]); err != nil {
			return
		}
	}
	_ = putWord(s, doneW)
	_ = s.writeRaw(make([]byte, 16))
}

// hexPreview renders bytes compactly for a trace line.
func hexPreview(p []byte) string {
	const max = 48
	s := hex.EncodeToString(p)
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}
