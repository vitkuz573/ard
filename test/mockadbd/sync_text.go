package mockadbd

// The text-framed sync protocol, as a current adb actually speaks it.
//
// The legacy binary protocol in sync.go is correct for what it implements and older clients
// use it. This file exists because `adb push` and `adb pull` do not go there.
//
// Layout, from file_sync_protocol.h:
//
//   - A command is four ASCII characters read as a little-endian word, via MKID. STA2 is
//     therefore 0x32415453, which is what the trace showed before the protocol was known.
//   - A request is id, then a 4-byte path length, then exactly that many bytes of path.
//     The path is not NUL-terminated; the length makes a terminator redundant.
//   - There is no envelope. A reply begins with its own id word. An earlier attempt here
//     invented an "RSP2" prefix, and adb then blocked instead of failing, because it read
//     that word as the code.
//   - The v2 commands are two requests: SND2 carries the path, then a second message with
//     the same id carries mode and flags. RCV2 carries the path, then flags.
//
// STATUS: the reply is complete and correct against the specification, and adb still does
// not proceed. The trace now shows the whole exchange, so this is one command to reproduce
// rather than an investigation:
//
//	MOCKADBD_FORCE_SYNC=1 MOCKADBD_TRACE=/tmp/t.log \
//	  go test ./test/mockadbd/ -run TestInteropPushLands
//
// and it currently reads:
//
//	OPEN service="sync"
//	  <- "STA2" 0x32415453
//	  <- 0x0000001a                      path length, 26
//	  -> "STA2"
//	  -> raw 4 bytes                     the id word
//	  -> raw 68 bytes                    the body
//	  (nothing further)
//
// Everything adb sent was understood, and everything it should have received was sent.
// What is missing is the specification of what it does next, which is client-side code
// rather than protocol code.
//
// The v2 stat body is 68 bytes, laid out IQQIIIIQqqq:
//
//	error u32, dev u64, ino u64, mode u32, nlink u32, uid u32, gid u32,
//	size u64, atime i64, mtime i64, ctime i64
//
// A DNT2 directory entry is the same 72 bytes with a name length at offset 68, followed by
// the name.

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
				// The second request carries the mode and the flags.
				modeWord, err := readWord(s)
				if err != nil {
					return
				}
				flags, err = readWord(s)
				if err != nil {
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
				if _, err := readWord(s); err != nil { // flags
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
	le64(b[4:], 1)         // dev
	le64(b[12:], inoOf(n)) // ino
	mode := statMode(n.Dir, n.Mode)
	if errno != 0 {
		// A client decides "no such file" by mode == 0, not by reading the error field.
		// Writing the type bits anyway reports a file that exists and has no content,
		// and the client then waits for something that will never come.
		mode = 0
	}
	le32(b[20:], mode)
	le32(b[24:], 1)                   // nlink
	le32(b[28:], 0)                   // uid
	le32(b[32:], 0)                   // gid
	le64(b[36:], uint64(len(n.Data))) // size
	// Seconds, not nanoseconds. These three are time_t on the wire, and a client that
	// reads nanoseconds as seconds gets a timestamp thousands of years out. It matters
	// most for the missing-file case, where the node is synthesised and carries the zero
	// time: in nanoseconds that is a large negative number, which as an unsigned 64-bit
	// second count is nonsense.
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
