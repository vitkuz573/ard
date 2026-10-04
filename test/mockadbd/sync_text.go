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
// STATUS: STA2 round-trips -- request parsed, reply written -- but adb still blocks
// afterwards instead of sending SND2, so push and pull do not work yet. The trace makes
// the next step a single command rather than an investigation:
//
//	MOCKADBD_TRACE=/tmp/t.log go test ./test/mockadbd/ -run TestInteropPushLands
//
// One real bug is already fixed here: a missing file has to be reported with mode == 0,
// because that is what a client tests. Writing the type bits anyway says "a file exists,
// empty", and the client then waits for something that never arrives.
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
	"fmt"
	"io"
	"os"
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
	return binary.LittleEndian.Uint32(b[:]), nil
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

func putWord(w io.Writer, v uint32) error {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	_, err := w.Write(b[:])
	return err
}

func failMsg(s *stream, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	_ = putWord(s, failW)
	var n [4]byte
	binary.LittleEndian.PutUint32(n[:], uint32(len(msg)))
	_, _ = s.Write(append(n[:], msg...))
}

// writeStatV2 emits id followed by the 68-byte body.
func writeStatV2(s *stream, id, errno uint32, n *Node) error {
	if err := putWord(s, id); err != nil {
		return err
	}
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
	le64(b[44:], uint64(n.ModTime.UnixNano()))
	le64(b[52:], uint64(n.ModTime.UnixNano()))
	le64(b[60:], uint64(n.ModTime.UnixNano()))
	_, err := s.Write(b[:])
	return err
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
		if _, err := s.Write(append(b[:], e.Name...)); err != nil {
			return
		}
	}
	// DONE carries 16 bytes, not an empty payload.
	_ = putWord(s, doneW)
	_, _ = s.Write(make([]byte, 16))
}

// splitSendV1 parses the v1 push form, "path,mode".
func splitSendV1(arg string) (string, os.FileMode, bool) {
	i := strings.LastIndex(arg, ",")
	if i < 0 {
		return arg, 0o644, false
	}
	var m uint32
	for _, c := range arg[i+1:] {
		if c < '0' || c > '7' {
			return arg, 0o644, false
		}
		m = m*8 + uint32(c-'0')
	}
	return arg[:i], os.FileMode(m), true
}

// sendFile receives a push.
//
// The body is raw bytes with no framing: it ends with a DONE word carrying the source's
// mtime, and a word can straddle a read, so the tail is held back until it can be read as
// four whole bytes.
func sendFile(cfg Config, s *stream, path string, mode os.FileMode, flags uint32) {
	if err := cfg.FS.EnsureFile(path, mode); err != nil {
		failMsg(s, "%s: %v", path, err)
		return
	}
	var carry []byte
	buf := make([]byte, syncChunk)
	for {
		n, err := s.Read(buf)
		if n > 0 {
			chunk := append(append([]byte(nil), carry...), buf[:n]...)
			body, tail := cutAtDone(chunk)
			if len(body) > 0 {
				if err := cfg.FS.AppendFile(path, body); err != nil {
					failMsg(s, "%s: %v", path, err)
					return
				}
			}
			carry = tail
		}
		if err != nil {
			failMsg(s, "%s: %v", path, err)
			return
		}
		if len(carry) == 4 {
			mtime := int64(binary.LittleEndian.Uint32(carry))
			_ = cfg.FS.Touch(path, time.Unix(mtime, 0))
			// OKAY carries a length, which is zero here.
			_ = putWord(s, okayW)
			_ = putWord(s, 0)
			return
		}
	}
}

// cutAtDone splits a chunk into file content and a trailing DONE word, keeping the last
// three bytes when no complete word is present.
func cutAtDone(b []byte) (body, tail []byte) {
	for i := 0; i+4 <= len(b); i++ {
		if binary.LittleEndian.Uint32(b[i:i+4]) == doneW {
			return b[:i], append([]byte(nil), b[i:i+4]...)
		}
	}
	if len(b) >= 4 {
		return b[:len(b)-3], append([]byte(nil), b[len(b)-3:]...)
	}
	return b, nil
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
		if _, err := s.Write(data[off:end]); err != nil {
			return
		}
	}
	_ = putWord(s, doneW)
	_, _ = s.Write(make([]byte, 16))
}
