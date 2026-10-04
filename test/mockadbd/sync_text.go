package mockadbd

// The text-framed sync protocol.
//
// This is what a current adb actually speaks. The legacy binary protocol in sync.go is
// correct for what it implements and older clients use it, but it is not what
// `adb push` does today, and that was established from a trace rather than from
// documentation:
//
//	runSync request id=843142227 (0x32415453)
//
// 0x32415453 is ASCII "STA2". Commands are four literal characters read as a little-endian
// word, not the integer ids of the classic protocol.
//
// The framing difference that matters most: paths carry an explicit 4-byte length and no
// NUL terminator. Confirmed by measurement rather than assumed -- the byte following STA2
// in that trace was 0x1a, and the path in the failing test was 26 characters.
//
// STATUS: STA2 is confirmed and parses correctly against the real adb binary. The reply
// shape is not.
//
// After a correct STA2 read, adb does not send its next command and does not report a
// fault either -- it blocks, waiting for more of a stat reply than 16 bytes. That matters
// beyond this file: while adb reported faults, each attempt revealed the next rule, so the
// protocol could be derived one fact at a time. Once it blocks instead, the loop yields
// nothing per attempt, and guessing a reply length is exactly the failure this commit was
// written about. The reply shape needs the specification.
//
// Reaching STA2 at all took two fixes that are worth recording, because both came from
// the trace rather than from the documentation:
//
//   - the command words are var, not const: a typed constant cannot be built from a call.
//   - the service is opened as "sync", with no colon.

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"time"
)

// Command words are four ASCII characters packed little-endian, so a word can be compared
// to ID('S','N','D','2') directly.
// Vars, not consts: id() is a function and a typed constant cannot be built from a call.
var (
	snd2  uint32 = id('S', 'N', 'D', '2')
	rcv2  uint32 = id('R', 'C', 'V', '2')
	sta2  uint32 = id('S', 'T', 'A', '2')
	lst2  uint32 = id('L', 'S', 'T', '2')
	dnt2  uint32 = id('D', 'N', 'T', '2')
	dne2  uint32 = id('D', 'N', 'E', '2')
	quit2 uint32 = id('Q', 'U', 'I', 'T')
	rsp2  uint32 = id('R', 'S', 'P', '2')

	okay2 uint32 = id('O', 'K', 'A', 'Y')
	fail2 uint32 = id('F', 'A', 'I', 'L')
	stat2 uint32 = id('S', 'T', 'A', 'T')
	done2 uint32 = id('D', 'O', 'N', 'E')
)

func id(a, b, c, d byte) uint32 {
	return uint32(a) | uint32(b)<<8 | uint32(c)<<16 | uint32(d)<<24
}

func idName(v uint32) string {
	return string([]byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)})
}

// runSync2 serves one sync stream in the text protocol.
func runSync2(cfg Config, s *stream) {
	for {
		cmd, err := readWord(s)
		if err != nil {
			if err != io.EOF {
				cfg.debug("sync: read command: %v", err)
			}
			return
		}
		tracef("sync2 command=%s (0x%08x)", idName(cmd), cmd)

		switch cmd {
		case quit2:
			return

		case sta2:
			path, err := readLenString(s)
			if err != nil {
				return
			}
			sync2Stat(cfg, s, path)

		case lst2:
			path, err := readLenString(s)
			if err != nil {
				return
			}
			sync2List(cfg, s, path)

		case snd2:
			path, err := readLenString(s)
			if err != nil {
				return
			}
			mode, err := readWord(s)
			if err != nil {
				return
			}
			sync2Send(cfg, s, path, os.FileMode(mode))

		case rcv2:
			path, err := readLenString(s)
			if err != nil {
				return
			}
			sync2Recv(cfg, s, path)

		default:
			rspFail(s, "unknown command %q", idName(cmd))
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

// readLenString reads a 4-byte length followed by exactly that many bytes.
//
// No NUL: the length makes one redundant, and treating the first length byte as a
// character is exactly how the trace showed this protocol being mis-parsed.
func readLenString(r io.Reader) (string, error) {
	n, err := readWord(r)
	if err != nil {
		return "", err
	}
	if n > 4096 {
		return "", fmt.Errorf("sync: path length %d is implausible", n)
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

func rspOkay(s *stream) error {
	if err := putWord(s, rsp2); err != nil {
		return err
	}
	return putWord(s, okay2)
}

func rspFail(s *stream, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	_ = putWord(s, rsp2)
	_ = putWord(s, fail2)
	var n [4]byte
	binary.LittleEndian.PutUint32(n[:], uint32(len(msg)))
	_, _ = s.Write(append(n[:], msg...))
}

func sync2Stat(cfg Config, s *stream, path string) {
	n, err := cfg.FS.Stat(path)
	if err != nil {
		rspFail(s, "%s: no such file or directory", path)
		return
	}
	_ = putWord(s, rsp2)
	_ = putWord(s, stat2)
	var b [12]byte
	binary.LittleEndian.PutUint32(b[0:4], statMode(n.Dir, n.Mode))
	binary.LittleEndian.PutUint32(b[4:8], uint32(len(n.Data)))
	binary.LittleEndian.PutUint32(b[8:12], uint32(n.ModTime.Unix()))
	_, _ = s.Write(b[:])
}

func sync2List(cfg Config, s *stream, path string) {
	entries, err := cfg.FS.ReadDir(path)
	if err != nil {
		rspFail(s, "%s: no such directory", path)
		return
	}
	if err := rspOkay(s); err != nil {
		return
	}
	for _, e := range entries {
		var b [12]byte
		binary.LittleEndian.PutUint32(b[0:4], statMode(e.Dir, e.Mode))
		binary.LittleEndian.PutUint32(b[4:8], uint32(len(e.Data)))
		binary.LittleEndian.PutUint32(b[8:12], uint32(e.ModTime.Unix()))
		var ln [4]byte
		binary.LittleEndian.PutUint32(ln[:], uint32(len(e.Name)))
		if err := putWord(s, dnt2); err != nil {
			return
		}
		_, _ = s.Write(append(append(b[:], ln[:]...), e.Name...))
	}
	_ = putWord(s, dne2)
}

// sync2Send receives a push.
//
// The body is raw bytes with no framing: the transfer is terminated by a DNE2 word, not
// by a length, because the sender knows the file length and the device does not need to be
// told per chunk. So the file is read in blocks until that word appears in the stream.
func sync2Send(cfg Config, s *stream, path string, mode os.FileMode) {
	if err := cfg.FS.EnsureFile(path, mode); err != nil {
		rspFail(s, "%s: %v", path, err)
		return
	}
	var carried []byte
	buf := make([]byte, syncChunk)
	for {
		n, err := s.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			// A trailing DNE2 may share a read with file content, so any bytes after the
			// last complete word are held back for the next pass rather than written.
			body, tail := splitAtDone(chunk)
			if len(body) > 0 {
				if err := cfg.FS.AppendFile(path, body); err != nil {
					rspFail(s, "%s: %v", path, err)
					return
				}
			}
			carried = append(carried[:0], tail...)
		}
		if err != nil {
			rspFail(s, "%s: %v", path, err)
			return
		}
		if len(carried) >= 4 {
			if binary.LittleEndian.Uint32(carried) == dne2 {
				if err := rspOkay(s); err != nil {
					return
				}
				_ = cfg.FS.Touch(path, time.Unix(0, 0))
				return
			}
			// Not the terminator, so these bytes were content after all.
			if err := cfg.FS.AppendFile(path, carried); err != nil {
				rspFail(s, "%s: %v", path, err)
				return
			}
			carried = carried[:0]
		}
	}
}

// splitAtDone separates file content from a trailing partial command word.
func splitAtDone(b []byte) (body, tail []byte) {
	if len(b) < 4 {
		return b, nil
	}
	for i := 0; i+4 <= len(b); i++ {
		if binary.LittleEndian.Uint32(b[i:i+4]) == dne2 {
			return b[:i], append([]byte(nil), b[i:]...)
		}
	}
	// Keep the last three bytes: they may be the start of a word split across reads.
	if len(b) >= 4 {
		return b[:len(b)-3], append([]byte(nil), b[len(b)-3:]...)
	}
	return b, nil
}

// sync2Recv answers a pull.
//
// The contents travel as DATA words with a length each, and the transfer ends with DONE,
// which is the same shape the legacy path used. What differs is the envelope: the reply
// word comes first, so a client knows whether it is getting a file or an error before any
// bytes of it arrive.
func sync2Recv(cfg Config, s *stream, path string) {
	data, err := cfg.FS.ReadFile(path)
	if err != nil {
		rspFail(s, "%s: no such file", path)
		return
	}
	if err := rspOkay(s); err != nil {
		return
	}
	for off := 0; off < len(data); off += syncChunk {
		end := off + syncChunk
		if end > len(data) {
			end = len(data)
		}
		if err := putWord(s, syncData); err != nil {
			return
		}
		var ln [4]byte
		binary.LittleEndian.PutUint32(ln[:], uint32(end-off))
		if _, err := s.Write(ln[:]); err != nil {
			return
		}
		if _, err := s.Write(data[off:end]); err != nil {
			return
		}
		if err := putWord(s, syncOkay); err != nil {
			return
		}
	}
	_ = putWord(s, done2)
	_ = rspOkay(s)
}
