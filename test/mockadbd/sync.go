package mockadbd

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

// The sync service's integer command ids, plus the two pieces of framing that the
// text-framed service in sync_text.go shares with them.
//
// A command on this wire is four literal characters, read as a little-endian word through
// MKID, so what arrives from a client is STA2, LST2, SND2, RCV2 and the rest -- not the
// integers named below. sync_text.go is the service the dispatcher opens, and it answers
// every spelling of a request, because which one a client uses is decided by the feature
// list it was given for the device rather than by the device: a client told stat_v2 sends
// STA2 and SND2, and a client told nothing sends STAT and SEND, and both spellings are
// answered from the same filesystem.
//
// What lives here is what both spellings need. syncChunk is how much of a file travels in
// one DATA frame; adbd uses 64 KiB, and matching it means a relay tested against this device
// sees the frame sizes it will see in the field and a reassembly bug cannot hide behind an
// unusually large frame. statMode folds the file type into the mode word the way stat(2)
// does, because a client decides whether to recurse by testing that bit and a directory
// reported without it is pulled as an empty file.

const (
	syncStat   uint32 = 1 // path -> mode, size, mtime
	syncLstat2 uint32 = 2 // symlink stat, kept distinct from LIST2: conflating them
	syncList2  uint32 = 3 // path -> repeated entries, then DONE
	syncSend   uint32 = 4 // "path,mode" -> DATA frames -> DONE with mtime
	syncDone   uint32 = 5
	syncData   uint32 = 6
	syncOkay   uint32 = 7
	syncFail   uint32 = 8
	syncRecv   uint32 = 9 // path -> DATA frames -> DONE
	syncQuit   uint32 = 10
)

// syncChunk is how much of a file travels in one DATA frame.
//
// adbd uses 64 KiB. Larger frames are legal and faster; this matches the platform so a
// relay tested against the mock sees the same frame sizes it will see in the field, and
// so a bug in reassembly cannot hide behind an unusually large frame.
const syncChunk = 64 * 1024

// runSync serves one sync stream.
func runSync(cfg Config, arg string, s *stream) {
	// "sync:version=1" and friends. The version selects LST2 over LST; ignoring it means
	// a client that asked for the newer listing silently gets the older one, which works
	// but tests nothing about the path real clients take.
	defer s.close(nil)

	tracef("runSync started arg=%q", arg)
	for {
		id, payload, err := readSyncRequest(s)
		if err != nil {
			tracef("runSync read request: %v", err)
			if err != io.EOF {
				cfg.debug("sync: read request: %v", err)
			}
			return
		}

		tracef("runSync request id=%d (0x%08x) raw=%q", id, id, payload)
		switch id {
		case syncQuit:
			return

		case syncStat:
			syncStatPath(cfg, s, payload)

		case syncList2:
			syncList(cfg, s, payload)

		case syncSend:
			syncSendFile(cfg, s, payload)

		case syncRecv:
			syncRecvFile(cfg, s, payload)

		case syncOkay:
			// Acknowledgement from the host for a SEND we already handled. Nothing to do:
			// the data has been consumed by now, which is the whole point of writing the
			// file as it arrives rather than buffering it.
			cfg.debug("sync: host acknowledged")

		default:
			syncFailf(s, "unknown sync request %d", id)
			return
		}
	}
}

// readSyncRequest reads a 4-byte id plus a NUL-terminated argument.
func readSyncRequest(s *stream) (uint32, string, error) {
	var head [4]byte
	if _, err := io.ReadFull(s, head[:]); err != nil {
		return 0, "", err
	}
	id := binary.LittleEndian.Uint32(head[:])
	arg, err := readCString(s)
	if err != nil {
		return 0, "", err
	}
	return id, arg, nil
}

// readCString reads up to a NUL. adbd reads byte by byte, and it matters: paths are short
// but a client that forgot the terminator would otherwise make this read until it happens
// to see a zero byte in file content.
func readCString(s *stream) (string, error) {
	var out []byte
	buf := make([]byte, 1)
	for {
		if _, err := io.ReadFull(s, buf); err != nil {
			return "", err
		}
		if buf[0] == 0 {
			return string(out), nil
		}
		out = append(out, buf[0])
		if len(out) > 4096 {
			return "", fmt.Errorf("sync: argument is not terminated")
		}
	}
}

func writeSyncHeader(w io.Writer, id uint32) error {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], id)
	_, err := w.Write(b[:])
	return err
}

func writeSyncOkay(w io.Writer, id uint32) error {
	if err := writeSyncHeader(w, syncOkay); err != nil {
		return err
	}
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], id)
	_, err := w.Write(b[:])
	return err
}

// syncFailf reports a failure the way adbd does: FAIL, a 4-byte length, then the message.
func syncFailf(s *stream, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	var head [8]byte
	binary.LittleEndian.PutUint32(head[0:4], syncFail)
	binary.LittleEndian.PutUint32(head[4:8], uint32(len(msg)))
	_, _ = s.Write(append(head[:], msg...))
}

// syncStatPath answers STAT for one path.
func syncStatPath(cfg Config, s *stream, p string) {
	tracef("syncStat %q", p)
	n, err := cfg.FS.Stat(p)
	if err != nil {
		syncFailf(s, "%s: no such file or directory", p)
		return
	}
	// STAT's reply is STAT followed by mode, size and mtime, all 4-byte little-endian.
	var b [12]byte
	binary.LittleEndian.PutUint32(b[0:4], statMode(n.Dir, n.Mode))
	binary.LittleEndian.PutUint32(b[4:8], uint32(len(n.Data)))
	binary.LittleEndian.PutUint32(b[8:12], uint32(n.ModTime.Unix()))
	if err := writeSyncHeader(s, syncStat); err != nil {
		return
	}
	_, _ = s.Write(b[:])
}

// syncList answers a directory listing.
//
// LST2 replaced the older LST because the old form cannot represent a name containing
// most byte values, so a name is length-prefixed here rather than NUL-terminated. Getting
// that wrong does not fail on ASCII names, which is why it is worth doing properly rather
// than only for the paths a test happens to use.
func syncList(cfg Config, s *stream, p string) {
	entries, err := cfg.FS.ReadDir(p)
	if err != nil {
		syncFailf(s, "%s: no such directory", p)
		return
	}
	for _, e := range entries {
		var b [12]byte
		binary.LittleEndian.PutUint32(b[0:4], statMode(e.Dir, e.Mode))
		binary.LittleEndian.PutUint32(b[4:8], uint32(len(e.Data)))
		binary.LittleEndian.PutUint32(b[8:12], uint32(e.ModTime.Unix()))

		// LIST2 length-prefixes the name, so a name may contain any byte value. The older
		// form was NUL-terminated and could not represent one containing a zero. Entries
		// carry the STAT header in both forms; only the name encoding differs.
		var ln [4]byte
		binary.LittleEndian.PutUint32(ln[:], uint32(len(e.Name)))
		if err := writeSyncHeader(s, syncStat); err != nil {
			return
		}
		_, _ = s.Write(append(append(b[:], ln[:]...), e.Name...))
	}
	// DONE carries 16 zero bytes, not an empty payload. The header is 24 bytes on the
	// wire but only 4 carry this command, so the terminator is padded to the older
	// 16-byte shape that clients still expect.
	var done [16]byte
	if err := writeSyncHeader(s, syncDone); err != nil {
		return
	}
	_, _ = s.Write(done[:])
}

// statMode folds the directory bit into the mode word, the way stat(2) does.
//
// It is not cosmetic: adb decides whether to recurse by testing this bit, so a directory
// reported without it is pulled as an empty file.
func statMode(dir bool, mode os.FileMode) uint32 {
	m := uint32(mode.Perm())
	if dir {
		m |= 0o040000 // S_IFDIR
	} else {
		m |= 0o100000 // S_IFREG
	}
	return m
}

// syncSendFile receives a push.
//
// The file is written as the data arrives rather than buffered whole, because a push of a
// multi-gigabyte apk must not require multi-gigabytes of memory to simulate.
func syncSendFile(cfg Config, s *stream, arg string) {
	target, mode, err := parseSendArg(arg)
	if err != nil {
		syncFailf(s, "%v", err)
		return
	}
	// adb sends the mode the destination should end up with. Applying it matters for a
	// test that checks what a push produced: a file that lands 0644 when 0600 was asked
	// for is a real difference on a device.
	if err := cfg.FS.EnsureFile(target, mode); err != nil {
		syncFailf(s, "%s: %v", target, err)
		return
	}
	for {
		id, err := readSyncID(s)
		if err != nil {
			_ = writeSyncOkay(s, syncData)
			return
		}
		switch id {
		case syncData:
			n, err := readSyncLength(s)
			if err != nil {
				_ = writeSyncOkay(s, syncData)
				return
			}
			if n > 64*1024*1024 {
				// Refuse an absurd length rather than allocate it. The payload may not
				// actually follow, and trusting the header is how a peer allocates
				// whatever it likes.
				syncFailf(s, "data frame of %d bytes is implausible", n)
				return
			}
			chunk := make([]byte, n)
			if _, err := io.ReadFull(s, chunk); err != nil {
				_ = writeSyncOkay(s, syncData)
				return
			}
			if err := cfg.FS.AppendFile(target, chunk); err != nil {
				syncFailf(s, "%s: %v", target, err)
				return
			}
			if err := writeSyncOkay(s, syncData); err != nil {
				return
			}

		case syncDone:
			mtime := time.Unix(0, 0)
			ts, err := readSyncMTime(s)
			if err == nil && ts > 0 {
				mtime = time.Unix(ts, 0)
			}
			_ = cfg.FS.Touch(target, mtime)
			_ = writeSyncOkay(s, syncDone)
			return

		case syncFail:
			// The host gave up partway. Leave whatever arrived, which is what a real
			// filesystem does with a truncated upload, and report the failure back.
			_, _ = readSyncLength(s)
			return

		default:
			return
		}
	}
}

// parseSendArg splits "path,mode", the form adb uses for a push destination.
func parseSendArg(arg string) (string, os.FileMode, error) {
	i := strings.LastIndex(arg, ",")
	if i < 0 {
		return "", 0, fmt.Errorf("sync: malformed send argument %q", arg)
	}
	m, err := strconv.ParseUint(arg[i+1:], 8, 32)
	if err != nil {
		return "", 0, fmt.Errorf("sync: malformed mode in %q", arg)
	}
	return arg[:i], os.FileMode(m), nil
}

// syncRecvFile answers a pull.
func syncRecvFile(cfg Config, s *stream, p string) {
	data, err := cfg.FS.ReadFile(p)
	if err != nil {
		syncFailf(s, "%s: no such file", p)
		return
	}
	for off := 0; off < len(data); off += syncChunk {
		end := off + syncChunk
		if end > len(data) {
			end = len(data)
		}
		if err := writeSyncHeader(s, syncData); err != nil {
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
		// Each DATA frame is acknowledged, so a pull cannot outrun the transport.
		if err := writeSyncOkay(s, syncData); err != nil {
			return
		}
	}
	var done [16]byte
	if err := writeSyncHeader(s, syncDone); err != nil {
		return
	}
	_, _ = s.Write(done[:])
	_ = writeSyncOkay(s, syncRecv)
}

func readSyncID(s *stream) (uint32, error) {
	var b [4]byte
	if _, err := io.ReadFull(s, b[:]); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b[:]), nil
}

func readSyncLength(s *stream) (uint32, error) {
	var b [4]byte
	if _, err := io.ReadFull(s, b[:]); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b[:]), nil
}

func readSyncMTime(s *stream) (int64, error) {
	v, err := readSyncLength(s)
	return int64(v), err
}
