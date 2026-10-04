package mockadbd_test

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"github.com/vitaly/ard/test/mockadbd"
)

// These tests drive the mock with a Go implementation of the host side of the
// protocol. They cover paths the adb command line does not drive conveniently:
// notably the exact moment stdin EOF is signalled, and frames that arrive split
// across packets.
//
// Interop with the real adb binary is covered separately in interop_test.go.
// Both matter: these tests are deterministic, while the interop test proves the
// mock matches what adb actually speaks.

// hostPacket mirrors the fields a Go host needs to track.
type hostPacket struct {
	cmd  uint32
	arg0 uint32
	arg1 uint32
	data []byte
}

// host is a minimal ADB host connection.
type host struct {
	t    *testing.T
	conn net.Conn
	rd   io.Reader

	// nextID is the local stream id counter, as adbd uses.
	nextID uint32
	// version is the negotiated protocol version.
	version uint32
	// streams maps a host stream id to the device stream id it was paired with.
	streams map[uint32]uint32
}

func dialHost(t *testing.T, addr string) *host {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial mock: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	return &host{t: t, conn: c, rd: c, streams: map[uint32]uint32{}}
}

func (h *host) magic(cmd uint32) uint32 { return cmd ^ 0xFFFFFFFF }

func (h *host) writePacket(cmd, arg0, arg1 uint32, data []byte) {
	h.t.Helper()
	var hdr [24]byte
	le(hdr[0:4], cmd)
	le(hdr[4:8], arg0)
	le(hdr[8:12], arg1)
	le(hdr[12:16], uint32(len(data)))
	// data_check is zero at or above the skip-checksum version.
	le(hdr[16:20], 0)
	le(hdr[20:24], h.magic(cmd))
	if _, err := h.conn.Write(hdr[:]); err != nil {
		h.t.Fatalf("write header: %v", err)
	}
	if len(data) > 0 {
		if _, err := h.conn.Write(data); err != nil {
			h.t.Fatalf("write payload: %v", err)
		}
	}
}

func le(b []byte, v uint32) {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
}

func (h *host) readPacket() hostPacket {
	h.t.Helper()
	var hdr [24]byte
	if _, err := io.ReadFull(h.rd, hdr[:]); err != nil {
		h.t.Fatalf("read header: %v", err)
	}
	p := hostPacket{
		cmd:  le32(hdr[0:4]),
		arg0: le32(hdr[4:8]),
		arg1: le32(hdr[8:12]),
	}
	n := le32(hdr[12:16])
	if got := le32(hdr[20:24]); got != h.magic(p.cmd) {
		h.t.Fatalf("magic mismatch for cmd 0x%08x: got 0x%08x want 0x%08x", p.cmd, got, h.magic(p.cmd))
	}
	if n > 0 {
		p.data = make([]byte, n)
		if _, err := io.ReadFull(h.rd, p.data); err != nil {
			h.t.Fatalf("read payload: %v", err)
		}
	}
	return p
}

func le32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

// handshake performs the CNXN exchange and returns the negotiated version.
func (h *host) handshake() uint32 {
	h.t.Helper()
	const cmdCNXN = 0x4e584e43
	h.writePacket(cmdCNXN, 0x01000001, 1<<20, []byte("host::features=cmd,shell_v2"))
	p := h.readPacket()
	if p.cmd != cmdCNXN {
		h.t.Fatalf("expected CNXN, got 0x%08x", p.cmd)
	}
	h.version = p.arg0
	return p.arg0
}

// open issues an OPEN and returns the host stream id, once the device acknowledges.
func (h *host) open(service string) uint32 {
	h.t.Helper()
	const cmdOPEN, cmdOKAY = 0x4e45504f, 0x59414b4f
	h.nextID++
	id := h.nextID
	h.writePacket(cmdOPEN, id, 0, append([]byte(service), 0))

	// The device answers OKAY; its arg1 is our id.
	for {
		p := h.readPacket()
		if p.cmd == cmdOKAY && p.arg1 == id {
			h.streams[id] = p.arg0
			return id
		}
	}
}

// sendV2 writes one shell v2 frame.
func (h *host) sendV2(id uint32, frameID byte, payload []byte) {
	h.t.Helper()
	const cmdWRTE = 0x45545257
	frame := make([]byte, 5+len(payload))
	frame[0] = frameID
	le(frame[1:5], uint32(len(payload)))
	copy(frame[5:], payload)
	h.writePacket(cmdWRTE, id, h.streams[id], frame)
}

func (h *host) closeStream(id uint32) {
	const cmdCLSE = 0x45534c43
	h.writePacket(cmdCLSE, id, h.streams[id], nil)
}

// collect reads packets until the stream closes, decoding shell v2 output.
func (h *host) collect(id uint32, timeout time.Duration) (stdout string, exitCode int, closed bool) {
	const (
		cmdWRTE = 0x45545257
		cmdCLSE = 0x45534c43
	)
	var out bytes.Buffer
	var buf []byte
	exitCode = -1
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		_ = h.conn.SetReadDeadline(deadline)
		p := h.readPacket()
		switch p.cmd {
		case cmdWRTE:
			if len(p.data) == 0 {
				continue
			}
			// Frames may be split across packets, so accumulate on the host side
			// too and drain every complete frame.
			buf = append(buf, p.data...)
			for {
				if len(buf) < 5 {
					break
				}
				n := int(le32(buf[1:5]))
				if n < 0 || n > 1<<20 || len(buf) < 5+n {
					break
				}
				frame := buf[:5+n]
				buf = buf[5+n:]
				switch frame[0] {
				case 1: // stdout
					out.Write(frame[5:])
				case 3: // exit
					if n > 0 {
						exitCode = int(frame[5])
					}
				}
			}
			if len(buf) == 0 {
				buf = nil
			}
		case cmdCLSE:
			// The device CLSEs with our id in arg1. Stopping on arg0 as well was
			// wrong: the device uses arg0 for its own id, and both are equal here
			// by coincidence, which is why it appeared to work. Any stream where
			// the two ids differ would terminate the wrong transfer.
			if p.arg1 == id {
				return out.String(), exitCode, true
			}
		}
	}
	return out.String(), exitCode, closed
}

func TestHostShellOutput(t *testing.T) {
	l, err := mockadbd.Listen("127.0.0.1:0", mockadbd.Config{})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()

	h := dialHost(t, l.Addr().String())
	if v := h.handshake(); v < 0x01000000 {
		t.Fatalf("implausible negotiated version 0x%08x", v)
	}

	id := h.open("shell,v2,TERM=xterm-256color,raw:echo hello")
	stdout, code, closed := h.collect(id, 5*time.Second)
	if !closed {
		t.Fatal("stream never closed")
	}
	if stdout != "hello\n" {
		t.Errorf("stdout = %q, want %q", stdout, "hello\n")
	}
	if code != 0 {
		t.Errorf("exit = %d, want 0", code)
	}
}

// stdin must reach the command, and the command must observe EOF when the host
// sends kIdCloseStdin. Both halves matter: without the first the command sees no
// data, and without the second a reader blocks forever.
func TestHostStdinRoundTripAndEOF(t *testing.T) {
	l, err := mockadbd.Listen("127.0.0.1:0", mockadbd.Config{})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()

	h := dialHost(t, l.Addr().String())
	h.handshake()
	id := h.open("shell,v2,TERM=xterm-256color,raw:cat")

	payload := []byte("data-through-stdin\n")
	h.sendV2(id, 0, payload) // kIdStdin
	h.sendV2(id, 4, nil)     // kIdCloseStdin
	h.closeStream(id)

	stdout, _, closed := h.collect(id, 5*time.Second)
	if !closed {
		t.Fatal("stream never closed; the command is probably blocked on stdin")
	}
	if stdout != string(payload) {
		t.Errorf("stdout = %q, want %q", stdout, payload)
	}
}

// A large stdin transfer arrives as many packets, and frames may straddle packet
// boundaries. This is the case that breaks an implementation which decodes
// exactly one frame per packet.
func TestHostLargeStdinAcrossPackets(t *testing.T) {
	l, err := mockadbd.Listen("127.0.0.1:0", mockadbd.Config{})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()

	h := dialHost(t, l.Addr().String())
	h.handshake()
	id := h.open("shell,v2,TERM=xterm-256color,raw:cat")

	// Deliberately split one frame across two writes so the device must buffer.
	big := bytes.Repeat([]byte("0123456789"), 4000) // 40000 bytes
	frame := make([]byte, 5+len(big))
	frame[0] = 0
	le(frame[1:5], uint32(len(big)))
	copy(frame[5:], big)

	const cmdWRTE = 0x45545257
	h.writePacket(cmdWRTE, id, h.streams[id], frame[:17])
	h.writePacket(cmdWRTE, id, h.streams[id], frame[17:])

	h.sendV2(id, 4, nil) // close stdin
	h.closeStream(id)

	stdout, _, closed := h.collect(id, 10*time.Second)
	if !closed {
		t.Fatal("stream never closed")
	}
	if stdout != string(big) {
		t.Errorf("stdout length = %d, want %d (content match: %v)",
			len(stdout), len(big), stdout == string(big))
	}
}

// Two frames packed into a single WRTE must both be handled. Real hosts do this
// when the last stdin chunk and kIdCloseStdin go out together.
func TestHostPackedFramesInOnePacket(t *testing.T) {
	l, err := mockadbd.Listen("127.0.0.1:0", mockadbd.Config{})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()

	h := dialHost(t, l.Addr().String())
	h.handshake()
	id := h.open("shell,v2,TERM=xterm-256color,raw:cat")

	const cmdWRTE = 0x45545257
	body := []byte("packed\n")
	// One packet: [id=0 len=7 "packed\n"][id=4 len=0]
	// Build the frames with the same little-endian helper used everywhere else.
	// Hand-rolling `byte(len(body))` happens to work for short inputs and breaks
	// the moment a length exceeds 255, which is exactly the kind of bug that only
	// shows up under a large transfer.
	pkt := make([]byte, 0, 5+len(body)+5)
	pkt = append(pkt, 0)
	var lenBuf [4]byte
	le(lenBuf[:], uint32(len(body)))
	pkt = append(pkt, lenBuf[:]...)
	pkt = append(pkt, body...)
	pkt = append(pkt, 4, 0, 0, 0, 0)
	h.writePacket(cmdWRTE, id, h.streams[id], pkt)
	h.closeStream(id)

	stdout, _, closed := h.collect(id, 5*time.Second)
	if !closed {
		t.Fatal("stream never closed; the packed CloseStdin was not honoured")
	}
	if stdout != "packed\n" {
		t.Errorf("stdout = %q, want %q", stdout, "packed\n")
	}
}

func TestHostExitStatus(t *testing.T) {
	l, err := mockadbd.Listen("127.0.0.1:0", mockadbd.Config{})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()

	cases := []struct {
		cmd  string
		want int
	}{
		{"true", 0},
		{"false", 1},
		{"definitely-not-a-real-command", 127},
	}
	for _, tc := range cases {
		t.Run(tc.cmd, func(t *testing.T) {
			h := dialHost(t, l.Addr().String())
			h.handshake()
			id := h.open("shell,v2,TERM=xterm-256color,raw:" + tc.cmd)
			_, code, closed := h.collect(id, 5*time.Second)
			if !closed {
				t.Fatal("stream never closed")
			}
			if code != tc.want {
				t.Errorf("exit = %d, want %d", code, tc.want)
			}
		})
	}
}

// A rejected service must close the stream rather than leave the host waiting.
func TestHostUnknownServiceIsClosed(t *testing.T) {
	l, err := mockadbd.Listen("127.0.0.1:0", mockadbd.Config{})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()

	h := dialHost(t, l.Addr().String())
	h.handshake()
	id := h.open("definitely-not-a-service:whatever")
	_, _, closed := h.collect(id, 5*time.Second)
	if !closed {
		t.Fatal("unknown service left the stream open")
	}
}
