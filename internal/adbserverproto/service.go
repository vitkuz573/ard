package adbserverproto

// Opening a service on a device, from the side that holds the transport.
//
// A device does not accept bytes on a transport: it accepts a named service on it. The
// exchange is CNXN in both directions, then OPEN naming the service, then the stream's own
// bytes travel as WRTE payloads in both directions. So anything that wants a device's
// `tcp:<port>` has to perform that exchange itself, and anything that then wants the device's
// socket has to unwrap the WRTE envelopes.
//
// That is the same work an adb server does for every command it forwards, and it is here
// because two callers need it from the opposite direction to the one that already existed:
// this package's host service relay drives it for an operator's client, and a port forward
// drives it for a socket this server accepted.

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

// OpenService opens one service on a device and returns its stream.
//
// The device's reply names its own stream id in arg0 and this host's in arg1, which is the
// same order every other packet takes: arg0 is the sender. That id is what every later packet
// has to carry in arg1, because the device resolves the stream from arg1.
//
// conn must already be carrying an ADB transport: it sends CNXN, reads the device's own CNXN
// and answers it, then sends OPEN. What comes back is a stream with the transport's envelopes
// removed, so a caller can read the service's bytes directly and write the service's bytes
// back without knowing anything about ADB framing.
//
// The returned conn is not the socket it was handed: it shares it, and closing it closes the
// stream rather than the connection, which is what a caller with a transport for other streams
// needs.
func OpenService(conn net.Conn, service string) (net.Conn, error) {
	br := bufio.NewReader(conn)
	if _, err := conn.Write(encodePacket(cmdCNXN, cnxnArg0, adbMaxData, []byte(hostBanner))); err != nil {
		return nil, fmt.Errorf("send CNXN: %w", err)
	}
	reply, err := readPacket(br)
	if err != nil {
		return nil, fmt.Errorf("read device CNXN: %w", err)
	}
	if reply.command != cmdCNXN {
		return nil, fmt.Errorf("device answered %q where CNXN was expected", reply.command)
	}
	if _, err := conn.Write(encodePacket(cmdOKAY, cnxnArg0, adbMaxData, nil)); err != nil {
		return nil, fmt.Errorf("acknowledge CNXN: %w", err)
	}

	// The payload is the service with a terminating NUL, because a device reads the OPEN
	// payload as a C string and an unterminated name runs into whatever follows.
	open := encodePacket(cmdOPEN, hostLocalID, 0, append([]byte(service), 0))
	if _, err := conn.Write(open); err != nil {
		return nil, fmt.Errorf("send OPEN: %w", err)
	}
	reply, err = readPacket(br)
	if err != nil {
		return nil, fmt.Errorf("read OPEN reply: %w", err)
	}
	if reply.command != cmdOKAY {
		return nil, fmt.Errorf("device answered %q to OPEN %q", reply.command, service)
	}
	// The device chooses its own stream id and announces it here, and every later packet in
	// this direction has to carry it as arg0. A stream whose id stayed zero resolves nothing
	// on the device and its payloads are dropped without a word.
	if reply.arg0 == 0 {
		return nil, fmt.Errorf("device answered OPEN for %q with stream id 0", service)
	}
	// Anything the device sent after the OPEN is already in br: it belongs to this stream,
	// and reading from the connection rather than from br would lose it.
	return &deviceStream{conn: conn, r: br, id: reply.arg0}, nil
}

// deviceStream is one service's bytes on a transport.
//
// Writes become WRTE addressed to the device's stream id; reads take the payload out of the
// WRTE packets for it and acknowledge each one. The acknowledgement is not politeness: a
// device's flow control is its host reading again, so an unacknowledged payload stops the
// device sending rather than failing.
type deviceStream struct {
	conn net.Conn
	r    *bufio.Reader
	id   uint32

	closeOnce sync.Once
}

func (d *deviceStream) Read(p []byte) (int, error) {
	for {
		pkt, err := readPacket(d.r)
		if err != nil {
			return 0, err
		}
		switch pkt.command {
		case cmdWRTE:
			if _, err := d.conn.Write(hostToDevice(cmdOKAY, pkt.arg0, nil)); err != nil {
				return 0, err
			}
			if len(pkt.payload) == 0 {
				continue
			}
			return copy(p, pkt.payload), nil
		case cmdCLSE:
			// The device ended the stream. The close goes back so the device is not left
			// holding one, and then the caller sees the end of the service.
			_, _ = d.conn.Write(hostToDevice(cmdCLSE, d.id, nil))
			return 0, io.EOF
		case cmdOPEN, cmdCNXN, cmdOKAY:
			// Handshake leftovers, or a stream on the same transport this call did not
			// open. Either way there is nothing here to read.
		default:
			// A device may legitimately send STATUS or SYNC on other services; neither
			// belongs to this stream.
		}
	}
}

func (d *deviceStream) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	// Split at the device's limit rather than sending more than it agreed to read: one
	// oversized WRTE is a packet the device rejects, and the bytes after it are lost.
	total := 0
	for total < len(p) {
		end := min(total+adbMaxData, len(p))
		if _, err := d.conn.Write(hostToDevice(cmdWRTE, d.id, p[total:end])); err != nil {
			return total, err
		}
		total = end
	}
	return total, nil
}

func (d *deviceStream) Close() error {
	var err error
	d.closeOnce.Do(func() {
		// The device ends a service when it sees the close. Without it a service reading
		// its input waits for an end that never arrives, and the connection hangs rather
		// than reporting.
		_, err = d.conn.Write(hostToDevice(cmdCLSE, d.id, nil))
	})
	return err
}

func (d *deviceStream) LocalAddr() net.Addr              { return deviceAddr{} }
func (d *deviceStream) RemoteAddr() net.Addr             { return deviceAddr{} }
func (d *deviceStream) SetDeadline(time.Time) error      { return errNoDeadline }
func (d *deviceStream) SetReadDeadline(time.Time) error  { return errNoDeadline }
func (d *deviceStream) SetWriteDeadline(time.Time) error { return errNoDeadline }

// deviceAddr stands in for the socket address of a stream that has none: the service is on a
// device and the transport is a connection, so there is no port to report.
type deviceAddr struct{}

func (deviceAddr) Network() string { return "adb-service" }
func (deviceAddr) String() string  { return "adb-service" }

// errNoDeadline says plainly that a deadline cannot be set on a multiplexed transport's
// stream. Reporting success would tell a caller it had bounded a wait it had not.
var errNoDeadline = fmt.Errorf("adbserverproto: deadlines are not supported on a device stream")

// serviceName is the name an OPEN payload carries, without its terminator.
func serviceName(payload []byte) string {
	return strings.TrimRight(string(payload), "\x00")
}
