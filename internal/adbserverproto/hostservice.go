package adbserverproto

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"strings"
)

// serveHostService is what a connection becomes after a smart-socket switch.
//
// The client does not open the device. It sends a service request -- `000cshell:whoami` --
// and expects the server to have done the talking to the device already, then answers
// `OKAYshell\n` and hands over a plain stream. Measured against the stock server:
//
//	client -> server  000cshell:whoami
//	server -> device  CNXN  arg0=0x01000001 arg1=4096 banner="host::features=..."
//	device -> server  CNXN  arg0=0x01000001 arg1=4096 banner="device::..."
//	server -> device  OKAY
//	server -> device  OPEN  arg0=<local id> "<service>\0"
//	device -> server  OKAY
//	server -> client  OKAYshell\n
//
// After that the stream is raw and length-prefixed in both directions: the device's WRTE
// payloads are what the client sees, with their four-byte lengths, and whatever the client
// sends is wrapped in WRTE before it reaches the device. Forwarding the envelopes instead
// would leave the client parsing its own transport as shell output.
//
// This is only used for host:tport. A host:transport connection keeps the raw form, because
// that is what the client expects there and the two are not interchangeable.
func (s *Server) serveHostService(c net.Conn, dev net.Conn, prefix []byte) error {
	br := bufio.NewReader(c)
	// Bytes taken while parsing the tport request belong to the service request, which is
	// the next thing on this connection, not to a device transport.
	var src io.Reader = br
	if len(prefix) > 0 {
		src = io.MultiReader(bytes.NewReader(prefix), br)
	}
	svc := bufio.NewReader(src)

	service, err := readRequest(svc)
	if err != nil {
		return fmt.Errorf("read service request: %w", err)
	}
	// Which service was requested is worth one line: it is the only thing that distinguishes
	// `adb shell whoami` from `adb push` in the log, and without it a session that opens a
	// transport and delivers nothing has nothing to explain it.
	s.debugf("adbserverproto: service %q on a switched transport", service)

	dbr := bufio.NewReader(dev)
	streamID, err := s.handshake(dbr, dev, service)
	if err != nil {
		return err
	}

	// The acknowledgement is a bare OKAY on a switched transport.
	//
	// It looks like the host:service form, "OKAYshell\n", and it is not. That form belongs
	// to the old host socket, where the client had not connected to anything yet. Measured:
	// a stock server answers a raw "000cshell:whoami" with "OKAYshell\n", but a real adb
	// client that has just switched transports gets no banner, and printing one is
	// visible immediately -- `adb shell whoami` came back as "shellshell", the banner and
	// the output, because the client echoed the banner instead of swallowing it.
	if _, err := c.Write([]byte(okayToken)); err != nil {
		return err
	}
	return s.pumpHostStream(c, dev, br, dbr, streamID)
}

// handshake performs the CNXN and OPEN exchange with the device. It returns the stream id
// the device assigned, which every subsequent packet in this direction must carry.
//
// Measured, for the OPEN exchange:
//
//	host  -> device  OPEN arg0=<host id>  arg1=0             "<service>\0"
//	device -> host   OKAY arg0=<device id> arg1=<host id>
//
// The device chooses its own stream id and announces it here; the host never picks it. That
// is not a detail: a packet the host sends carries the destination in arg0 and the source in
// arg1, so a WRTE written as arg0=<host id> arg1=0 names a device stream that does not exist.
// The device looks the stream up in arg1, finds nothing, and drops the payload silently --
// `adb shell cat` then reads no input at all and blocks forever, with no error anywhere. The
// stock server's exchange, captured:
//
//	WRTE arg0=0x73 arg1=0x1e "..."      <- the host id is 0x73, the device's is 0x1e
func (s *Server) handshake(br *bufio.Reader, dev net.Conn, service string) (uint32, error) {
	if _, err := dev.Write(encodePacket(cmdCNXN, cnxnArg0, adbMaxData, []byte(hostBanner))); err != nil {
		return 0, fmt.Errorf("send CNXN: %w", err)
	}
	reply, err := readPacket(br)
	if err != nil {
		return 0, fmt.Errorf("read device CNXN: %w", err)
	}
	if reply.command != cmdCNXN {
		return 0, fmt.Errorf("device answered %q where CNXN was expected", reply.command)
	}
	// The device's banner, logged because it is where the shell v2 negotiation is decided:
	// a device that does not list shell_v2 answers every command without a status frame, and
	// that presents as this relay dropping the exit code.
	s.debugf("adbserverproto: device says %q", string(reply.payload))

	if _, err := dev.Write(encodePacket(cmdOKAY, cnxnArg0, adbMaxData, nil)); err != nil {
		return 0, fmt.Errorf("acknowledge CNXN: %w", err)
	}

	// The payload is the service with a terminating NUL. A device reads the OPEN payload as
	// a C string, so without it the name runs into whatever follows.
	open := encodePacket(cmdOPEN, hostLocalID, 0, append([]byte(service), 0))
	if _, err := dev.Write(open); err != nil {
		return 0, fmt.Errorf("send OPEN: %w", err)
	}
	reply, err = readPacket(br)
	if err != nil {
		return 0, fmt.Errorf("read OPEN reply: %w", err)
	}
	if reply.command != cmdOKAY {
		return 0, fmt.Errorf("device answered %q to OPEN %q", reply.command, service)
	}
	if reply.arg0 == 0 {
		return 0, fmt.Errorf("device answered OPEN for %q with stream id 0", service)
	}
	return reply.arg0, nil
}

// hostLocalID is the stream id this server claims when it opens a stream of its own. The
// device only echoes it back, so any non-zero value identifies the stream consistently.
const hostLocalID = 1

// pumpHostStream relays raw, length-prefixed data in both directions for as long as the
// service runs.
//
// The device side is unframed here on purpose: the WRTE envelopes are unwrapped, and the
// four-byte length each payload carries is kept, because that length is part of the stream
// the client reads rather than part of the transport around it.
func (s *Server) pumpHostStream(c net.Conn, dev net.Conn, cbr *bufio.Reader, dbr *bufio.Reader, devID uint32) error {
	errc := make(chan error, 2)

	go func() {
		// Device to client: the transport envelope comes off and the payload goes across
		// as it is.
		//
		// The payload is not length-prefixed here. A client that has just switched
		// transports reads a raw stream, and a four-byte length put in front of the data
		// is not stripped by anything: it comes out as four stray bytes at the top of the
		// command's output, which is what `adb shell whoami` printed -- "\0\0\0shell".
		//
		// What the payload *is*, under shell v2, is a framed stream the client decodes
		// itself: a one-byte frame id, a four-byte little-endian length, then the bytes.
		// Frame id 3 carries the exit status. This relay neither reads nor rewrites those
		// frames -- it does not know the service was a shell -- so the status arrives at
		// the client because it was never in the way. Measured end to end for
		// `adb shell false`, the whole device-to-client exchange is one payload:
		//
		//	03 01 00 00 00 01      id=3 (exit), length 1, status 1
		//
		// A relay that tried to interpret it and forward only the status byte would put
		// that 1 on the client's stdout instead.
		for {
			p, err := readPacket(dbr)
			if err != nil {
				errc <- err
				return
			}
			switch p.command {
			case cmdWRTE:
				// Every device WRTE is acknowledged, and it has to be a separate packet:
				// the device's flow control is the client's socket being read again, so an
				// unacknowledged payload stops the device sending rather than failing.
				// Measured against the stock server, which acks each one in turn.
				if _, err := dev.Write(encodePacket(cmdOKAY, devID, hostLocalID, nil)); err != nil {
					errc <- err
					return
				}
				if len(p.payload) == 0 {
					continue
				}
				if _, err := c.Write(p.payload); err != nil {
					errc <- err
					return
				}
			case cmdCLSE:
				// The device has closed the stream, and p.arg1 is where it puts the exit
				// status for a service that reports one. It is not forwarded: the client is
				// not reading a transport here, it is reading a shell stream, and the status
				// it wants already travelled as a v2 frame inside a WRTE payload. The
				// measured exchange for `adb shell false` shows the CLSE carrying nothing --
				// arg1 is the device's own stream id -- so there is no second copy to send.
				//
				// What is sent is the close itself, which the stock server also sends, and
				// the client is left to see the socket end. Its own exit status is the one
				// it decoded from the stream.
				if _, err := dev.Write(encodePacket(cmdCLSE, devID, hostLocalID, nil)); err != nil {
					errc <- err
					return
				}
				errc <- io.EOF
				return
			case cmdOKAY, cmdOPEN, cmdCNXN:
				// Handshake leftovers. Nothing to hand the client.
			default:
				// Not an error: a device may legitimately send STATUS or SYNC frames on a
				// sync service, and this relay has no use for either. Logged so that an
				// unexpected one is a fact in the log rather than a silence.
				s.debugf("adbserverproto: device sent %q, ignored", p.command)
			}
		}
	}()

	go func() {
		// Client to device: whatever arrives is one block of stream data, and the device
		// wants it wrapped. There is no framing on the client side to respect, so a read
		// is a block and the block size is bounded by the device's own limit.
		//
		// arg0 is the device's stream id and arg1 is this host's. The other way round names
		// a stream that does not exist and the payload is dropped without a word; see the
		// note on handshake.
		buf := make([]byte, adbMaxData)
		for {
			n, err := cbr.Read(buf)
			if n > 0 {
				if _, werr := dev.Write(encodePacket(cmdWRTE, devID, hostLocalID, buf[:n])); werr != nil {
					errc <- werr
					return
				}
			}
			if err != nil {
				// The client's input ended. That has to reach the device as a CLSE, because
				// a device under shell v2 ends input on kIdCloseStdin in the stream and
				// nothing else: without a close, a command reading stdin waits forever and
				// the connection hangs until something times out. The stock server's
				// measured behaviour on a client half-close is exactly this one packet, and
				// nothing else -- no empty WRTE, no close of the device's socket.
				if _, werr := dev.Write(encodePacket(cmdCLSE, devID, hostLocalID, nil)); werr != nil {
					errc <- werr
					return
				}
				errc <- err
				return
			}
		}
	}()

	if err := <-errc; err != nil && err != io.EOF {
		return err
	}
	return nil
}

// readPacket reads one ADB message.
func readPacket(br *bufio.Reader) (packet, error) {
	head := make([]byte, adbHeaderLen)
	if _, err := io.ReadFull(br, head); err != nil {
		return packet{}, err
	}
	n := uint32At(head[12:16])
	if n > adbMaxData {
		return packet{}, fmt.Errorf("packet claims %d bytes, over the %d byte limit", n, adbMaxData)
	}
	p := packet{
		command: strings.TrimRight(string(head[0:4]), "\x00"),
		arg0:    uint32At(head[4:8]),
		arg1:    uint32At(head[8:12]),
	}
	if n > 0 {
		p.payload = make([]byte, n)
		if _, err := io.ReadFull(br, p.payload); err != nil {
			return packet{}, err
		}
	}
	return p, nil
}
