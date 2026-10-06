package adbserverproto

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
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
func (s *Server) serveHostService(c net.Conn, dev net.Conn, prefix []byte) (bool, string, error) {
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
		return false, "", fmt.Errorf("read service request: %w", err)
	}
	// Which service was requested is worth one line: it is the only thing that distinguishes
	// `adb shell whoami` from `adb push` in the log, and without it a session that opens a
	// transport and delivers nothing has nothing to explain it.
	s.debugf("adbserverproto: service %q on a switched transport", service)

	// The transport is already switched, and the acknowledgement has to reach the client
	// before anything else: this connection is about to carry either the rest of a session
	// or a reply, and a client that has not seen the OKAY reads whatever comes next as the
	// answer to its request.
	//
	// It looks like the host:service form, "OKAYshell\n", and it is not. That form belongs
	// to the old host socket, where the client had not connected to anything yet. Measured:
	// a stock server answers a raw "000cshell:whoami" with "OKAYshell\n", but a real adb
	// client that has just switched transports gets no banner, and printing one is visible
	// immediately -- `adb shell whoami` came back as "shellshell", the banner and the
	// output, because the client echoed the banner instead of swallowing it.
	if _, err := c.Write([]byte(okayToken)); err != nil {
		return false, service, err
	}

	// Forwarding is answered here rather than by the device, because the port being
	// forwarded is this server's: a device has no say in a port on the machine the adb
	// binary talks to. Everything else on this connection is the device's to answer.
	if rest, ok := strings.CutPrefix(service, "host:"); ok {
		return false, service, s.serveHostForward(c, rest)
	}

	dbr := bufio.NewReader(dev)
	streamID, err := s.handshake(dbr, dev, service)
	if err != nil {
		return false, service, err
	}
	if err := s.pumpHostStream(c, dev, br, dbr, streamID); err != nil {
		return false, service, err
	}
	// The service is over and the device is free to be asked something else. Whether this
	// transport is still needed is not this function's to decide: a device that bound a port
	// of its own keeps holding this one, and closing it here would end the forward before
	// anything reached the port.
	return keepsTransport(service), service, nil
}

// keepsTransport reports whether a service leaves the device holding this transport.
//
// A reverse forward is the case that decides it. The device binds the remote port on this
// transport and, for every connection to that port, opens a stream here asking for the local
// port. It has no connection of its own to open that stream on, so closing the transport once
// the request is answered leaves the bound port with nothing behind it.
//
// Measured against a device that bound a port and then connected to it: with the transport
// closed at the end of the request, the device could not open its callback stream and the
// connection to the port it had bound was reset.
func keepsTransport(service string) bool {
	return strings.HasPrefix(service, "reverse:forward:")
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
//
// Each service gets a device transport of its own, so this one number is unique on every
// connection this server makes.
const hostLocalID = 1

// Which of arg0 and arg1 carries the stream id.
//
// Measured, on a connection where the two ids are told apart because the host had already
// opened several streams and the device was on its second:
//
//	host -> device  OPEN  arg0=10 arg1=0   "sync:\0"
//	device -> host  OKAY  arg0=2  arg1=10
//	host -> device  WRTE  arg0=10 arg1=2   "SEND..."
//	host -> device  CLSE  arg0=10 arg1=2
//
// so arg0 is the sender's stream id and arg1 the receiver's, without exception. That reads
// backwards the first time, and the failure it causes is silent: a peer that resolves the
// stream from arg1 finds nothing, drops the payload and says nothing, and the symptom is a
// command that produces no output and no error.
//
// The reason it is easy to get wrong here is that this server's own id is 1 and a device's
// ids start at 1, so on a fresh connection the two fields are interchangeable and a packet
// written the wrong way round still resolves. A push over a device's second stream is what
// separates them.
func hostToDevice(command string, devID uint32, payload []byte) []byte {
	return encodePacket(command, hostLocalID, devID, payload)
}

// deviceStreams are the streams a device opened on this transport, keyed by the ids it chose.
//
// They share this transport's read loop with the service the client asked for, so they are
// demultiplexed here rather than on connections of their own: one transport carries every
// stream a device needs, and the packets do not say which is which except by arg0.
type deviceStreams struct {
	mu sync.Mutex
	by map[uint32]net.Conn
}

func newDeviceStreams() *deviceStreams { return &deviceStreams{by: map[uint32]net.Conn{}} }

// get returns the socket a device-opened stream is attached to, or nil.
func (d *deviceStreams) get(id uint32) net.Conn {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.by[id]
}

func (d *deviceStreams) put(id uint32, c net.Conn) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.by[id] = c
}

// take removes a stream and closes it, so a device's close ends the socket with it rather than
// leaving a connection open for a stream nobody holds.
func (d *deviceStreams) take(id uint32) {
	d.mu.Lock()
	c, ok := d.by[id]
	delete(d.by, id)
	d.mu.Unlock()
	if ok {
		_ = c.Close()
	}
}

func (d *deviceStreams) closeAll() {
	d.mu.Lock()
	all := d.by
	d.by = map[uint32]net.Conn{}
	d.mu.Unlock()
	for _, c := range all {
		_ = c.Close()
	}
}

// ServeDeviceStreams answers every stream a device opens on conn, until conn ends.
//
// It is the half of the relay a kept transport needs: once the request that opened the
// transport is finished there is no client left to relay to, and the only thing that can still
// arrive on it is the device asking for a connection of its own. That is the whole life of a
// reverse forward's callback half -- the device binds a port, and every connection to that port
// becomes a stream opened here asking for a port on this server.
func (s *Server) ServeDeviceStreams(conn net.Conn, serial string) {
	br := bufio.NewReader(conn)
	streams := newDeviceStreams()
	defer streams.closeAll()

	var wmu sync.Mutex
	write := func(b []byte) error {
		wmu.Lock()
		defer wmu.Unlock()
		_, err := conn.Write(b)
		return err
	}

	for {
		p, err := readPacket(br)
		if err != nil {
			return
		}
		if sink := streams.get(p.arg0); sink != nil && (p.command == cmdWRTE || p.command == cmdCLSE) {
			if err := write(encodePacket(cmdOKAY, hostLocalID, p.arg0, nil)); err != nil {
				return
			}
			if p.command == cmdWRTE {
				if _, err := sink.Write(p.payload); err != nil {
					streams.take(p.arg0)
				}
			} else {
				streams.take(p.arg0)
			}
			continue
		}
		switch p.command {
		case cmdOPEN:
			s.serveDeviceOpen(conn, p, streams, write)
		case cmdCLSE:
			// The device closed the transport. Every callback on it is over, and nothing
			// can be done about that from here: the device holds the listener and decides
			// what to do with it.
			return
		}
	}
}

// serveDeviceOpen answers a stream the device opened on this transport.
//
// The device chose the stream id, so it is p.arg0, and it has to be carried in arg1 of every
// packet sent back: a WRTE naming the wrong id resolves no stream on the device and its payload
// is dropped without a word, which presents as a connection that opens and delivers nothing.
//
// A dial that fails is answered with a close rather than an OKAY, so the device sees the refusal
// as a closed stream and releases whatever was waiting on its port.
func (s *Server) serveDeviceOpen(dev net.Conn, open packet, streams *deviceStreams, write func([]byte) error) {
	service := serviceName(open.payload)
	if s.dialer == nil {
		s.debugf("adbserverproto: device asked for %q and this server has no ports to offer", service)
		_ = write(encodePacket(cmdCLSE, hostLocalID, open.arg0, nil))
		return
	}
	conn, err := s.dialer.Dial(service)
	if err != nil {
		s.debugf("adbserverproto: device asked for %q: %v", service, err)
		_ = write(encodePacket(cmdCLSE, hostLocalID, open.arg0, nil))
		return
	}
	if err := write(encodePacket(cmdOKAY, hostLocalID, open.arg0, nil)); err != nil {
		_ = conn.Close()
		return
	}
	streams.put(open.arg0, conn)
	s.debugf("adbserverproto: device asked for %q; connected", service)
	go s.pumpDeviceStream(dev, open.arg0, conn, streams, write)
}

// pumpDeviceStream carries one device-opened stream out to the socket this server connected to.
//
// This is the socket's input only. The device's side of the stream arrives on the transport's
// read loop and is written to the socket by the same demultiplexing that registered it, so
// there is one reader per socket and one reader per transport.
func (s *Server) pumpDeviceStream(dev net.Conn, devID uint32, conn net.Conn, streams *deviceStreams, write func([]byte) error) {
	defer func() {
		streams.take(devID)
		_ = conn.Close()
	}()
	buf := make([]byte, adbMaxData)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			if werr := write(hostToDevice(cmdWRTE, devID, buf[:n])); werr != nil {
				return
			}
		}
		if err != nil {
			// The socket ended, so the stream has to end: a device holding a stream it has
			// finished with keeps whatever it opened for it.
			_ = write(hostToDevice(cmdCLSE, devID, nil))
			return
		}
	}
}

// pumpHostStream relays raw, length-prefixed data in both directions for as long as the
// service runs.
//
// The device side is unframed here on purpose: the WRTE envelopes are unwrapped, and the
// four-byte length each payload carries is kept, because that length is part of the stream
// the client reads rather than part of the transport around it.
func (s *Server) pumpHostStream(c net.Conn, dev net.Conn, cbr *bufio.Reader, dbr *bufio.Reader, devID uint32) error {
	errc := make(chan error, 2)
	streams := newDeviceStreams()
	defer streams.closeAll()

	// Every packet for this device goes through one writer. Several streams share one
	// transport -- the service the client asked for, plus any the device opened for itself --
	// and two packets interleaved byte for byte are two packets neither end can parse.
	var wmu sync.Mutex
	write := func(b []byte) error {
		wmu.Lock()
		defer wmu.Unlock()
		_, err := dev.Write(b)
		return err
	}

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
			// A payload for a stream the device opened goes to that stream's socket, not to
			// the client. Both arrive on this one transport and are told apart only by the
			// stream id, which is why the lookup comes before anything else.
			if sink := streams.get(p.arg0); sink != nil && (p.command == cmdWRTE || p.command == cmdCLSE) {
				if err := write(encodePacket(cmdOKAY, hostLocalID, p.arg0, nil)); err != nil {
					errc <- err
					return
				}
				switch p.command {
				case cmdWRTE:
					if _, err := sink.Write(p.payload); err != nil {
						s.debugf("adbserverproto: device stream %d: %v", p.arg0, err)
						streams.take(p.arg0)
						continue
					}
				case cmdCLSE:
					// The device ended it. Closing the socket is what lets the goroutine
					// reading it finish, and it in turn sends the close the device is
					// waiting for.
					streams.take(p.arg0)
				}
				continue
			}
			switch p.command {
			case cmdWRTE:
				// Every device WRTE is acknowledged, and it has to be a separate packet:
				// the device's flow control is the client's socket being read again, so an
				// unacknowledged payload stops the device sending rather than failing.
				// Measured against the stock server, which acks each one in turn.
				if err := write(hostToDevice(cmdOKAY, devID, nil)); err != nil {
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
			case cmdOPEN:
				// A device opening a stream on this transport is asking for a connection to
				// a port on this machine, which is the callback half of a reverse forward.
				// It arrives on the same connection and the same read loop as everything
				// else, and it is not a handshake leftover: treating it as one drops the
				// stream and the device's connection to whatever reached its port is reset,
				// which is what `adb reverse` produced.
				//
				// Answering is a dial and a splice on a stream of its own, so the current
				// service's relay carries on untouched while this one runs beside it.
				s.serveDeviceOpen(dev, p, streams, write)
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
				if err := write(hostToDevice(cmdCLSE, devID, nil)); err != nil {
					errc <- err
					return
				}
				errc <- io.EOF
				return
			case cmdOKAY, cmdCNXN:
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
				if werr := write(hostToDevice(cmdWRTE, devID, buf[:n])); werr != nil {
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
				if werr := write(hostToDevice(cmdCLSE, devID, nil)); werr != nil {
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
//
// The payload cap is adbMaxPacket, measured from what a stock adb client reads rather than
// from the window this server offers: a device puts a whole sync DATA frame in one packet,
// and 64 KiB of frame is a size a real device produces and a real adb accepts. Refusing it
// truncates the pull of any file larger than one frame, and reports nothing on either end.
func readPacket(br *bufio.Reader) (packet, error) {
	head := make([]byte, adbHeaderLen)
	if _, err := io.ReadFull(br, head); err != nil {
		return packet{}, err
	}
	n := uint32At(head[12:16])
	if n > adbMaxPacket {
		return packet{}, fmt.Errorf("packet claims %d bytes, over the %d byte limit", n, adbMaxPacket)
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
