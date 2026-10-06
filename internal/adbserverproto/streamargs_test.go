package adbserverproto

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

// devicePacket is a packet as a device sends it: arg0 is the device's stream id and arg1 this
// server's. It is the mirror of hostToDevice, and it exists so a device script reads as the
// device rather than as the server with its fields transposed.
func devicePacket(command string, devID, hostID uint32, payload []byte) []byte {
	return encodePacket(command, devID, hostID, payload)
}

// echoServer listens and echoes whatever it is sent, standing in for the port a callback is
// answered with. It echoes so that a test can check both directions of a tunnel rather than
// only that one of them opened.
func echoServer(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
	return ln
}

// dialFunc adapts a function to DeviceDialer.
type dialFunc func(service string) (net.Conn, error)

func (f dialFunc) Dial(service string) (net.Conn, error) { return f(service) }

// ServiceRun is one switched-transport service with its client end and its device script.
//
// The two are returned together because they are one conversation: the device script asserts
// what this server sent, and the client end is what the assertions are about. Holding both is
// what keeps an assertion inside the test that asked for it rather than in a goroutine that
// outlives it.
type ServiceRun struct {
	// Client is the connection the adb client would hold.
	Client net.Conn
	done   chan struct{}
}

// await waits for the device script to finish, so anything it reported arrives while the test
// is still running.
func (s *ServiceRun) await(t *testing.T) {
	t.Helper()
	select {
	case <-s.done:
	case <-time.After(10 * time.Second):
		t.Fatal("the device script did not finish")
	}
}

// openService runs one switched-transport service against a scripted device.
//
// after is handed the device's connection, a reader sharing that connection's buffer, and the
// stream id this server claimed in its OPEN. Everything it asserts is about what this server
// sends to the device, which is the only direction a reversed arg0/arg1 shows up in.
func openService(t *testing.T, s *Server, service string, deviceID uint32,
	after func(conn net.Conn, br *bufio.Reader, hostID uint32)) *ServiceRun {
	t.Helper()
	// The client end is a real socket rather than a pipe, because one of these tests needs a
	// half-close: a pipe cannot end its input without ending its output, and the relay reads
	// the client's input to know that the command has finished typing.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	type dialed struct {
		c   net.Conn
		err error
	}
	got := make(chan dialed, 1)
	go func() {
		c, err := ln.Accept()
		got <- dialed{c, err}
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	server := (<-got).c

	// The device end is a socket too, for the same reason on the other side: a packet this
	// server writes to the device is acknowledged before the device reads it, and on an
	// unbuffered pipe that write does not return until the device does -- which deadlocks a
	// script that is waiting to write its next packet first.
	dln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for the device: %v", err)
	}
	t.Cleanup(func() { _ = dln.Close() })
	acceptedDevice := make(chan dialed, 1)
	go func() {
		c, err := dln.Accept()
		acceptedDevice <- dialed{c, err}
	}()
	deviceToServer, err := net.Dial("tcp", dln.Addr().String())
	if err != nil {
		t.Fatalf("dial the device: %v", err)
	}
	device := (<-acceptedDevice).c

	run := &ServiceRun{Client: client, done: make(chan struct{})}
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
		_ = deviceToServer.Close()
		_ = device.Close()
	})

	go func() {
		defer close(run.done)
		defer deviceToServer.Close()
		br := bufio.NewReader(device)
		// The handshake is this server's and is the same whatever the service: a CNXN in each
		// direction, then the OPEN naming the service.
		if err := expectPacket(device, br, cmdCNXN, cnxnArg0, adbMaxData); err != nil {
			t.Errorf("device: %v", err)
			return
		}
		if err := writeTo(device, encodePacket(cmdCNXN, cnxnArg0, adbMaxData, []byte("device::features=shell_v2,"))); err != nil {
			return
		}
		if err := expectPacket(device, br, cmdOKAY, cnxnArg0, adbMaxData); err != nil {
			t.Errorf("device: %v", err)
			return
		}
		open, err := readPacket(br)
		if err != nil {
			t.Errorf("device: read OPEN: %v", err)
			return
		}
		if err := writeTo(device, encodePacket(cmdOKAY, deviceID, open.arg0, nil)); err != nil {
			return
		}
		if after != nil {
			after(device, br, open.arg0)
		}
	}()

	served := New(s.filter, func(string) (net.Conn, error) { return deviceToServer, nil }, s.operator, s.logf, s.forwards)
	served.dialer = s.dialer
	served.adopter = s.adopter
	go func() { _ = served.Serve(server) }()

	if _, err := client.Write(request("host:tport:serial:AAA")); err != nil {
		t.Fatalf("write tport: %v", err)
	}
	head := make([]byte, 12)
	client.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(client, head); err != nil {
		t.Fatalf("read tport reply: %v", err)
	}
	if _, err := client.Write(request(service)); err != nil {
		t.Fatalf("write service: %v", err)
	}
	// A switched transport is acknowledged with a bare OKAY, then the connection is a raw
	// stream. Two writes, so two reads.
	ack := make([]byte, 4)
	if _, err := io.ReadFull(client, ack); err != nil {
		t.Fatalf("read the switch acknowledgement: %v", err)
	}
	if string(ack) != okayToken {
		t.Fatalf("switch acknowledgement %q, want %q", ack, okayToken)
	}
	// The handshake's deadline has done its job. Left in place it would expire in the middle
	// of whatever the test does next and report a timeout that looks like a relay failure.
	if err := client.SetDeadline(time.Time{}); err != nil {
		t.Fatalf("clear the deadline: %v", err)
	}
	return run
}

// The client's bytes reach the device addressed with this server's stream id in arg0 and the
// device's in arg1.
//
// Measured, on a transport where the two ids are told apart because the host had opened
// several streams and the device was on its second:
//
//	host -> device  OPEN arg0=10 arg1=0
//	device -> host  OKAY arg0=2  arg1=10
//	host -> device  WRTE arg0=10 arg1=2
//
// The device resolves the stream from arg1, so the reversed pair resolves nothing and the
// payload is dropped without a word. This server's own id being 1 is what makes that easy to
// miss: a device whose ids also start at 1 cannot tell the two orders apart. So the device
// here claims an id that is not 1, and the end of the client's input is checked for the same
// reason.
func TestClientBytesAreAddressedToTheDeviceStreamTheDeviceNamed(t *testing.T) {
	const deviceID = 0x2f
	const payload = "stdin-frame"

	run := openService(t, forwardingServer(nil), "shell,v2,raw:cat", deviceID,
		func(conn net.Conn, br *bufio.Reader, hostID uint32) {
			p, err := readPacket(br)
			if err != nil {
				t.Errorf("device: %v", err)
				return
			}
			if p.command != cmdWRTE {
				t.Errorf("device got %q, want WRTE", p.command)
				return
			}
			if p.arg0 != hostID || p.arg1 != deviceID {
				t.Errorf("WRTE arg0=%d arg1=%d, want arg0=%d (this server) arg1=%d (the device)",
					p.arg0, p.arg1, hostID, deviceID)
			}
			if string(p.payload) != payload {
				t.Errorf("device received %q, want %q", p.payload, payload)
			}
			if err := writeTo(conn, encodePacket(cmdOKAY, deviceID, hostID, nil)); err != nil {
				return
			}
			// The client's half-close reaches the device as a CLSE from this server, with the
			// same ordering. A device under shell v2 ends its input on the kIdCloseStdin frame
			// and on nothing else, so this close is what stops a command reading stdin from
			// waiting for an end that never comes.
			if err := expectPacket(conn, br, cmdCLSE, hostID, deviceID); err != nil {
				t.Errorf("device: %v", err)
			}
		})

	if _, err := run.Client.Write([]byte(payload)); err != nil {
		t.Fatalf("write to the stream: %v", err)
	}
	if cw, ok := run.Client.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
	run.await(t)
}

// A device that opens a stream on the transport it already has is asking for a connection to
// a port on this server. The answer has to be a real connection, addressed the same way round:
// arg0 is this server's id, arg1 the device's.
//
// Measured against a stock adb server, which answers a device's OPEN with exactly this pair:
//
//	device -> host  OPEN arg0=2 arg1=0 "tcp:35124\0"
//	host -> device  OKAY arg0=8 arg1=2
func TestADeviceOpenedStreamIsAnsweredOnItsOwnStreamAndAddressed(t *testing.T) {
	const deviceID = 0x2a
	// The device's own stream is a different stream, so it gets a different id. A device that
	// reused its service stream's id for the stream it opens would make this server's
	// demultiplexing send the service's own traffic to the callback, and that is not a shape
	// any device produces: an id identifies one stream.
	const openID = 0x2c
	const service = "tcp:9911"

	// The far end of the dial. It echoes, so both directions of the callback are checked
	// rather than only the fact that one happened.
	echo := echoServer(t)
	defer echo.Close()

	dialed := make(chan string, 1)
	s := forwardingServer(nil)
	s.dialer = dialFunc(func(service string) (net.Conn, error) {
		dialed <- service
		return net.Dial("tcp", echo.Addr().String())
	})

	run := openService(t, s, "sync:", deviceID,
		func(conn net.Conn, br *bufio.Reader, hostID uint32) {
			// The device opens its own stream while the sync service is still running, which is
			// when a reverse forward's callback arrives in practice.
			_ = writeTo(conn, encodePacket(cmdOPEN, openID, 0, append([]byte(service), 0)))
			p, err := readPacket(br)
			if err != nil {
				t.Errorf("device: %v", err)
				return
			}
			if p.command != cmdOKAY {
				t.Errorf("device got %q arg0=%d arg1=%d for its OPEN, want OKAY", p.command, p.arg0, p.arg1)
				return
			}
			if p.arg0 != hostID || p.arg1 != openID {
				t.Errorf("OKAY arg0=%d arg1=%d, want arg0=%d (this server) arg1=%d (the device)",
					p.arg0, p.arg1, hostID, openID)
			}
			// The device's own stream, into the socket this server dialled. The far end echoes,
			// so the answer has to come back on this stream rather than somewhere else: that is
			// the whole of what a reverse forward's callback half does.
			if err := writeTo(conn, devicePacket(cmdWRTE, openID, hostID, []byte("through the socket"))); err != nil {
				t.Errorf("device: %v", err)
				return
			}
			// Every payload is acknowledged before the next is sent, so the acknowledgement
			// for this one is read rather than skipped: it is the device's flow control, and a
			// device that ignores it stops being sent anything.
			if err := expectPacket(conn, br, cmdOKAY, hostID, openID); err != nil {
				t.Errorf("device: %v", err)
			}
			w, err := readPacket(br)
			if err != nil {
				t.Errorf("device: %v", err)
				return
			}
			if w.command != cmdWRTE || string(w.payload) != "through the socket" {
				t.Errorf("device got %q %q, want WRTE carrying what the socket echoed", w.command, w.payload)
			}
			if w.arg0 != hostID || w.arg1 != openID {
				t.Errorf("WRTE arg0=%d arg1=%d, want arg0=%d arg1=%d", w.arg0, w.arg1, hostID, openID)
			}
		})
	run.await(t)

	select {
	case got := <-dialed:
		if got != service {
			t.Errorf("dialed for %q, want %q", got, service)
		}
	default:
		t.Fatal("the device's request was never dialled")
	}
}

// A device that opens a stream for a port this server cannot reach is answered with a close
// rather than an OKAY. An OKAY would be a promise, and what the device is waiting on after it
// is a connection this server has already failed to make.
func TestADeviceOpenedStreamForAnUnreachablePortIsClosed(t *testing.T) {
	const deviceID = 0x2b
	const openID = 0x2e

	s := forwardingServer(nil)
	s.dialer = dialFunc(func(string) (net.Conn, error) {
		return nil, io.ErrUnexpectedEOF
	})

	run := openService(t, s, "sync:", deviceID,
		func(conn net.Conn, br *bufio.Reader, hostID uint32) {
			// A port nothing is listening on, so the dial fails immediately.
			_ = writeTo(conn, encodePacket(cmdOPEN, openID, 0, append([]byte("tcp:1"), 0)))
			p, err := readPacket(br)
			if err != nil {
				t.Errorf("device: %v", err)
				return
			}
			if p.command != cmdCLSE {
				t.Errorf("device got %q for an unreachable port, want CLSE", p.command)
				return
			}
			if p.arg0 != hostID || p.arg1 != openID {
				t.Errorf("CLSE arg0=%d arg1=%d, want arg0=%d arg1=%d", p.arg0, p.arg1, hostID, openID)
			}
		})
	run.await(t)
}

// A device's own stream is not the client's stream, and the two do not merge. The bytes on the
// stream the device opened go to the socket this server dialled for it, and the client's own
// stream carries on across the OPEN unaffected -- otherwise a reverse forward's callback would
// deliver a device's shell output to whatever the operator was reading.
func TestADeviceOpenedStreamDoesNotDisturbTheClientStream(t *testing.T) {
	const deviceID = 0x2d
	const openID = 0x2f
	const onService = "the client's service"
	const onCallback = "the device's own stream"

	echo := echoServer(t)
	defer echo.Close()

	s := forwardingServer(nil)
	s.dialer = dialFunc(func(string) (net.Conn, error) { return net.Dial("tcp", echo.Addr().String()) })

	run := openService(t, s, "sync:", deviceID,
		func(conn net.Conn, br *bufio.Reader, hostID uint32) {
			// The service's own payload, acknowledged.
			if err := writeTo(conn, devicePacket(cmdWRTE, deviceID, hostID, []byte(onService))); err != nil {
				return
			}
			if err := expectPacket(conn, br, cmdOKAY, hostID, deviceID); err != nil {
				t.Errorf("device: %v", err)
				return
			}
			// Then a stream of the device's own, which is answered on its own id.
			_ = writeTo(conn, encodePacket(cmdOPEN, openID, 0, append([]byte("tcp:9911"), 0)))
			if err := expectPacket(conn, br, cmdOKAY, hostID, openID); err != nil {
				t.Errorf("device: %v", err)
				return
			}
			// Bytes on the device's own stream. They must reach the socket and come back there,
			// and must not appear on the client's stream.
			if err := writeTo(conn, devicePacket(cmdWRTE, openID, hostID, []byte(onCallback))); err != nil {
				return
			}
			if err := expectPacket(conn, br, cmdOKAY, hostID, openID); err != nil {
				t.Errorf("device: %v", err)
				return
			}
			w, err := readPacket(br)
			if err != nil {
				t.Errorf("device: %v", err)
				return
			}
			if w.command != cmdWRTE || string(w.payload) != onCallback {
				t.Errorf("the callback's echo came back as %q %q", w.command, w.payload)
			}
			// And the service closes, which must not disturb the callback's socket either.
			_ = writeTo(conn, devicePacket(cmdCLSE, deviceID, hostID, nil))
			_ = expectPacket(conn, br, cmdCLSE, hostID, deviceID)
		})

	// The client reads its own stream's payload, and nothing else. The device's callback
	// payload goes to the socket this server dialled for it, so if it arrived here the two
	// streams would have merged.
	got := make([]byte, len(onService)+len(onCallback)+16)
	n, err := run.Client.Read(got)
	if err != nil && err != io.EOF {
		t.Fatalf("read: %v", err)
	}
	if string(got[:n]) != onService {
		t.Errorf("the client received %q, want %q and nothing else", got[:n], onService)
	}
	run.await(t)
}

// A device's payload is not length-prefixed on the way to the client: a client that has just
// switched transports reads a raw stream, and a length in front of the data comes out as
// stray bytes at the top of the command's output.
func TestDevicePayloadReachesTheClientWithNoFramingAdded(t *testing.T) {
	const deviceID = 0x2e
	// A shell v2 exit frame: id 3, a four-byte little-endian length, then the status byte.
	payload := []byte{0x03, 0x01, 0x00, 0x00, 0x00, 0x01}

	run := openService(t, forwardingServer(nil), "shell,v2,raw:false", deviceID,
		func(conn net.Conn, br *bufio.Reader, hostID uint32) {
			if err := writeTo(conn, encodePacket(cmdWRTE, deviceID, hostID, payload)); err != nil {
				return
			}
			_ = expectPacket(conn, br, cmdOKAY, hostID, deviceID)
			if err := writeTo(conn, encodePacket(cmdCLSE, deviceID, hostID, nil)); err != nil {
				return
			}
			_ = expectPacket(conn, br, cmdCLSE, hostID, deviceID)
		})

	got := make([]byte, len(payload))
	if _, err := io.ReadFull(run.Client, got); err != nil {
		t.Fatalf("read the device's payload: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("the client received % x, want % x", got, payload)
	}
	run.await(t)
}

// A service is answered on the connection the client already switched, and the acknowledgement
// of that switch is four bytes and nothing else. A banner here is what an adb client echoes
// instead of swallowing, so the shell it ran came back as "shellshell".
func TestSwitchedTransportAcknowledgesBeforeTheServiceAnswer(t *testing.T) {
	const deviceID = 0x2f

	run := openService(t, forwardingServer(nil), "sync:", deviceID,
		func(conn net.Conn, br *bufio.Reader, hostID uint32) {
			_ = writeTo(conn, encodePacket(cmdWRTE, deviceID, hostID, []byte("payload")))
			_ = expectPacket(conn, br, cmdOKAY, hostID, deviceID)
			_ = writeTo(conn, encodePacket(cmdCLSE, deviceID, hostID, nil))
			_ = expectPacket(conn, br, cmdCLSE, hostID, deviceID)
		})

	buf := make([]byte, 64)
	n, err := run.Client.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != "payload" {
		t.Errorf("the client received %q, want the device's payload and nothing before it", buf[:n])
	}
	run.await(t)
}
