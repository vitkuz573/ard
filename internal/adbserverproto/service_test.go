package adbserverproto

import (
	"bufio"
	"io"
	"net"
	"testing"
	"time"
)

// deviceEnd is the far side of a transport a service is opened on. It plays the device: it
// answers CNXN, answers OPEN, and from then on it is the other end of a byte stream.
type deviceEnd struct {
	conn net.Conn
	br   *bufio.Reader
	// id is the stream id this device announces. It is deliberately not 1, so a packet
	// addressed the wrong way round resolves nothing instead of resolving the same stream by
	// coincidence.
	id uint32
}

// openServiceOn starts a device that answers for the named service and returns the byte stream
// OpenService should hand back.
func openServiceOn(t *testing.T, deviceID uint32, service string) (*deviceEnd, net.Conn) {
	t.Helper()
	client, server := net.Pipe()
	d := &deviceEnd{conn: server, br: bufio.NewReader(server), id: deviceID}

	go func() {
		if err := expectPacket(d.conn, d.br, cmdCNXN, cnxnArg0, adbMaxData); err != nil {
			return
		}
		if err := writeTo(d.conn, encodePacket(cmdCNXN, cnxnArg0, adbMaxData, []byte("device::features=shell_v2,"))); err != nil {
			return
		}
		if err := expectPacket(d.conn, d.br, cmdOKAY, cnxnArg0, adbMaxData); err != nil {
			return
		}
		open, err := readPacket(d.br)
		if err != nil || open.command != cmdOPEN {
			return
		}
		// The service name is what decides which port on the device this reaches, so it is
		// checked rather than assumed: a device that connected somewhere else would make the
		// tunnel work and lead nowhere.
		if got := serviceName(open.payload); got != service {
			t.Errorf("device was asked for %q, want %q", got, service)
		}
		if open.arg1 != 0 {
			t.Errorf("OPEN arg1 = %d, want 0", open.arg1)
		}
		_ = writeTo(d.conn, encodePacket(cmdOKAY, deviceID, open.arg0, nil))
	}()

	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	return d, client
}

// A service's bytes travel to the device as WRTE payloads addressed with this host's id in
// arg0 and the device's in arg1, and the device's own payloads come back the same way round.
//
// Measured, on a transport where the two ids are told apart (host 10, device 2):
//
//	host -> device  WRTE arg0=10 arg1=2
//	device -> host  WRTE arg0=2  arg1=10
func TestOpenServiceCarriesBytesInBothDirections(t *testing.T) {
	const deviceID = 0x2b
	const toDevice = "request"
	const toHost = "reply"

	d, transport := openServiceOn(t, deviceID, "tcp:9911")
	stream, err := OpenService(transport, "tcp:9911")
	if err != nil {
		t.Fatalf("open the service: %v", err)
	}

	// The device's read loop: acknowledge what arrives, answer with a payload, and report the
	// addressing of both.
	done := make(chan struct{})
	go func() {
		defer close(done)
		p, err := readPacket(d.br)
		if err != nil {
			t.Errorf("device: %v", err)
			return
		}
		if p.command != cmdWRTE {
			t.Errorf("device got %q, want WRTE", p.command)
			return
		}
		if p.arg0 != hostLocalID || p.arg1 != deviceID {
			t.Errorf("WRTE arg0=%d arg1=%d, want arg0=%d (this host) arg1=%d (the device)",
				p.arg0, p.arg1, hostLocalID, deviceID)
		}
		if string(p.payload) != toDevice {
			t.Errorf("device received %q, want %q", p.payload, toDevice)
		}
		_ = writeTo(d.conn, encodePacket(cmdWRTE, deviceID, hostLocalID, []byte(toHost)))
		// The acknowledgement this server sends for it. Reading it is what a device does, and
		// leaving it unread would block the writer on a connection with no buffer.
		_ = expectPacket(d.conn, d.br, cmdOKAY, hostLocalID, deviceID)
	}()

	if _, err := stream.Write([]byte(toDevice)); err != nil {
		t.Fatalf("write to the service: %v", err)
	}
	got := make([]byte, len(toHost))
	stream.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(stream, got); err != nil {
		t.Fatalf("read from the service: %v", err)
	}
	if string(got) != toHost {
		t.Errorf("the stream read %q, want %q", got, toHost)
	}
	<-done
}

// A payload is split rather than sent oversized. A device is offered a window in its CNXN and
// sends nothing larger, so one oversized WRTE is a packet the device rejects with the bytes
// after it lost -- and nothing reports that on either end.
func TestOpenServiceSplitsAPayloadLargerThanTheDeviceWindow(t *testing.T) {
	const deviceID = 0x2c
	big := make([]byte, adbMaxData*2+100)
	for i := range big {
		big[i] = byte(i)
	}

	d, transport := openServiceOn(t, deviceID, "tcp:9911")
	stream, err := OpenService(transport, "tcp:9911")
	if err != nil {
		t.Fatalf("open the service: %v", err)
	}

	// The device reads every frame back and reassembles, which is what a device does with a
	// payload split across packets.
	done := make(chan []byte, 1)
	go func() {
		var out []byte
		for {
			p, err := readPacket(d.br)
			if err != nil {
				done <- out
				return
			}
			if p.command == cmdCLSE {
				done <- out
				return
			}
			if p.command != cmdWRTE {
				continue
			}
			if len(p.payload) > adbMaxData {
				t.Errorf("device got a %d byte payload, over the %d byte window it offered",
					len(p.payload), adbMaxData)
			}
			out = append(out, p.payload...)
			// Acknowledged from its own goroutine: an acknowledgement is a write on the same
			// connection, and a device that writes one while this loop is waiting to read the
			// next frame would block itself rather than reopen the window.
			go writeTo(d.conn, encodePacket(cmdOKAY, deviceID, hostLocalID, nil))
		}
	}()

	n, err := stream.Write(big)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if n != len(big) {
		t.Errorf("Write reported %d bytes written, want %d", n, len(big))
	}
	_ = stream.Close()

	got := <-done
	if len(got) != len(big) {
		t.Fatalf("the device reassembled %d bytes, want %d", len(got), len(big))
	}
	for i := range got {
		if got[i] != big[i] {
			t.Fatalf("the payload differs at byte %d", i)
		}
	}
}

// Every payload is acknowledged, and the acknowledgement is not politeness: the device's flow
// control is its host reading again, so an unacknowledged payload stops the device sending.
func TestOpenServiceAcknowledgesEveryPayload(t *testing.T) {
	const deviceID = 0x2d

	d, transport := openServiceOn(t, deviceID, "tcp:9911")
	stream, err := OpenService(transport, "tcp:9911")
	if err != nil {
		t.Fatalf("open the service: %v", err)
	}

	// Acknowledgements are drained as they arrive rather than after the payloads: they are
	// writes on the same connection, so an unread one stops this server writing the next
	// payload, which is exactly the flow control being tested.
	acks := make(chan int, 4)
	go func() {
		for {
			p, err := readPacket(d.br)
			if err != nil {
				close(acks)
				return
			}
			if p.command != cmdOKAY {
				continue
			}
			acks <- 1
		}
	}()
	go func() {
		_ = writeTo(d.conn, encodePacket(cmdWRTE, deviceID, hostLocalID, []byte("from the device")))
		_ = writeTo(d.conn, encodePacket(cmdWRTE, deviceID, hostLocalID, []byte("and another")))
		_ = writeTo(d.conn, encodePacket(cmdCLSE, deviceID, hostLocalID, nil))
	}()
	defer func() {
		// Two payloads, each acknowledged. The close is not: it ends the stream rather than
		// carrying data, and there is nothing further to unblock.
		for i := 0; i < 2; i++ {
			select {
			case <-acks:
			case <-time.After(5 * time.Second):
				t.Errorf("only %d of 2 payloads were acknowledged", i)
				return
			}
		}
	}()

	var got []byte
	buf := make([]byte, 64)
	for {
		n, err := stream.Read(buf)
		got = append(got, buf[:n]...)
		if err != nil {
			break
		}
	}
	if string(got) != "from the deviceand another" {
		t.Errorf("the stream read %q, want both of the device's payloads", got)
	}
}

// The device ending a service has to reach the caller as the end of its input, not as a hang:
// a relay waiting for a payload that will never come holds the connection it was asked to carry.
func TestOpenServiceReportsTheDevicesCloseAsTheEndOfTheStream(t *testing.T) {
	const deviceID = 0x2e

	d, transport := openServiceOn(t, deviceID, "tcp:9911")
	stream, err := OpenService(transport, "tcp:9911")
	if err != nil {
		t.Fatalf("open the service: %v", err)
	}

	go func() {
		_ = writeTo(d.conn, encodePacket(cmdCLSE, deviceID, hostLocalID, nil))
	}()

	// The close is answered, and it is read here rather than after the Read below: the answer
	// is a write on this connection, so leaving it unread would hold up the reader that is
	// waiting to report the end of the stream.
	answered := make(chan error, 1)
	go func() {
		answered <- expectPacket(d.conn, d.br, cmdCLSE, hostLocalID, deviceID)
	}()

	stream.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := stream.Read(make([]byte, 16)); err != io.EOF {
		t.Errorf("Read after the device closed = %v, want io.EOF", err)
	}
	// A device waiting to release its own side needs to be told, or it holds the stream.
	if err := <-answered; err != nil {
		t.Errorf("the device's close was not answered with a close: %v", err)
	}
}

// A device that cannot open the service says so rather than being taken to have opened it, and
// the answer is reported rather than turned into a stream that delivers nothing.
func TestOpenServiceReportsADeviceThatRefuses(t *testing.T) {
	for _, answer := range []struct {
		name   string
		packet []byte
	}{
		{"a close", encodePacket(cmdCLSE, 0x2f, hostLocalID, nil)},
		{"a failure", encodePacket(cmdFAIL, 0x2f, hostLocalID, []byte("closed\x00"))},
	} {
		client, server := net.Pipe()
		br := bufio.NewReader(server)
		go func() {
			_ = expectPacket(server, br, cmdCNXN, cnxnArg0, adbMaxData)
			_ = writeTo(server, encodePacket(cmdCNXN, cnxnArg0, adbMaxData, []byte("device::features=shell_v2,")))
			_ = expectPacket(server, br, cmdOKAY, cnxnArg0, adbMaxData)
			_ = expectPacket(server, br, cmdOPEN, hostLocalID, 0)
			_ = writeTo(server, answer.packet)
		}()
		if _, err := OpenService(client, "tcp:9911"); err == nil {
			t.Errorf("%s: OpenService reported success", answer.name)
		}
		_ = client.Close()
		_ = server.Close()
	}
}

// A device that answers OPEN with stream id 0 has named no stream, and a stream written
// against id 0 resolves nothing on the device: the payload is dropped without a word and the
// caller waits forever. Refusing here is what turns that into an error.
func TestOpenServiceRefusesAStreamTheDeviceNamedZero(t *testing.T) {
	client, server := net.Pipe()
	br := bufio.NewReader(server)
	go func() {
		_ = expectPacket(server, br, cmdCNXN, cnxnArg0, adbMaxData)
		_ = writeTo(server, encodePacket(cmdCNXN, cnxnArg0, adbMaxData, []byte("device::features=shell_v2,")))
		_ = expectPacket(server, br, cmdOKAY, cnxnArg0, adbMaxData)
		_ = expectPacket(server, br, cmdOPEN, hostLocalID, 0)
		_ = writeTo(server, encodePacket(cmdOKAY, 0, hostLocalID, nil))
	}()
	defer client.Close()
	defer server.Close()

	if _, err := OpenService(client, "tcp:9911"); err == nil {
		t.Error("OpenService accepted a stream the device named zero")
	}
}
