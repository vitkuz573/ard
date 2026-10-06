package adbserverproto

// The device packet ceiling, checked against the number a real adb client enforces.
//
// The number is measured, not chosen. Pulling a file from a device that puts a whole sync
// DATA frame in one packet, with the device's frame size raised past a megabyte, produces on
// the client's own terminal:
//
//	adb: error: msg.data.size too large: 3000000 (max 65536)
//
// and with the frame size at the 64 KiB that a stock adbd uses, the packet that has to
// survive is exactly 65536 bytes. A relay that refuses that packet breaks every pull of a
// file larger than one frame, while reporting nothing to the operator: the transfer stops
// with no message on either end.
//
// So this asserts three things about one number: the packet at the measured size arrives at
// the client byte for byte, the packet one byte above it does not, and the relay's own
// advertisement in CNXN is not mistaken for what it will read. Those are separate claims and
// a change to any one of them should be caught on its own.

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

// syncDataFrame builds the bytes of one sync DATA frame as a stock adbd writes them: the
// command word, the payload length, then the payload.
//
// This is the shape that reaches the relay as a single WRTE payload, and it is why the
// ceiling has to be as large as one frame rather than one small packet.
func syncDataFrame(size int) []byte {
	frame := make([]byte, 8+size)
	copy(frame[0:4], "DATA")
	frame[4] = byte(size)
	frame[5] = byte(size >> 8)
	frame[6] = byte(size >> 16)
	frame[7] = byte(size >> 24)
	for i := 8; i < len(frame); i++ {
		frame[i] = byte(i)
	}
	return frame
}

// relayDevicePayload runs one switched transport against a device that sends payload in a
// single WRTE, and returns what the client read from the stream.
//
// The handshake is the one adb performs: tport, then the service request, then a bare OKAY.
// Everything after that is stream data, which is what a sync conversation is.
func relayDevicePayload(t *testing.T, payload []byte) []byte {
	t.Helper()
	ad := newPipe()
	dev := newPipe()
	client, server := ad.a, ad.b
	device := dev.b
	defer client.Close()
	defer server.Close()
	defer dev.a.Close()
	defer device.Close()

	s := New(fakeFilter{allowed: map[string]bool{"AAA": true}},
		func(string) (net.Conn, error) { return dev.a, nil }, nil)
	served := make(chan error, 1)
	go func() { served <- s.Serve(server) }()

	const deviceID = 0x1e
	deviceDone := make(chan error, 1)
	go func() {
		br := bufio.NewReader(device)
		if err := expectPacket(device, br, cmdCNXN, cnxnArg0, adbMaxData); err != nil {
			deviceDone <- err
			return
		}
		if err := writeTo(device, encodePacket(cmdCNXN, cnxnArg0, adbMaxData, []byte("device::"))); err != nil {
			deviceDone <- err
			return
		}
		if err := expectPacket(device, br, cmdOKAY, cnxnArg0, adbMaxData); err != nil {
			deviceDone <- err
			return
		}
		open, err := readPacket(br)
		if err != nil {
			deviceDone <- fmt.Errorf("read OPEN: %w", err)
			return
		}
		if want := "sync:\x00"; string(open.payload) != want {
			deviceDone <- fmt.Errorf("OPEN payload %q, want %q", open.payload, want)
			return
		}
		if err := writeTo(device, encodePacket(cmdOKAY, deviceID, open.arg0, nil)); err != nil {
			deviceDone <- err
			return
		}
		if err := writeTo(device, encodePacket(cmdWRTE, deviceID, open.arg0, payload)); err != nil {
			deviceDone <- err
			return
		}
		// Every device WRTE is acknowledged before the relay will read the next one, so
		// the device has to wait for the ack. Reading it here is what keeps the two sides
		// in step on a synchronous pipe.
		if err := expectPacket(device, br, cmdOKAY, deviceID, open.arg0); err != nil {
			deviceDone <- err
			return
		}
		// The device ends the stream and the relay answers a close with a close. Without
		// that the relay is still reading when the test is finished with it, and Serve has
		// nothing to return from.
		if err := writeTo(device, encodePacket(cmdCLSE, deviceID, open.arg0, nil)); err != nil {
			deviceDone <- err
			return
		}
		if err := expectPacket(device, br, cmdCLSE, deviceID, open.arg0); err != nil {
			deviceDone <- err
			return
		}
		deviceDone <- nil
	}()

	if _, err := client.Write(request("host:tport:serial:AAA")); err != nil {
		t.Fatalf("write request: %v", err)
	}
	head := make([]byte, 12)
	client.SetReadDeadline(time.Now().Add(20 * time.Second))
	if _, err := io.ReadFull(client, head); err != nil {
		t.Fatalf("read tport reply: %v", err)
	}
	if _, err := client.Write(request("sync:")); err != nil {
		t.Fatalf("write service request: %v", err)
	}
	ack := make([]byte, 4)
	if _, err := io.ReadFull(client, ack); err != nil {
		t.Fatalf("read stream acknowledgement: %v", err)
	}
	if string(ack) != "OKAY" {
		t.Fatalf("stream acknowledgement %q, want \"OKAY\"", ack)
	}

	got := make([]byte, len(payload))
	if _, err := io.ReadFull(client, got); err != nil {
		t.Fatalf("read %d bytes of stream: %v", len(payload), err)
	}
	if err := <-deviceDone; err != nil {
		t.Fatalf("device side: %v", err)
	}
	_ = client.Close()
	select {
	case <-served:
	case <-time.After(20 * time.Second):
		t.Fatal("Serve did not return after the client closed")
	}
	return got
}

// A DATA frame of exactly the measured size reaches the client unchanged. This is the pull of
// any file bigger than one frame, which is most files worth moving.
func TestASyncFrameOfTheMeasuredSizeReachesTheClientWhole(t *testing.T) {
	frame := syncDataFrame(adbMaxPacket - 8)
	if len(frame) != adbMaxPacket {
		t.Fatalf("frame is %d bytes, want the packet ceiling of %d", len(frame), adbMaxPacket)
	}
	got := relayDevicePayload(t, frame)
	if !bytes.Equal(got, frame) {
		t.Errorf("client received %d bytes and the device sent %d", len(got), len(frame))
	}
}

// The ceiling is the ceiling: a packet one byte above what a real adb client reads is refused
// rather than allocated on the strength of its own length field.
func TestAPacketAboveTheCeilingIsRefusedRatherThanRead(t *testing.T) {
	frame := syncDataFrame(adbMaxPacket - 7)
	if len(frame) != adbMaxPacket+1 {
		t.Fatalf("frame is %d bytes, want %d", len(frame), adbMaxPacket+1)
	}
	if _, err := readPacket(bufio.NewReader(bytes.NewReader(encodePacket(cmdWRTE, 1, 2, frame)))); err == nil {
		t.Fatal("a packet one byte over the ceiling was read; a real adb client refuses it")
	}
}

// The window this server offers and the ceiling it reads are two different numbers, and
// conflating them is what put a 4096-byte cap on a stream carrying 64 KiB frames. adb's own
// server advertises a megabyte and reads 64 KiB, measured on the same exchange.
func TestTheAdvertisedWindowIsNotTheReadCeiling(t *testing.T) {
	if adbMaxPacket <= adbMaxData {
		t.Fatalf("read ceiling %d is not above the advertised window %d, so the two are the "+
			"same number again", adbMaxPacket, adbMaxData)
	}
}
