package adbserverproto

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeFilter is the gateway's answer to "what may this client see", and a listing of it so
// the tests can check that a serial is absent as well as refused.
type fakeFilter struct {
	allowed   map[string]bool
	connected map[string]bool
}

func (f fakeFilter) Allows(s string) bool { return f.allowed[s] }
func (f fakeFilter) Connected(s string) bool {
	return f.connected[s]
}
func (f fakeFilter) Serials() []string {
	out := make([]string, 0, len(f.allowed))
	for s := range f.allowed {
		out = append(out, s)
	}
	return out
}

// pipe is a net.Conn pair for tests: one end is what adb would hold, the other is what the
// caller sees when the server opens a device.
type pipe struct {
	a, b net.Conn
}

func newPipe() pipe {
	a, b := net.Pipe()
	return pipe{a: a, b: b}
}

func (p pipe) client() net.Conn { return p.a }

// request frames a service string the way adb does.
func request(service string) []byte {
	return []byte(fmt.Sprintf("%04x%s", len(service), service))
}

func TestReadRequestFramesLengthPrefixedService(t *testing.T) {
	for _, svc := range []string{
		"host:version",
		"host:devices",
		"host:tport:serial:ABC123",
		strings.Repeat("x", 300),
	} {
		got, err := readRequest(bufio.NewReader(bytes.NewReader(request(svc))))
		if err != nil {
			t.Fatalf("%q: %v", svc, err)
		}
		if got != svc {
			t.Errorf("read %q, want %q", got, svc)
		}
	}
}

func TestReadRequestRejectsMalformedLength(t *testing.T) {
	cases := map[string][]byte{
		"uppercase hex":  []byte("000Ahost:version"),
		"non hex digit":  []byte("00ZZhost:version"),
		"zero length":    []byte("0000"),
		"over the limit": append([]byte(fmt.Sprintf("%04x", maxRequest+1)), 'x'),
	}
	for name, in := range cases {
		if _, err := readRequest(bufio.NewReader(bytes.NewReader(in))); err == nil {
			t.Errorf("%s: expected an error, got none", name)
		}
	}
}

func TestReadRequestReportsEOFOnCleanDisconnect(t *testing.T) {
	if _, err := readRequest(bufio.NewReader(bytes.NewReader(nil))); err != io.EOF {
		t.Fatalf("err = %v, want io.EOF", err)
	}
}

// serveOne runs one request through the server on a pipe and returns what the client read.
func serveOne(t *testing.T, s *Server, service string) string {
	t.Helper()
	p := newPipe()
	done := make(chan error, 1)
	go func() { done <- s.Serve(p.b) }()

	if _, err := p.client().Write(request(service)); err != nil {
		t.Fatalf("write request: %v", err)
	}
	p.client().SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4096)
	n, err := p.client().Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("read reply: %v", err)
	}
	p.client().Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after the client closed")
	}
	return string(buf[:n])
}

func testServer() *Server {
	return New(fakeFilter{
		allowed:   map[string]bool{"AAA": true, "BBB": true},
		connected: map[string]bool{"AAA": true},
	}, func(string) (net.Conn, error) {
		return nil, fmt.Errorf("no device in this test")
	}, nil)
}

func TestHostVersionAndFeaturesReplyOKAYWithValue(t *testing.T) {
	for _, service := range []string{"host:version", "host:features"} {
		got := serveOne(t, testServer(), service)
		if !strings.HasPrefix(got, "OKAY") {
			t.Fatalf("%s: reply %q does not start with OKAY", service, got)
		}
		// OKAY, then a four-digit length, then the payload.
		if len(got) < 8 {
			t.Fatalf("%s: reply too short to carry a length: %q", service, got)
		}
		declared := got[4:8]
		payload := got[8:]
		if fmt.Sprintf("%04x", len(payload)) != declared {
			t.Errorf("%s: declared length %q, payload is %d bytes", service, declared, len(payload))
		}
	}
}

func TestHostDevicesListsOnlyEntitledSerials(t *testing.T) {
	got := serveOne(t, testServer(), "host:devices")
	if !strings.HasPrefix(got, "OKAY") {
		t.Fatalf("reply %q does not start with OKAY", got)
	}
	list := got[8:]
	for _, serial := range []string{"AAA", "BBB"} {
		if !strings.Contains(list, serial) {
			t.Errorf("listing %q omits entitled device %s", list, serial)
		}
	}
	// AAA is connected and BBB is not, and the state has to say so.
	if !strings.Contains(list, "AAA\tdevice") {
		t.Errorf("listing %q does not mark the connected device as device", list)
	}
	if !strings.Contains(list, "BBB\toffline") {
		t.Errorf("listing %q does not mark the absent device as offline", list)
	}
}

// The point of filtering: a client that was never shown a serial must not get one, and a
// modified client that asks by name must be refused. Refusing is the part that matters --
// hiding it from the listing alone would not be enough.
func TestUnentitledSerialIsRefusedOnEveryTransportRequest(t *testing.T) {
	for _, service := range []string{
		"host:tport:serial:SECRET",
		"host:transport:SECRET",
		"host-serial:SECRET:features",
	} {
		got := serveOne(t, testServer(), service)
		if !strings.HasPrefix(got, "FAIL") {
			t.Errorf("%s: reply %q is not a FAIL -- an unentitled device was not refused", service, got)
		}
	}
}

func TestUnknownServiceFailsRatherThanHanging(t *testing.T) {
	got := serveOne(t, testServer(), "host:something-nobody-defined")
	if !strings.HasPrefix(got, "FAIL") {
		t.Fatalf("reply %q is not a FAIL", got)
	}
}

func TestFailReplyCarriesAMessage(t *testing.T) {
	got := serveOne(t, testServer(), "host:transport:SECRET")
	// FAIL, total length, message length, message.
	if len(got) < 12 {
		t.Fatalf("FAIL reply too short to carry a message: %q", got)
	}
	if !strings.Contains(got, "SECRET") {
		t.Errorf("FAIL %q does not name the device it refused, so an operator cannot tell why", got)
	}
}

// After OKAY on tport the connection must become the device's transport: bytes written by
// the client have to arrive at the device, and the device's bytes have to arrive back.
func TestTportTurnsTheConnectionIntoADeviceTransport(t *testing.T) {
	// Two separate pairs. The first is the connection adb holds and the server serves; the
	// second is the device, with the server holding one end and the test the other. Sharing
	// one pair would connect the client's own writes straight back to itself.
	ad := newPipe()
	dev := newPipe()
	client, server := ad.a, ad.b
	device := dev.b
	defer client.Close()
	defer server.Close()
	defer dev.a.Close()
	defer device.Close()

	opened := make(chan string, 1)
	s := New(fakeFilter{allowed: map[string]bool{"AAA": true}},
		func(serial string) (net.Conn, error) {
			opened <- serial
			return dev.a, nil
		}, nil)

	done := make(chan error, 1)
	go func() { done <- s.Serve(server) }()

	if _, err := client.Write(request("host:tport:serial:AAA")); err != nil {
		t.Fatalf("write request: %v", err)
	}

	select {
	case serial := <-opened:
		if serial != "AAA" {
			t.Fatalf("opened %q, want AAA", serial)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the device was never opened")
	}

	// Read the OKAY, then the relay takes over.
	head := make([]byte, 4)
	client.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(client, head); err != nil {
		t.Fatalf("read OKAY: %v", err)
	}
	if string(head) != "OKAY" {
		t.Fatalf("first four bytes %q, want OKAY", head)
	}

	// Client to device: this is the CNXN the real adb would send here.
	if _, err := client.Write([]byte("CNXN-from-client")); err != nil {
		t.Fatalf("write to transport: %v", err)
	}
	got := make([]byte, len("CNXN-from-client"))
	device.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(device, got); err != nil {
		t.Fatalf("device did not receive the client's bytes: %v", err)
	}
	if string(got) != "CNXN-from-client" {
		t.Errorf("device received %q", got)
	}

	// And back the other way.
	if _, err := device.Write([]byte("from-device")); err != nil {
		t.Fatalf("write from device: %v", err)
	}
	back := make([]byte, len("from-device"))
	client.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(client, back); err != nil {
		t.Fatalf("client did not receive the device's bytes: %v", err)
	}
	if string(back) != "from-device" {
		t.Errorf("client received %q", back)
	}

	client.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after the client closed")
	}
}

// A device that cannot be opened has to be reported, not left hanging.
func TestTportReportsADeviceThatWillNotOpen(t *testing.T) {
	s := New(fakeFilter{allowed: map[string]bool{"AAA": true}},
		func(string) (net.Conn, error) {
			return nil, fmt.Errorf("device busy")
		}, nil)
	got := serveOne(t, s, "host:tport:serial:AAA")
	if !strings.HasPrefix(got, "FAIL") {
		t.Fatalf("reply %q is not a FAIL", got)
	}
	if !strings.Contains(got, "busy") {
		t.Errorf("FAIL %q does not carry the reason the device could not be opened", got)
	}
}

// A nil filter is a programming error, not an open door: nothing is entitled, so everything
// must be refused rather than allowed by accident.
func TestNilFilterEntitlesNothing(t *testing.T) {
	s := New(nil, func(string) (net.Conn, error) { return nil, fmt.Errorf("unused") }, nil)
	for _, service := range []string{"host:tport:serial:AAA", "host:transport:AAA"} {
		if got := serveOne(t, s, service); !strings.HasPrefix(got, "FAIL") {
			t.Errorf("%s with no filter: reply %q is not a FAIL", service, got)
		}
	}
}

// Entitlement is consulted per request rather than remembered from when the connection was
// accepted, so revocation takes effect on the next request instead of whenever the client
// happens to reconnect.
func TestRevocationTakesEffectOnAnOpenConnection(t *testing.T) {
	p := newPipe()
	defer p.a.Close()
	defer p.b.Close()

	var mu sync.Mutex
	allowed := true
	s := New(filterFunc(func(string) bool {
		mu.Lock()
		defer mu.Unlock()
		return allowed
	}), func(string) (net.Conn, error) {
		return nil, fmt.Errorf("not needed for this assertion")
	}, nil)

	go s.Serve(p.b)

	ask := func() string {
		// host-serial:<serial>:features checks entitlement and then answers, without
		// opening anything, which is what makes it a clean probe of the filter alone.
		if _, err := p.a.Write(request("host-serial:AAA:features")); err != nil {
			t.Fatalf("write: %v", err)
		}
		buf := make([]byte, 256)
		p.a.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, _ := p.a.Read(buf)
		return string(buf[:n])
	}

	// Granted first, so a later FAIL can only come from the revocation.
	if got := ask(); !strings.HasPrefix(got, "OKAY") {
		t.Fatalf("while entitled, reply %q is not OKAY", got)
	}
	mu.Lock()
	allowed = false
	mu.Unlock()

	if got := ask(); !strings.HasPrefix(got, "FAIL") {
		t.Errorf("after revocation on the same connection, reply %q is still permitted", got)
	}
}

// filterFunc adapts a function to Filter for tests that do not need a listing.
type filterFunc func(string) bool

func (f filterFunc) Allows(s string) bool  { return f(s) }
func (f filterFunc) Connected(string) bool { return false }
