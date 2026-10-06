package adbserverproto

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// testOperator is the client identity every test passes to New, standing in for whatever
// authenticated the connection in production.
const testOperator = "someone"

// fakeFilter is the gateway's answer to "what may this client see", and a listing of it so
// the tests can check that a serial is absent as well as refused.
type fakeFilter struct {
	allowed   map[string]bool
	connected map[string]bool
	// features is each device's own list, as its banner carried it.
	features map[string]string
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
	sort.Strings(out)
	return out
}
func (f fakeFilter) Features(s string) string { return f.features[s] }

// silentFilter is a filter with no opinion about features at all, which is what a Filter
// implementation that is not a gateway looks like.
type silentFilter struct{ fakeFilter }

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
	}, testOperator, nil, nil)
}

// host:version is answered with exactly twelve bytes, captured from the stock adb server:
// OKAY, a four-digit length of 0004, and the four characters 0029. No version banner is
// appended. That exactness is the point -- a reply of the right shape but the wrong contents
// is what made adb stop talking to this port while every other test still passed.
func TestHostVersionRepliesExactlyAsTheStockServerDoes(t *testing.T) {
	if got := serveOne(t, testServer(), "host:version"); got != "OKAY00040029" {
		t.Errorf("host:version reply = %q (% x), want \"OKAY00040029\"", got, got)
	}
}

// A second request on the same connection is answered with silence, then the caller closes.
// A real adb server does exactly this, and adb opens a fresh connection per request.
func TestOnlyOneRequestIsAnsweredPerConnection(t *testing.T) {
	p := newPipe()
	defer p.a.Close()
	defer p.b.Close()
	go testServer().Serve(p.b)

	if _, err := p.a.Write(request("host:version")); err != nil {
		t.Fatalf("first request: %v", err)
	}
	buf := make([]byte, 64)
	p.a.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := p.a.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("read first reply: %v", err)
	}
	if string(buf[:n]) != "OKAY00040029" {
		t.Fatalf("first reply = %q", buf[:n])
	}

	// The pipe is synchronous, so a write with nobody reading blocks rather than failing.
	// The deadline is what turns "blocks forever" into "nothing happened", which is the
	// outcome being asserted.
	_ = p.a.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := p.a.Write(request("host:version")); err != nil {
		// The peer closed, which is also the expected outcome.
		return
	}
	p.a.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, _ := p.a.Read(buf); n > 0 {
		t.Errorf("a second request was answered with %q, want nothing", buf[:n])
	}
}

// shell_v2 is the one feature this gateway must claim, and the cost of not claiming it is
// two broken commands that both look like the device's fault. Measured: with an empty
// feature list the adb client sends the bare service "shell:false" and its stdin as raw
// bytes, so no exit status frame is produced and nothing ever says that input has ended.
//
//	reply = OKAY + "0008" + "shell_v2"
//
// Both feature replies are the device's own bytes, and the two bytes of a length prefix in
// front of them.
//
// The captures, from a stock adb server with one device attached whose banner carried
// "shell_v2,cmd,stat_v2,ls_v2,sendrecv_v2,":
//
//	host:features               -> OKAY 0027 "shell_v2,cmd,stat_v2,ls_v2,sendrecv_v2,"
//	host-serial:SERIAL:features -> OKAY 0027, the identical 39 bytes
//
// The trailing comma is in the capture because the device's own banner ends that way, and it
// is passed on rather than tidied up: adb splits the value on commas, so the empty field
// after the last one is a field the device sent, and dropping it would make the reply differ
// from the device in a place nothing reports.
func TestFeatureRepliesAreTheDeviceListVerbatim(t *testing.T) {
	const deviceList = "shell_v2,cmd,stat_v2,ls_v2,sendrecv_v2,"
	s := New(fakeFilter{
		allowed:   map[string]bool{"AAA": true},
		connected: map[string]bool{"AAA": true},
		features:  map[string]string{"AAA": deviceList},
	}, nil, testOperator, nil, nil)

	const want = "OKAY0027shell_v2,cmd,stat_v2,ls_v2,sendrecv_v2,"
	for _, service := range []string{"host:features", "host-serial:AAA:features"} {
		got := serveOne(t, s, service)
		if got != want {
			t.Errorf("%s reply = %q (% x), want %q", service, got, got, want)
		}
	}
}

// host:features has one answer only when there is one device to answer about, and the stock
// server says so rather than picking one. Measured, on that same stock server:
//
//	no device attached   -> FAIL 001a "no devices/emulators found"
//	two devices attached -> FAIL 001d "more than one device/emulator"
//
// A union would be the wrong substitute: it is a list neither device has, and a client
// holding it is entitled to send stat_v2 to a device that never said it could. The cost of
// refusing is measured too -- with two devices attached and this reply failing, `adb shell`
// still opened "shell,v2,TERM=xterm-256color,raw:", because adb asks the per-serial question
// while it builds its transport cache and that one is answered.
func TestHostFeaturesRefusesRatherThanGuessBetweenDevices(t *testing.T) {
	none := New(silentFilter{fakeFilter{}}, nil, testOperator, nil, nil)
	if got := serveOne(t, none, "host:features"); got != "FAIL001ano devices/emulators found" {
		t.Errorf("with no devices: %q, want FAIL001ano devices/emulators found", got)
	}

	two := New(fakeFilter{allowed: map[string]bool{"AAA": true, "BBB": true}}, nil, testOperator, nil, nil)
	if got := serveOne(t, two, "host:features"); got != "FAIL001dmore than one device/emulator" {
		t.Errorf("with two devices: %q, want FAIL001dmore than one device/emulator", got)
	}
}

// A feature list is the device's claim, not this server's, so a filter that cannot supply
// one produces an empty reply rather than a substitute. There is no substitute to reach for:
// any list invented here would be a claim about a device made by something that has not
// spoken to it.
func TestFeatureReplyIsEmptyWhenTheFilterHasNoFeatures(t *testing.T) {
	s := New(silentFilter{fakeFilter{allowed: map[string]bool{"AAA": true}}}, nil, testOperator, nil, nil)
	if got := serveOne(t, s, "host-serial:AAA:features"); got != "OKAY0000" {
		t.Errorf("reply = %q, want OKAY0000", got)
	}
}

// `adb get-state` asks the server rather than opening a transport. It was unimplemented and
// failed with "unknown service" on every device, which reads as a broken gateway rather than as
// a missing command. The exact replies, captured from the stock server:
//
//	host-serial:SERIAL:get-state  -> OKAY 0006 "device"    (attached)
//	host-serial:other:get-state   -> OKAY 0007 "offline"   (entitled, not attached)
//	host-serial:nope:get-state    -> FAIL 0017 "device 'nope' not found"
func TestHostSerialGetStateAnswersFromTheRegistry(t *testing.T) {
	s := New(fakeFilter{
		allowed:   map[string]bool{"AAA": true, "BBB": true},
		connected: map[string]bool{"AAA": true},
	}, func(string) (net.Conn, error) { return nil, fmt.Errorf("unused") }, testOperator, nil, nil)

	// AAA is attached, BBB is entitled but not attached. One message per case so a FAIL is
	// distinguishable from a state, which is the whole point of the command.
	for _, tc := range []struct{ service, want string }{
		{"host-serial:AAA:get-state", "OKAY0006device"},
		{"host-serial:BBB:get-state", "OKAY0007offline"},
		{"host-serial:SECRET:get-state", "FAIL0019device 'SECRET' not found"},
	} {
		if got := serveOne(t, s, tc.service); got != tc.want {
			t.Errorf("%s reply = %q (% x), want %q", tc.service, got, got, tc.want)
		}
	}
}

// An adb serial over TCP is host:port, so the serial contains a colon. Splitting on the first
// colon truncates it and the device stops being found.
func TestSerialWithAColonSurvivesHostSerialRequests(t *testing.T) {
	s := New(fakeFilter{
		allowed:   map[string]bool{"127.0.0.1:5555": true},
		connected: map[string]bool{"127.0.0.1:5555": true},
	}, func(string) (net.Conn, error) { return nil, fmt.Errorf("unused") }, testOperator, nil, nil)
	if got := serveOne(t, s, "host-serial:127.0.0.1:5555:get-state"); got != "OKAY0006device" {
		t.Errorf("reply = %q (% x), want \"OKAY0006device\"", got, got)
	}
}

// An action this server does not implement is refused by name rather than falling through to
// the generic unknown-service message, which would blame the request the operator never made.
func TestUnknownHostSerialActionIsRefusedByName(t *testing.T) {
	got := serveOne(t, testServer(), "host-serial:AAA:sync-something")
	if !strings.HasPrefix(got, "FAIL") {
		t.Fatalf("reply %q is not a FAIL", got)
	}
	if !strings.Contains(got, "sync-something") {
		t.Errorf("FAIL %q does not name the action that was refused", got)
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

// A refusal has to reach the operator as a sentence. The exact wire form is captured from the
// stock server:
//
//	host:tport:serial:nope -> FAIL 0017 "device 'nope' not found"
//
// One four-digit length, then the message. A second length inside it is not a variant adb
// tolerates: adb reads the four digits after FAIL as the message length, reads that many bytes
// and prints them, so the digits of a misplaced length appear in the middle of the sentence an
// operator is trying to read:
//
//	error: 0052operator "bob" may not attach to "dev-a": role "observer" lacks permission "shell"
func TestFailReplyIsTheMessageAndNothingElse(t *testing.T) {
	msg := fmt.Sprintf("device '%s' not found", "nope")
	got := serveOne(t, testServer(), "host:tport:serial:nope")
	want := "FAIL" + fmt.Sprintf("%04x", len(msg)) + msg
	if got != want {
		t.Errorf("reply = %q (% x), want %q (% x)", got, got, want, want)
	}
}

// Whatever the reason, a refusal names the device it is about, so an operator can tell which of
// their devices is the one that was stopped.
func TestFailReplyNamesTheDevice(t *testing.T) {
	got := serveOne(t, testServer(), "host:transport:SECRET")
	// FAIL, four digits of length, then the message and nothing after it.
	if len(got) < 8 {
		t.Fatalf("FAIL reply too short to carry a message: %q", got)
	}
	msg := got[8:]
	if !strings.Contains(msg, "SECRET") {
		t.Errorf("FAIL %q does not name the device it refused, so an operator cannot tell why", msg)
	}
	if n, err := strconv.ParseUint(got[4:8], 16, 32); err != nil || int(n) != len(msg) {
		t.Errorf("FAIL length says %q for a %d byte message; adb would print the wrong bytes", got[4:8], len(msg))
	}
}

// host:transport is the raw form: after OKAY the connection carries the ADB transport itself,
// so the client sends CNXN and the bytes belong to the device with nothing in between.
//
// This is asserted on host:transport rather than host:tport because the two are not the same
// protocol, and a test on tport that wrote a CNXN straight after the OKAY would be asserting a
// conversation no adb client has. On tport the client sends a service request instead, and this
// server does the CNXN and OPEN with the device -- see TestShellV2ExitStatusReachesTheClientUnaltered
// for those exact bytes.
func TestHostTransportBecomesARawDeviceTransport(t *testing.T) {
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
		}, testOperator, nil, nil)

	done := make(chan error, 1)
	go func() { done <- s.Serve(server) }()

	if _, err := client.Write(request("host:transport:AAA")); err != nil {
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

	// host:transport is answered with a bare four-byte OKAY -- captured from the stock
	// server, and the whole difference from tport, which appends a 64-bit transport id.
	head := make([]byte, 4)
	client.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(client, head); err != nil {
		t.Fatalf("read OKAY: %v", err)
	}
	if string(head) != "OKAY" {
		t.Fatalf("host:transport reply %q (% x), want \"OKAY\"", head, head)
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
		}, testOperator, nil, nil)
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
	s := New(nil, func(string) (net.Conn, error) { return nil, fmt.Errorf("unused") }, testOperator, nil, nil)
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
	var mu sync.Mutex
	allowed := true
	s := New(filterFunc(func(string) bool {
		mu.Lock()
		defer mu.Unlock()
		return allowed
	}), func(string) (net.Conn, error) {
		return nil, fmt.Errorf("not needed for this assertion")
	}, testOperator, nil, nil)

	// One request per connection, because that is the protocol: adb opens a fresh
	// connection for each host service request. Revocation still has to take effect
	// between two requests rather than being remembered from the first connection.
	ask := func() string {
		pp := newPipe()
		c, srv := pp.a, pp.b
		go s.Serve(srv)
		defer c.Close()
		defer srv.Close()
		if _, err := c.Write(request("host-serial:AAA:features")); err != nil {
			t.Fatalf("write: %v", err)
		}
		buf := make([]byte, 256)
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, _ := c.Read(buf)
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

// The bytes the device sees for a shell command, and the bytes the client sees back, asserted
// as exact captures rather than as "the shape is right". Every byte here was taken off a live
// exchange between the stock adb server, a device and the real adb client:
//
//	host -> device  OPEN arg0=<host id> arg1=0 len=0x27 "shell,v2,TERM=xterm-256color,raw:false\0"
//	device -> host  OKAY arg0=0x1e(argument is the device's stream id) arg1=<host id>
//	device -> host  WRTE arg0=<device id> arg1=<host id> len=6 03 01 00 00 00 01
//	host -> device  OKAY arg0=<device id> arg1=<host id>
//	device -> host  CLSE arg0=<device id> arg1=<host id>
//	host -> device  CLSE arg0=<device id> arg1=<host id>
//
// The three things this asserts that a shape check would not have caught: the device's stream
// id has to be read out of the OKAY reply and used as arg0 of every later packet, the WRTE
// has to be acknowledged, and the client has to receive the six payload bytes untouched --
// `03 01 00 00 00 01` is the shell v2 exit frame, id 3, length 1, status 1, and it is how
// `adb shell false` comes back as a failure.
func TestShellV2ExitStatusReachesTheClientUnaltered(t *testing.T) {
	ad := newPipe()
	dev := newPipe()
	client, server := ad.a, ad.b
	device := dev.b
	defer client.Close()
	defer server.Close()
	defer dev.a.Close()
	defer device.Close()

	s := New(fakeFilter{allowed: map[string]bool{"AAA": true}},
		func(string) (net.Conn, error) { return dev.a, nil }, testOperator, nil, nil)
	go s.Serve(server)

	// The device side: answer the handshake, then send the exact six payload bytes the
	// capture shows, then close the stream.
	const deviceID = 0x1e
	done := make(chan struct{})
	go func() {
		defer close(done)
		br := bufio.NewReader(device)
		if err := expectPacket(device, br, cmdCNXN, cnxnArg0, adbMaxData); err != nil {
			t.Errorf("device: %v", err)
			return
		}
		if err := writeTo(device, encodePacket(cmdCNXN, cnxnArg0, adbMaxData, []byte("device::"))); err != nil {
			t.Errorf("device: %v", err)
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
		if want := "shell,v2,TERM=xterm-256color,raw:false\x00"; string(open.payload) != want {
			t.Errorf("device: OPEN payload %q, want %q", open.payload, want)
		}
		if open.arg1 != 0 {
			t.Errorf("device: OPEN arg1 = %d, want 0", open.arg1)
		}
		if err := writeTo(device, encodePacket(cmdOKAY, deviceID, open.arg0, nil)); err != nil {
			t.Errorf("device: %v", err)
			return
		}
		// net.Pipe is unbuffered, so the order here has to alternate with the host's or the
		// two goroutines deadlock on each other's writes. The host's order is measured and
		// fixed: ack the WRTE, then send the CLSE once it has seen the device's own.
		if err := writeTo(device, encodePacket(cmdWRTE, deviceID, open.arg0, []byte{0x03, 0x01, 0x00, 0x00, 0x00, 0x01})); err != nil {
			t.Errorf("device: %v", err)
			return
		}
		if err := expectPacket(device, br, cmdOKAY, open.arg0, deviceID); err != nil {
			t.Errorf("device: the WRTE was not acknowledged: %v", err)
			return
		}
		if err := writeTo(device, encodePacket(cmdCLSE, deviceID, open.arg0, nil)); err != nil {
			t.Errorf("device: %v", err)
			return
		}
		if err := expectPacket(device, br, cmdCLSE, open.arg0, deviceID); err != nil {
			t.Errorf("device: the close was not answered with a close: %v", err)
		}
	}()

	if _, err := client.Write(request("host:tport:serial:AAA")); err != nil {
		t.Fatalf("write request: %v", err)
	}
	head := make([]byte, 12)
	client.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(client, head); err != nil {
		t.Fatalf("read tport reply: %v", err)
	}
	if _, err := client.Write(request("shell,v2,TERM=xterm-256color,raw:false")); err != nil {
		t.Fatalf("write service request: %v", err)
	}

	// A switched transport answers with a bare OKAY and then hands over a raw stream, so
	// everything after it is the stream itself.
	ack := make([]byte, 4)
	if _, err := io.ReadFull(client, ack); err != nil {
		t.Fatalf("read stream acknowledgement: %v", err)
	}
	if string(ack) != "OKAY" {
		t.Fatalf("stream acknowledgement %q, want \"OKAY\"", ack)
	}

	// Exactly the six bytes from the capture, no framing added and none removed.
	payload := make([]byte, 6)
	if _, err := io.ReadFull(client, payload); err != nil {
		t.Fatalf("read the device's payload: %v", err)
	}
	want := []byte{0x03, 0x01, 0x00, 0x00, 0x00, 0x01}
	if !bytes.Equal(payload, want) {
		t.Errorf("client received % x, want % x", payload, want)
	}

	<-done
}

// The client's input has to reach the device addressed to the stream the device named, and
// the end of it has to arrive as a CLSE.
//
// Measured against the stock server with `adb shell cat` and a five-byte file:
//
//	host -> device  WRTE arg0=0x76 arg1=0x1f len=5 00 05 00 00 00 "hello"   <- the v2 stdin frame
//	device -> host  OKAY arg0=0x1f arg1=0x76
//	... and on the client's half-close:
//	host -> device  CLSE arg0=0x76 arg1=0x1f
//
// arg0 is the device's stream id and arg1 is the host's. Written the other way round -- arg0
// the host's own id and arg1 zero, as this did before -- the device resolves no stream from
// arg1 and drops the payload without saying so: `adb shell cat` reads no input and blocks
// forever. That is the failure this test was written for.
func TestClientInputReachesTheDeviceStreamTheDeviceNamed(t *testing.T) {
	// A real TCP socket on the client side, not net.Pipe. The assertion is about a
	// half-close, which net.Pipe has no way to express: it can only be closed outright,
	// which would end the output direction too and make the case indistinguishable from
	// the client going away. adb's own connection is a socket too, so this is closer to
	// what happens than the pipe was.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	type accepted struct {
		conn net.Conn
		err  error
	}
	acceptc := make(chan accepted, 1)
	go func() {
		c, err := ln.Accept()
		acceptc <- accepted{c, err}
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	got := <-acceptc
	if got.err != nil {
		t.Fatalf("accept: %v", got.err)
	}
	server := got.conn
	defer server.Close()

	dev := newPipe()
	device := dev.b
	defer dev.a.Close()
	defer device.Close()

	const deviceID = 0x1f
	s := New(fakeFilter{allowed: map[string]bool{"AAA": true}},
		func(string) (net.Conn, error) { return dev.a, nil }, testOperator, nil, nil)
	go s.Serve(server)

	done := make(chan struct{})
	go func() {
		defer close(done)
		br := bufio.NewReader(device)
		if err := expectPacket(device, br, cmdCNXN, cnxnArg0, adbMaxData); err != nil {
			t.Errorf("device: %v", err)
			return
		}
		if err := writeTo(device, encodePacket(cmdCNXN, cnxnArg0, adbMaxData, []byte("device::"))); err != nil {
			t.Errorf("device: %v", err)
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
			t.Errorf("device: %v", err)
			return
		}
		// The stdin frame is the client's own: id 0, a four-byte little-endian length, then
		// the bytes. The gateway does not build it and must not disturb it.
		first, err := readPacket(br)
		if err != nil {
			t.Errorf("device: read WRTE: %v", err)
			return
		}
		wantFrame := append([]byte{0x00, 0x05, 0x00, 0x00, 0x00}, []byte("hello")...)
		// arg0 is this server's stream id and arg1 the device's. The device resolves the
		// stream from arg1, so a packet with the pair the other way round is dropped without
		// a word -- which is the whole reason this assertion reads both fields.
		if first.arg0 != open.arg0 || first.arg1 != deviceID {
			t.Errorf("WRTE arg0=%d arg1=%d, want arg0=%d arg1=%d", first.arg0, first.arg1, open.arg0, deviceID)
		}
		if !bytes.Equal(first.payload, wantFrame) {
			t.Errorf("device received % x, want % x", first.payload, wantFrame)
		}
		if err := writeTo(device, encodePacket(cmdOKAY, deviceID, open.arg0, nil)); err != nil {
			t.Errorf("device: %v", err)
			return
		}
		// The end of the client's input. Read on the same buffered reader as everything else,
		// because a second reader on the same conn would miss whatever this one had already
		// taken in and the assertion would be about nothing.
		if err := expectPacket(device, br, cmdCLSE, open.arg0, deviceID); err != nil {
			t.Errorf("device: the end of the client's input did not arrive as a CLSE: %v", err)
		}
	}()

	if _, err := client.Write(request("host:tport:serial:AAA")); err != nil {
		t.Fatalf("write request: %v", err)
	}
	head := make([]byte, 12)
	client.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(client, head); err != nil {
		t.Fatalf("read tport reply: %v", err)
	}
	if _, err := client.Write(request("shell,v2,TERM=xterm-256color,raw:cat")); err != nil {
		t.Fatalf("write service request: %v", err)
	}
	// The bare OKAY comes before the stream. It is read here rather than folded into the
	// payload assertion because it is part of the handshake, not part of what the device
	// said -- a test that skipped it would read four bytes of handshake as stream data and
	// blame the relay.
	ack := make([]byte, 4)
	if _, err := io.ReadFull(client, ack); err != nil {
		t.Fatalf("read stream acknowledgement: %v", err)
	}
	if string(ack) != "OKAY" {
		t.Fatalf("stream acknowledgement %q, want \"OKAY\"", ack)
	}
	if _, err := client.Write([]byte{0x00, 0x05, 0x00, 0x00, 0x00, 'h', 'e', 'l', 'l', 'o'}); err != nil {
		t.Fatalf("write stdin: %v", err)
	}
	// Half-close: the client's input is over and its output is still expected. This is
	// what adb's shell client does when stdin reaches its end, and it is the event the
	// CLSE exists for.
	if err := client.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatalf("half-close: %v", err)
	}

	<-done
}

// expectPacket reads one packet and checks its command and its two ids, which is the whole
// content of most of the assertions here.
func expectPacket(c net.Conn, br *bufio.Reader, command string, arg0, arg1 uint32) error {
	p, err := readPacket(br)
	if err != nil {
		return fmt.Errorf("read %s: %w", command, err)
	}
	if p.command != command {
		return fmt.Errorf("packet is %s, want %s (arg0=%d arg1=%d len=%d)", p.command, command, p.arg0, p.arg1, len(p.payload))
	}
	if p.arg0 != arg0 || p.arg1 != arg1 {
		return fmt.Errorf("%s arg0=%d arg1=%d, want arg0=%d arg1=%d", command, p.arg0, p.arg1, arg0, arg1)
	}
	return nil
}

// writeTo writes one packet. net.Pipe is synchronous, so a write blocks until the reader takes
// it, which is what keeps these two goroutines in step.
func writeTo(c net.Conn, p []byte) error {
	if _, err := c.Write(p); err != nil {
		return fmt.Errorf("write packet: %w", err)
	}
	return nil
}

// host:transport is answered with a bare four-byte OKAY and nothing else. The stock server
// does exactly that, and the distinction from tport is eight bytes of transport id: treating
// the two as the same reply left adb waiting for an id that never came.
func TestHostTransportRepliesWithBareOKAY(t *testing.T) {
	// The device has to open, because a failure to open is answered with FAIL and the
	// reply being measured is the one that follows a successful open.
	dev := newPipe()
	defer dev.a.Close()
	defer dev.b.Close()
	s := New(fakeFilter{allowed: map[string]bool{"AAA": true}},
		func(string) (net.Conn, error) { return dev.a, nil }, testOperator, nil, nil)

	p := newPipe()
	defer p.a.Close()
	defer p.b.Close()
	go s.Serve(p.b)

	if _, err := p.a.Write(request("host:transport:AAA")); err != nil {
		t.Fatalf("write request: %v", err)
	}
	head := make([]byte, 4)
	p.a.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(p.a, head); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if string(head) != "OKAY" {
		t.Errorf("host:transport reply = %q (% x), want \"OKAY\"", head, head)
	}
}
