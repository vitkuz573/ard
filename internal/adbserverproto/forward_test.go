package adbserverproto

import (
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeForwards is a Forwards set that records what it was asked for and reports a fixed
// bound port, so the reply bytes can be pinned without a listener in the way.
type fakeForwards struct {
	mu sync.Mutex

	// port is what Bind answers with, and it is what the reply carries to the client.
	port int
	// bindErr, when set, is what Bind fails with.
	bindErr error

	binds    []string
	norebind []bool
	kills    []string
}

func (f *fakeForwards) Bind(operator, serial, local, remote string, norebind bool) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.binds = append(f.binds, strings.Join([]string{operator, serial, local, remote}, "|"))
	f.norebind = append(f.norebind, norebind)
	if f.bindErr != nil {
		return 0, f.bindErr
	}
	return f.port, nil
}

func (f *fakeForwards) Kill(serial, local string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.kills = append(f.kills, strings.Join([]string{serial, local}, "|"))
}

func (f *fakeForwards) List(string) string { return "" }

// listForwards reports a fixed one-forward listing and records which serial it was asked
// about, which is the part that decides whether one device's forwards can be told from
// another's.
type listForwards struct {
	mu     sync.Mutex
	listed []string
}

func (l *listForwards) Bind(string, string, string, string, bool) (int, error) {
	return 0, fmt.Errorf("not used in this test")
}
func (l *listForwards) Kill(string, string) {}
func (l *listForwards) List(serial string) string {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.listed = append(l.listed, serial)
	return "AAA tcp:9930 tcp:9931\n"
}

// forwardingServer returns a Server with forwards set and every device allowed, which is the
// state a forwarding request is answered from.
func forwardingServer(set Forwards) *Server {
	return New(fakeFilter{
		allowed:   map[string]bool{"AAA": true, "BBB": true},
		connected: map[string]bool{"AAA": true, "BBB": true},
	}, func(string) (net.Conn, error) {
		return nil, fmt.Errorf("no device in this test")
	}, testOperator, nil, set)
}

// switched asks for a transport and then for a service on it, returning what the client reads
// in answer to the service.
//
// The two-step shape is what a real client does: `adb forward` opens a transport to the device
// first and sends the forwarding request on the switched connection, so a test that sent
// "host:forward:..." as its only request would be asserting a conversation adb does not have.
// The four-byte acknowledgement of the switch is read and checked here, because it belongs to
// the transport rather than to the answer under test.
//
// The device end of the connection is a pipe this never reads. That is deliberate for every
// test using it: a forwarding request is answered before the device is spoken to, and the one
// test that asserts that waits on the device to confirm its silence.
func switched(t *testing.T, s *Server, serial, service string) string {
	t.Helper()
	ad := newPipe()
	dev := newPipe()
	client, server := ad.a, ad.b
	defer client.Close()
	defer server.Close()
	defer dev.a.Close()
	defer dev.b.Close()

	served := New(s.filter, func(string) (net.Conn, error) { return dev.a, nil }, s.operator, s.logf, s.forwards)
	go func() { _ = served.Serve(server) }()

	if _, err := client.Write(request("host:tport:serial:" + serial)); err != nil {
		t.Fatalf("write tport request: %v", err)
	}
	head := make([]byte, 12)
	client.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(client, head); err != nil {
		t.Fatalf("read tport reply: %v", err)
	}
	if string(head[:4]) != okayToken {
		t.Fatalf("tport reply % x, want it to begin OKAY", head)
	}
	if _, err := client.Write(request(service)); err != nil {
		t.Fatalf("write service request: %v", err)
	}
	// A switched transport is acknowledged with a bare OKAY and then hands over a raw
	// stream, so this reads the acknowledgement on its own and the service's answer after
	// it. Two writes, two reads: the connection is unbuffered, so nothing else can be
	// waiting.
	ack := make([]byte, 4)
	if _, err := io.ReadFull(client, ack); err != nil {
		t.Fatalf("read the switch acknowledgement: %v", err)
	}
	if string(ack) != okayToken {
		t.Fatalf("switch acknowledgement %q, want a bare %q", ack, okayToken)
	}
	buf := make([]byte, 4096)
	n, err := client.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("read the reply: %v", err)
	}
	return string(buf[:n])
}

// A bind is answered with the port that was bound, as decimal characters behind a four-hex
// length. Both details are measured: a client asked to bind tcp:0 prints the characters it
// reads here, and the same four bytes as a little-endian integer print an empty port.
func TestForwardBindRepliesWithTheBoundPortAsDigits(t *testing.T) {
	set := &fakeForwards{port: 9930}
	s := forwardingServer(set)

	if got := switched(t, s, "AAA", "host:forward:tcp:9930;tcp:9931"); got != "OKAY00049930" {
		t.Errorf("bind reply = %q (% x), want \"OKAY00049930\"", got, got)
	}
	if len(set.binds) != 1 {
		t.Fatalf("Bind called %d times, want 1", len(set.binds))
	}
	// The operator and the serial travel with the bind: the connection is closed the moment
	// the request is answered, so neither can be read off it again when the port is used.
	if want := "someone|AAA|tcp:9930|tcp:9931"; set.binds[0] != want {
		t.Errorf("Bind got %q, want %q", set.binds[0], want)
	}
	if set.norebind[0] {
		t.Error("Bind was told to rebind; the request did not ask for --no-rebind")
	}
}

// The serial the client switched onto is the device the forward leads to, and a forward for one
// device must not be reported as a forward for another.
func TestForwardBindCarriesTheSwitchedSerial(t *testing.T) {
	set := &fakeForwards{port: 1234}
	s := forwardingServer(set)

	switched(t, s, "BBB", "host:forward:tcp:1;tcp:2")
	if len(set.binds) != 1 {
		t.Fatalf("Bind called %d times, want 1", len(set.binds))
	}
	if want := "someone|BBB|tcp:1|tcp:2"; set.binds[0] != want {
		t.Errorf("Bind got %q, want it to end in %q", set.binds[0], want)
	}
}

// --no-rebind reaches Bind as part of the operation, because whether an existing forward may
// be replaced is the set's decision rather than something the protocol layer can decide.
func TestForwardNoRebindReachesBindAsPartOfTheOperation(t *testing.T) {
	set := &fakeForwards{port: 9932}
	switched(t, forwardingServer(set), "AAA", "host:forward:norebind:tcp:9932;tcp:9933")

	if len(set.binds) != 1 {
		t.Fatalf("Bind called %d times, want 1", len(set.binds))
	}
	// The flag comes off the front, so the specification handed over is still the pair of
	// ports rather than a local port spelled "norebind:9932".
	if want := "someone|AAA|tcp:9932|tcp:9933"; set.binds[0] != want {
		t.Errorf("Bind got %q, want %q", set.binds[0], want)
	}
	if !set.norebind[0] {
		t.Error("Bind was not told about --no-rebind")
	}
}

// Both removals are answered with a bare OKAY: no length and no body, measured. The difference
// is worth asserting -- a client that read a length here would read the four OKAY bytes of the
// next reply as that length and desynchronise for the rest of the connection.
func TestForwardRemovalRepliesWithABareOKAY(t *testing.T) {
	for _, tc := range []struct {
		service string
		kill    string
	}{
		{"host:killforward:tcp:9930", "AAA|tcp:9930"},
		// --remove-all names no specification, and the client has switched onto one device
		// by the time it arrives, so the serial is what bounds it.
		{"host:killforward-all", "AAA|"},
	} {
		set := &fakeForwards{}
		got := switched(t, forwardingServer(set), "AAA", tc.service)
		if got != "OKAY" {
			t.Errorf("%s reply = %q (% x), want a bare \"OKAY\"", tc.service, got, got)
		}
		if len(set.kills) != 1 || set.kills[0] != tc.kill {
			t.Errorf("%s killed %v, want [%s]", tc.service, set.kills, tc.kill)
		}
	}
}

// A port that is asked for but cannot be bound is refused in words. Silence here is a hang
// rather than a refusal: `adb forward` waits for the answer it never gets.
func TestForwardBindFailureIsRefusedWithTheReason(t *testing.T) {
	set := &fakeForwards{bindErr: fmt.Errorf("tcp:80 is already forwarded; --no-rebind replaces it")}
	got := switched(t, forwardingServer(set), "AAA", "host:forward:tcp:80;tcp:81")

	if !strings.HasPrefix(got, "FAIL") || !strings.Contains(got, "--no-rebind") {
		t.Errorf("reply = %q, want a FAIL carrying the reason", got)
	}
}

// A specification without the semicolon is refused rather than guessed at: which half is local
// and which is remote decides where the port connects, and a guess picks one.
func TestForwardBindWithoutTheSeparatorIsRefused(t *testing.T) {
	set := &fakeForwards{port: 1}
	got := switched(t, forwardingServer(set), "AAA", "host:forward:tcp:9930")

	if !strings.HasPrefix(got, "FAIL") {
		t.Errorf("reply = %q, want a FAIL", got)
	}
	if len(set.binds) != 0 {
		t.Errorf("Bind was called with %v; a malformed request must bind nothing", set.binds)
	}
}

// Anything else under host: is refused, and the refusal names the service with its prefix
// stripped: measured, "host:bogus:thing" came back as FAIL 0022 "unknown host service
// 'bogus:thing'". That is the part the caller wrote, and it is the part worth echoing back.
func TestUnknownHostServiceOnASwitchedTransportNamesItself(t *testing.T) {
	got := switched(t, forwardingServer(&fakeForwards{}), "AAA", "host:bogus:thing")
	const msg = "unknown host service 'bogus:thing'"
	if want := fmt.Sprintf("FAIL%04x%s", len(msg), msg); got != want {
		t.Errorf("reply = %q (% x), want %q", got, got, want)
	}
}

// `adb forward --list` is a plain host request naming no serial, answered without a transport
// switch. The framing is the stock server's: one forward renders as "SERIAL tcp:LOCAL
// tcp:REMOTE\n" behind a four-hex length, which is the 0022 in the capture.
func TestListForwardIsAPlainHostRequestWithAFramedListing(t *testing.T) {
	set := &listForwards{}
	listing := "AAA tcp:9930 tcp:9931\n"
	got := serveOne(t, forwardingServer(set), "host:list-forward")
	if want := fmt.Sprintf("OKAY%04x%s", len(listing), listing); got != want {
		t.Errorf("host:list-forward reply = %q (% x), want %q", got, got, want)
	}
	if len(set.listed) != 1 || set.listed[0] != "" {
		t.Errorf("List called with %v, want one call naming no serial", set.listed)
	}
}

// The serial-qualified form answers with only that device's forwards, which is what makes two
// devices' forwards of one local port tellable apart.
func TestListForwardPerDeviceAsksForThatDeviceOnly(t *testing.T) {
	set := &listForwards{}
	got := serveOne(t, forwardingServer(set), "host-serial:BBB:list-forward")
	if !strings.HasPrefix(got, "OKAY") {
		t.Fatalf("reply = %q, want an OKAY", got)
	}
	if len(set.listed) != 1 || set.listed[0] != "BBB" {
		t.Errorf("List called with %v, want one call for BBB", set.listed)
	}
}

// An unentitled serial is refused before any listing is produced, so the reply cannot report a
// forward belonging to a device this client may not see.
func TestListForwardForAnUnentitledSerialIsRefused(t *testing.T) {
	set := &listForwards{}
	got := serveOne(t, forwardingServer(set), "host-serial:CCC:list-forward")
	if !strings.HasPrefix(got, "FAIL") || !strings.Contains(got, "not found") {
		t.Errorf("reply = %q, want a FAIL naming a device that is not found", got)
	}
	if len(set.listed) != 0 {
		t.Errorf("List was called for a device the client may not see: %v", set.listed)
	}
}

// A server with no forwards answers every forwarding service by name. Silence is the failure
// this avoids: the client asked for a port and would wait rather than report anything.
func TestForwardingIsRefusedByNameWhenTheServerHasNone(t *testing.T) {
	s := forwardingServer(nil)

	for _, service := range []string{
		"host:forward:tcp:9930;tcp:9931",
		"host:killforward:tcp:9930",
		"host:killforward-all",
	} {
		got := switched(t, s, "AAA", service)
		if !strings.HasPrefix(got, "FAIL") || !strings.Contains(got, "forwarding") {
			t.Errorf("%s with no forwards: reply %q, want a FAIL saying so", service, got)
		}
	}
	for _, service := range []string{"host:list-forward", "host-serial:AAA:list-forward"} {
		got := serveOne(t, s, service)
		if !strings.HasPrefix(got, "FAIL") || !strings.Contains(got, "forwarding") {
			t.Errorf("%s with no forwards: reply %q, want a FAIL saying so", service, got)
		}
	}
}

// A forwarding request never reaches the device. The port being forwarded is this server's, so
// a device asked about it has nothing to say, and an OPEN naming a forward would be a question
// sent to a peer that cannot answer it.
func TestForwardingRequestNeverReachesTheDevice(t *testing.T) {
	ad := newPipe()
	dev := newPipe()
	client, server := ad.a, ad.b
	device := dev.b
	defer client.Close()
	defer server.Close()
	defer dev.a.Close()
	defer device.Close()

	set := &fakeForwards{port: 4242}
	s := New(fakeFilter{allowed: map[string]bool{"AAA": true}},
		func(string) (net.Conn, error) { return dev.a, nil }, testOperator, nil, set)
	go func() { _ = s.Serve(server) }()

	if _, err := client.Write(request("host:tport:serial:AAA")); err != nil {
		t.Fatalf("write tport: %v", err)
	}
	head := make([]byte, 12)
	client.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(client, head); err != nil {
		t.Fatalf("read tport reply: %v", err)
	}
	if _, err := client.Write(request("host:forward:tcp:0;tcp:1")); err != nil {
		t.Fatalf("write service: %v", err)
	}
	ack := make([]byte, 4)
	if _, err := io.ReadFull(client, ack); err != nil {
		t.Fatalf("read the switch acknowledgement: %v", err)
	}
	if string(ack) != okayToken {
		t.Fatalf("switch acknowledgement %q, want a bare %q", ack, okayToken)
	}
	buf := make([]byte, 64)
	n, err := client.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("read the bind reply: %v", err)
	}
	if string(buf[:n]) != "OKAY00044242" {
		t.Fatalf("bind reply = %q, want the bound port", buf[:n])
	}

	// Silence on the device end is the assertion, so it is waited for rather than inferred
	// from the reply being right.
	device.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if n, err := device.Read(buf); err == nil {
		t.Errorf("the device received %q for a forwarding request", buf[:n])
	}
}
