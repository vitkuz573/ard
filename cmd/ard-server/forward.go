package main

// Port forwarding, as this gateway answers it.
//
// adb's forwarding is not one mechanism but two, and which of them an operator's `adb
// forward` reaches depends on where the adb binary is: the client asks its own server, and
// here that server is this gateway. Measured against a stock adb server with a device
// attached, byte for byte:
//
//	adb forward tcp:9930 tcp:9931
//	  client -> server  host:tport:serial:SERIAL
//	  server -> client  OKAY + an 8-byte transport id, then OKAY
//	  client -> server  001ahost:forward:tcp:9930;tcp:9931
//	  server -> client  OKAY 0004 "9930"          <- the port it bound, as four digits
//
//	adb forward --no-rebind tcp:9932 tcp:9933
//	  client -> server  host:forward:norebind:tcp:9932;tcp:9933
//	adb forward --remove tcp:9930
//	  client -> server  host:killforward:tcp:9930
//	  server -> client  OKAY                       <- bare: no length, no body
//	adb forward --remove-all
//	  client -> server  host:killforward-all
//	  server -> client  OKAY
//	adb forward --list
//	  client -> server  host:list-forward
//	  server -> client  OKAY 0022 "SERIAL tcp:9930 tcp:9931\n"
//
// The port the host binds and the socket the device connects to are the two halves of one
// tunnel: the host listens, and for each connection to it opens a stream to the device
// asking for "tcp:<remote>". The device connects to that port on its own loopback and
// splices the stream onto the socket -- measured, that service arrives as an OPEN carrying
// "tcp:9911\0" and nothing else.
//
// `adb reverse` is the mirror and needs no listener here: the device binds the remote port
// itself and, when something connects to it, opens a stream back asking for "tcp:<local>".
// This gateway answers that by connecting to a port on its own machine, which is what the
// stock adb server does with a stream a device opens for it -- measured: a device that opens
// "tcp:9911" gets a connection to 9911 on the adb server's own machine, and the bytes on that
// connection travel on the stream.
//
// So the "host" in a forward or a reverse is this gateway, and both halves live here. That
// is worth being explicit about, because it decides who can use the result: a forwarded port
// is bound on the gateway's address, so reaching it means reaching the gateway, which is the
// same reachability question every other operator path through it already asks.

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vitkuz573/ard/internal/adbserverproto"
	"github.com/vitkuz573/ard/internal/audit"
	"github.com/vitkuz573/ard/internal/hs"
)

// forward is one bound port and the device socket it leads to.
type forward struct {
	// serial is the device this port leads to and operator is who asked for it. Both are
	// recorded at binding time and never re-derived: the connection that asked for the
	// forward is closed by adb immediately afterwards, so an operator's name that had to be
	// read from that connection would be gone by the time anyone wanted to say who owns
	// this port.
	serial   string
	operator string
	local    string
	remote   string

	// gw is set before the listener is reachable, so an accept goroutine does not have to
	// take the set's lock to find the gateway it belongs to.
	gw *gateway
	ln net.Listener
}

// forwards owns every forward this gateway is holding.
//
// It lives on the gateway rather than on a connection because a forward outlives the request
// that created it. It also outlives the authorization decision behind it, which is why the
// decision is made once here and the resulting listener belongs to the gateway rather than
// to the operator's machine: a connection arriving on a bound port carries no certificate
// and no name, so there is nothing to check when it arrives.
type forwards struct {
	gw *gateway

	mu    sync.Mutex
	byKey map[string]*forward
}

// newForwards returns an empty set.
func newForwards(gw *gateway) *forwards {
	return &forwards{gw: gw, byKey: map[string]*forward{}}
}

// bind is what `host:forward:` asks for: listen on local, and for each connection to it open
// a stream to the device asking for remote.
//
// The reply is the port that was bound, as decimal characters behind a four-hex-digit length
// and an OKAY. Measured by offering the alternatives: those are the characters a client
// prints after asking for tcp:0, and a 4-byte integer in the same place decodes to nothing
// and the client prints an empty port.
func (f *forwards) Bind(operator, serial, local, remote string, norebind bool) (int, error) {
	if !f.gw.authz.CanSee(operator, serial) {
		return 0, fmt.Errorf("operator %q may not forward for device %q", operator, serial)
	}
	if _, ok := f.gw.reg.Get(serial); !ok {
		return 0, fmt.Errorf("device %q is not connected", serial)
	}
	addr, err := loopbackSpec(local)
	if err != nil {
		return 0, err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return 0, err
	}

	key := forwardKey(local)

	f.mu.Lock()
	old, dup := f.byKey[key]
	if dup && !norebind {
		f.mu.Unlock()
		_ = ln.Close()
		return 0, fmt.Errorf("%s is already forwarded; --no-rebind replaces it", local)
	}
	fwd := &forward{
		serial: serial, operator: operator, local: local, remote: remote,
		ln: ln, gw: f.gw,
	}
	f.byKey[key] = fwd
	f.mu.Unlock()

	// norebind means exactly this: the caller has said that losing the old forward is
	// preferable to failing, and keeping the old one would leave the caller with a port
	// that leads somewhere it did not ask for.
	if dup {
		_ = old.ln.Close()
	}

	bound := ln.Addr().(*net.TCPAddr).Port
	f.gw.logger.Printf("forward %s %s -> %s on %s (%s)", serial, local, remote, ln.Addr(), operator)
	f.gw.audit.Record(audit.Event{
		Kind: "forward.bind", Actor: operator, Device: serial,
		Detail: fmt.Sprintf("%s -> %s", local, remote),
	})
	go fwd.serve()
	return bound, nil
}

// forwardKey identifies a bound port by its numeric value, so tcp:80 and tcp:080 name one
// port rather than two.
func forwardKey(local string) string {
	_, port, ok := strings.Cut(local, ":")
	if !ok {
		return local
	}
	if n, err := strconv.Atoi(port); err == nil {
		return strconv.Itoa(n)
	}
	return port
}

// serve accepts connections on the bound port and tunnels each to the device.
func (f *forward) serve() {
	for {
		conn, err := f.ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			f.gw.tunnelForward(f, conn)
		}()
	}
}

// kill removes a forward by its local specification.
//
// A specification that is not there is not an error: `--remove` on a port nothing holds is a
// state the caller wanted and already has, and reporting a failure for it teaches an operator
// that the command means something it does not.
func (f *forwards) Kill(serial, local string) {
	key := forwardKey(local)
	f.mu.Lock()
	fwd, ok := f.byKey[key]
	if ok && (serial == "" || fwd.serial == serial) {
		delete(f.byKey, key)
	}
	f.mu.Unlock()
	if ok {
		_ = fwd.ln.Close()
		f.gw.logger.Printf("forward %s removed", local)
	}
}

// list renders the forwards as the stock server renders them: one line per forward, as
// "serial local remote\n".
//
// The serial is there because it is what makes two forwards of one local port for different
// devices tellable apart, which is why the format has three fields.
func (f *forwards) List(serial string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	lines := make([]string, 0, len(f.byKey))
	for _, fwd := range f.byKey {
		if serial == "" || fwd.serial == serial {
			lines = append(lines, fmt.Sprintf("%s %s %s\n", fwd.serial, fwd.local, fwd.remote))
		}
	}
	sort.Strings(lines)
	return strings.Join(lines, "")
}

// tunnelForward carries one accepted connection to the device.
//
// The device side is the "tcp:<remote>" service, so the bytes are never interpreted, which is
// what makes a forward usable for a protocol the gateway does not speak. Getting to that
// service is not a copy: a device accepts a named service on a transport and answers in WRTE
// envelopes, so the exchange is performed here and the envelopes come off before the splice.
func (g *gateway) tunnelForward(fwd *forward, conn net.Conn) {
	// The remote specification is already the service name a device answers to: the port the
	// device is asked to connect to on its own loopback. loopbackSpec has refused anything
	// that is not tcp:PORT by the time this runs.
	service := fwd.remote
	stream, err := g.reg.Open(fwd.serial, newStreamID(), hs.KindADB)
	if err != nil {
		g.logger.Printf("forward %s -> %s: %v", fwd.local, fwd.remote, err)
		return
	}
	svc, err := adbserverproto.OpenService(&streamConn{stream}, service)
	if err != nil {
		g.logger.Printf("forward %s -> %s: %v", fwd.local, service, err)
		_ = stream.Close()
		return
	}
	defer svc.Close()
	relay(svc, conn)
}

// handleDeviceOpen serves a stream the device opened for itself.
//
// A device opens one when it needs a connection to a port on this gateway: a reverse forward
// binds a port on the device, and whatever connects to that port has to land on a port here.
// The service names that port and answering it is a local dial and a splice.
func (g *gateway) handleDeviceOpen(device string, meta json.RawMessage, stream net.Conn) error {
	var ask hs.DeviceOpen
	if err := json.Unmarshal(meta, &ask); err != nil || ask.Service == "" {
		_ = stream.Close()
		return fmt.Errorf("device %s opened a stream without naming a service", device)
	}
	addr, err := loopbackSpec(ask.Service)
	if err != nil {
		_ = stream.Close()
		return fmt.Errorf("device %s asked for %q: %w", device, ask.Service, err)
	}
	conn, err := net.DialTimeout("tcp", addr, deviceOpenDialTimeout)
	if err != nil {
		_ = stream.Close()
		g.logger.Printf("device %s asked for %s: %v", device, ask.Service, err)
		g.audit.Record(audit.Event{
			Kind: "forward.device_open_refused", Actor: device, Device: device,
			Detail: fmt.Sprintf("%s: %v", ask.Service, err),
		})
		return fmt.Errorf("device %s asked for %s: %w", device, ask.Service, err)
	}
	g.logger.Printf("device %s opened %s; connected to %s", device, ask.Service, conn.RemoteAddr())
	g.audit.Record(audit.Event{
		Kind: "forward.device_open", Actor: device, Device: device,
		Detail: ask.Service,
	})
	relay(&streamConn{stream}, conn)
	return nil
}

// deviceOpenDialTimeout bounds a dial to a port on this gateway in answer to a device's ask.
// The device is waiting on the answer, so it has to arrive one way or the other.
const deviceOpenDialTimeout = 10 * time.Second

// streamConn adapts a registry stream to net.Conn, which is what relay takes.
//
// The deadline methods report that they do nothing rather than succeeding: there is no
// socket here to set a deadline on, and reporting success would tell a caller it had bounded
// a wait it had not.
type streamConn struct {
	io.ReadWriteCloser
}

func (s streamConn) LocalAddr() net.Addr              { return streamAddr{} }
func (s streamConn) RemoteAddr() net.Addr             { return streamAddr{} }
func (s streamConn) SetDeadline(time.Time) error      { return errNoDeadline }
func (s streamConn) SetReadDeadline(time.Time) error  { return errNoDeadline }
func (s streamConn) SetWriteDeadline(time.Time) error { return errNoDeadline }

// relay copies in both directions until either side stops.
func relay(a net.Conn, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(b, a)
		halfClose(b)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(a, b)
		halfClose(a)
		done <- struct{}{}
	}()
	<-done
}

// halfClose ends one direction where the transport supports it, so the peer sees the end of
// this side's input rather than losing both directions at once.
func halfClose(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = c.Close()
}

// Dial connects to a port on this gateway's own loopback, for a device that opened a stream
// asking for one.
//
// The constraint is the same as on the forward's other half and for the same reason: the
// requesting side chose the name, so resolving it or honouring an address here would let a
// device pick which host on the network a reverse forward reaches. Only tcp: with a numeric
// port is answered, and always 127.0.0.1.
func (f *forwards) Dial(service string) (net.Conn, error) {
	addr, err := loopbackSpec(service)
	if err != nil {
		return nil, err
	}
	return net.DialTimeout("tcp", addr, deviceOpenDialTimeout)
}

// loopbackSpec turns a socket specification into an address on this gateway's own loopback.
//
// Only tcp: and only a numeric port. The same reasoning as on the device: a name in a service
// request is a name the requesting side chose, and resolving it here would let that side
// pick where a forwarded port connects.
func loopbackSpec(spec string) (string, error) {
	kind, port, ok := strings.Cut(spec, ":")
	if !ok || kind != "tcp" {
		return "", fmt.Errorf("unsupported socket specification %q: only tcp:PORT is forwarded", spec)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 0 || n > 65535 {
		return "", fmt.Errorf("malformed port in %q", spec)
	}
	return "127.0.0.1:" + port, nil
}
