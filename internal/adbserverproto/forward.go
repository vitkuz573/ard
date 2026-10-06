package adbserverproto

// Forwarding, answered on the connection a client already switched.
//
// `adb forward` is a question for the adb server rather than for a device, and that is the
// whole reason it lives here. The port being forwarded is on the machine running the adb
// binary's own server: a device has no say in it, and one asked to answer would have to
// guess which of its own ports the operator meant. So the client switches transports, sends
// the request on the switched connection, and this answers it.
//
// Measured, from a stock adb server with a device attached:
//
//	adb forward tcp:9930 tcp:9931
//	  client -> server  host:forward:tcp:9930;tcp:9931
//	  server -> client  OKAY 0004 "9930"      <- the bound port, as four decimal digits
//
//	adb forward --no-rebind tcp:9932 tcp:9933
//	  client -> server  host:forward:norebind:tcp:9932;tcp:9933
//
//	adb forward --remove tcp:9930    -> server -> client  OKAY     (bare: no length, no body)
//	adb forward --remove-all         -> server -> client  OKAY
//	adb forward --list               -> server -> client  OKAY 0022 "SERIAL tcp:9930 tcp:9931\n"
//
// Anything else beginning with host: is refused, and the refusal names what it did not
// recognise: measured, a client that sent "host:bogus:thing" on a switched socket got
// FAIL 0022 "unknown host service 'bogus:thing'" -- the service with its "host:" prefix
// stripped, which is the part the caller wrote and the part worth echoing back.

import (
	"fmt"
	"net"
	"strings"
)

// Forward is one bound port and where it leads.
type Forward struct {
	// Serial is the device the port leads to, Local the specification that was bound and
	// Remote the one the device is asked for.
	Serial string
	Local  string
	Remote string
}

// Forwards is the collaborator that owns this server's port forwards.
//
// It is separate from Filter and Opener because it is about ports rather than about
// devices, and because a forward outlives the connection that asked for it: adb closes that
// connection as soon as the request is answered, so anything that lived on the connection
// would be gone while the port was still bound.
type Forwards interface {
	// Bind listens on local and answers with the port it bound. The port matters because
	// the client may have asked for tcp:0, and only the answer tells it which port it got.
	//
	// norebind is the client's own word for "a port already held by another forward may be
	// taken from it". It arrives here rather than being left in the specification because
	// which of those two outcomes to choose is the set's decision: only it knows what the
	// port currently leads to.
	Bind(operator, serial, local, remote string, norebind bool) (int, error)
	// Kill removes the forward of that local specification. A specification that is not
	// there is not an error: removing something that is absent reaches the wanted state.
	Kill(serial, local string)
	// List renders the forwards as the stock server renders them, one
	// "serial local remote\n" line each.
	List(serial string) string
}

// DeviceDialer reaches a socket this server can see on its own machine, for a device that
// opened a stream asking for one.
//
// It is separate from Forwards because it is asked per connection rather than per request: a
// device asks for a port every time something reaches a port it is holding, so the answer has
// to be a fresh connection each time.
type DeviceDialer interface {
	// Dial connects to the port the service names on this server's own machine.
	Dial(service string) (net.Conn, error)
}

// SetTransportAdopter arranges for a device transport to outlive the request that opened it.
//
// It is asked after the client's own stream has finished, with the service it was for, and
// reports whether it took the connection. A connection nobody took is closed, which is the
// ordinary case: only a device that binds a port on itself keeps needing the transport it was
// asked on, because a reverse forward's listener is held there and not on a connection of its
// own. Measured by having a device reverse forward bind a port, close the request, and then
// connect to the port it had bound: with the transport gone, the device's connection to the
// other end was already closed and the callback could not be made at all.
func (s *Server) SetTransportAdopter(ask func(serial, service string, conn net.Conn) bool) {
	s.adopter = ask
}

// SetDeviceDialer says where to connect when a device opens a stream for itself.
//
// It is separate from New because it is optional and it is the gateway's business rather than
// this protocol's: a server with no dialer answers a device's OPEN with a close, which the
// device reads as the connection being refused. That is the honest answer for a server that
// has no port to offer, and it is much better than silence, which leaves the device waiting on
// a connection this server was never going to make.
func (s *Server) SetDeviceDialer(d DeviceDialer) { s.dialer = d }

// serveHostForward answers a service that names this server rather than a device.
//
// It runs after the switched-transport acknowledgement, which the client reads as the answer
// to having switched; everything from here is the answer to the service itself.
func (s *Server) serveHostForward(c net.Conn, service string) error {
	if s.forwards == nil {
		// Refusing in words is the point. The client asked for a port, and silence here is
		// a hang rather than a refusal; the message names what would be needed.
		return writeFail(c, "port forwarding is not available on this server")
	}
	switch {
	case strings.HasPrefix(service, "forward:"):
		return s.serveForwardBind(c, s.forwards, strings.TrimPrefix(service, "forward:"))
	case strings.HasPrefix(service, "killforward-all"):
		// The serial is not in the request: `--remove-all` is per device, and the client
		// has switched onto one by the time it sends this.
		s.forwards.Kill(s.forwardSerial, "")
		return writeOKAY(c)
	case strings.HasPrefix(service, "killforward:"):
		s.forwards.Kill(s.forwardSerial, strings.TrimPrefix(service, "killforward:"))
		return writeOKAY(c)
	default:
		return writeFail(c, "unknown host service '"+service+"'")
	}
}

// serveForwardBind answers "forward:[norebind:]<local>;<remote>", the service with the
// "host:" prefix already stripped.
//
// The flag comes off the front rather than out of the middle, because everything after it is
// the specification and a flag left inside that would be a local specification naming a port
// nobody can bind.
func (s *Server) serveForwardBind(c net.Conn, set Forwards, spec string) error {
	norebind := false
	if rest, ok := strings.CutPrefix(spec, "norebind:"); ok {
		norebind, spec = true, rest
	}
	local, remote, ok := strings.Cut(spec, ";")
	if !ok {
		return writeFail(c, "malformed forward '"+spec+"': want LOCAL;REMOTE")
	}
	port, err := set.Bind(s.operator, s.forwardSerial, local, remote, norebind)
	if err != nil {
		return writeFail(c, err.Error())
	}
	// The bound port, as decimal characters behind a length. Measured against the
	// alternative: a client asked for tcp:0 prints the port it read here, and it prints
	// nothing when the same four bytes are a little-endian integer instead.
	digits := fmt.Sprintf("%d", port)
	_, err = c.Write([]byte(fmt.Sprintf("%s%04x%s", okayToken, len(digits), digits)))
	return err
}
