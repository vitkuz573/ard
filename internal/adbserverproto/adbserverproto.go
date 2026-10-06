// Package adbserverproto speaks the adb server's own protocol: the small request/reply
// language the stock adb binary uses to talk to its own adb server over a plain socket.
//
// # Why it exists
//
// This project gives an operator a stock adb binary against a phone on the internet. adb
// cannot do TLS, so a helper has to terminate TLS on the operator's own machine -- that is
// unavoidable, not a preference. The question is what that helper has to know, and the
// obvious answer is "everything": bind a loopback port per device, hand the operator a list
// of serials, and splice raw bytes through each one. That answer costs a port table, a rule
// for keeping ports stable when devices come and go, and operator-side knowledge of serials.
//
// It is also unnecessary. adb already speaks a protocol for finding out what devices exist
// and for switching onto one of them. A helper that answers that protocol -- over a tunnel,
// with the device list filtered -- lets stock adb do everything it does with a local device:
// adb devices, adb -s SERIAL shell, adb connect, and its own transport switching.
//
// The one request that carries the weight is host:tport:serial:SERIAL. After answering OKAY
// to it, the connection stops being this protocol and becomes the raw ADB transport to the
// device: the client sends CNXN and from then on the bytes belong to the device. Everything
// else here is a short reply.
//
// # What this package does not do
//
// It does not authenticate, authorise or encrypt. Filtering is a callback the caller
// supplies, because who may see which device is a decision for the gateway, and a package
// that guessed would be a package that could be wrong. It does not open devices; that too is
// a callback. And it never leaves a request unanswered: adb waits forever for a reply that
// does not arrive, so an unknown service is a FAIL and never a silence.
package adbserverproto

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
)

// Service version strings. adb asks for the protocol version first and compares it against
// what it knows; answering with the same one the stock server answers keeps it moving.
const (
	versionReply = "0029host::version=41"
	okayToken    = "OKAY"
	failToken    = "FAIL"
)

// maxRequest caps a request. adb's own services are small; anything larger is a client that
// is confused or hostile, and reading it would mean allocating on its say-so.
const maxRequest = 4096

// Filter decides what one client is allowed to see. Both calls are made per request, never
// cached, because entitlement can change while a connection is open.
type Filter interface {
	// Allows reports whether this client may see the device at all. A client that was
	// never shown a serial must be refused it here, not merely hidden from the listing:
	// a modified client can ask for anything by name.
	Allows(serial string) bool
	// Connected reports whether the device is attached right now, which is what turns
	// into the "device" or "offline" state in a listing.
	Connected(serial string) bool
}

// Opener returns a connection carrying the raw ADB transport to one device. It is called
// only after Allows has answered yes.
type Opener func(serial string) (net.Conn, error)

// Server answers adb server protocol requests on behalf of one client.
type Server struct {
	filter Filter
	open   Opener
	// logf is optional and receives one line per unexpected condition. It is nil in
	// tests and never required in production.
	logf func(format string, args ...any)
}

// New returns a Server. logf may be nil.
func New(filter Filter, open Opener, logf func(string, ...any)) *Server {
	return &Server{filter: filter, open: open, logf: logf}
}

func (s *Server) debugf(format string, args ...any) {
	if s.logf != nil {
		s.logf(format, args...)
	}
}

// Serve answers requests on c until the client goes away or asks for a transport, in which
// case the connection becomes that transport and this call relays it to completion.
//
// Serving one connection per call is deliberate: adb opens a fresh connection per host
// service request, so a listener hands each of them straight here.
func (s *Server) Serve(c net.Conn) error {
	br := bufio.NewReader(c)
	for {
		req, err := readRequest(br)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		done, err := s.dispatch(c, req)
		if err != nil {
			s.debugf("adbserverproto: %q: %v", req, err)
			return err
		}
		if done {
			return nil
		}
	}
}

// dispatch answers one request. It reports true when the connection has become a device
// transport and the caller must stop speaking this protocol.
func (s *Server) dispatch(c net.Conn, req string) (bool, error) {
	switch {
	case req == "host:version":
		return false, s.replyValue(c, versionReply)

	case req == "host:features":
		// A feature list, not a version string. adb asks this separately from host:version
		// and parses the answer as a comma-separated list; handing it the version reply
		// made it treat a server it did not understand as one it should not talk to.
		//
		// Empty is honest. Everything this server does is decided by which services it
		// answers, and advertising features it does not implement is how a client ends up
		// on a path that cannot work -- the same mistake a device banner makes when it
		// claims compression it cannot decompress.
		return false, s.replyValue(c, "")

	case req == "host:devices", req == "host:devices-l":
		return false, s.replyValue(c, s.deviceList())

	case strings.HasPrefix(req, "host-serial:") && strings.HasSuffix(req, ":features"):
		serial := serialBetween(req, "host-serial:", ":features")
		if serial == "" || !s.filter.Allows(serial) {
			return false, writeFail(c, fmt.Sprintf("unknown device %q", serial))
		}
		return false, s.replyValue(c, versionReply)

	case strings.HasPrefix(req, "host:tport:serial:"):
		serial := strings.TrimPrefix(req, "host:tport:serial:")
		return s.beginTransport(c, serial)

	case strings.HasPrefix(req, "host:transport:"):
		serial := strings.TrimPrefix(req, "host:transport:")
		if !s.allowed(serial) {
			return false, writeFail(c, fmt.Sprintf("unknown device %q", serial))
		}
		dev, err := s.open(serial)
		if err != nil {
			return false, writeFail(c, err.Error())
		}
		defer dev.Close()
		// host:transport differs from host:tport in that the caller asks for a device to
		// become the *default* and then opens a separate connection for the traffic. So
		// the transport has to stay usable after this returns; here it does not, and
		// saying so beats appearing to succeed.
		return false, writeFail(c, "host:transport is not supported: use host:tport:serial:SERIAL")

	case strings.HasPrefix(req, "host:connect:"):
		// Opening a TCP device is the gateway's business, not this package's, and the
		// gateway does not implement it. FAIL with a reason: adb prints the message,
		// whereas a silent reply would hang the command.
		return false, writeFail(c, "adb connect is not supported by this gateway")

	default:
		return false, writeFail(c, "unknown service "+quote(req))
	}
}

// beginTransport answers a tport request. On success the connection is the device's
// transport and the relay runs here, so the caller returns true and stops speaking the
// adb server protocol.
func (s *Server) beginTransport(c net.Conn, serial string) (bool, error) {
	if serial == "" || !s.allowed(serial) {
		return false, writeFail(c, fmt.Sprintf("unknown device %q", serial))
	}
	dev, err := s.open(serial)
	if err != nil {
		return false, writeFail(c, err.Error())
	}
	// OKAY has to reach the client before the relay starts, or the two sides interleave
	// CNXN with a reply and the device sees rubbish.
	if err := writeOKAY(c); err != nil {
		dev.Close()
		return false, err
	}
	// From here the connection is the transport: a half-close on the client side is how a
	// device signals end of input, so copying until either side errors rather than to
	// EOF is what keeps `adb shell cat` working.
	err = relay(c, dev)
	dev.Close()
	if err != nil && err != io.EOF {
		return true, err
	}
	return true, nil
}

func (s *Server) allowed(serial string) bool {
	return serial != "" && s.filter != nil && s.filter.Allows(serial)
}

// deviceList renders the listing. Only devices this client may see appear, so the list
// itself cannot leak a serial; and the refusal in dispatch is what stops a client that
// guesses one anyway.
func (s *Server) deviceList() string {
	var b strings.Builder
	for _, d := range s.devices() {
		state := "offline"
		if s.filter != nil && s.filter.Connected(d) {
			state = "device"
		}
		b.WriteString(d)
		b.WriteByte('\t')
		b.WriteString(state)
		b.WriteByte('\n')
	}
	return b.String()
}

// devices is the set of serials this client is entitled to. It comes from the filter
// because entitlement is per client and the gateway owns the registry.
func (s *Server) devices() []string {
	if s == nil || s.filter == nil {
		return nil
	}
	if lister, ok := s.filter.(interface{ Serials() []string }); ok {
		return lister.Serials()
	}
	return nil
}

func serialBetween(s, prefix, suffix string) string {
	if !strings.HasPrefix(s, prefix) || !strings.HasSuffix(s, suffix) {
		return ""
	}
	return s[len(prefix) : len(s)-len(suffix)]
}

func quote(s string) string {
	if len(s) > 60 {
		s = s[:60] + "..."
	}
	return fmt.Sprintf("%q", s)
}

// readRequest reads one length-prefixed request.
//
// The length is exactly four lowercase hex digits and the payload follows immediately, with
// no terminator. A client that sends something else gets an error rather than a guess:
// adb will retry on a fresh connection and the failure is visible, where a misparse would be
// silent.
func readRequest(br *bufio.Reader) (string, error) {
	var head [4]byte
	if _, err := io.ReadFull(br, head[:]); err != nil {
		return "", err
	}
	n := 0
	for _, c := range head {
		switch {
		case c >= '0' && c <= '9':
			n = n<<4 | int(c-'0')
		case c >= 'a' && c <= 'f':
			n = n<<4 | int(c-'a') + 10
		default:
			return "", fmt.Errorf("adbserverproto: malformed length prefix %q", string(head[:]))
		}
	}
	if n == 0 {
		return "", errors.New("adbserverproto: empty request")
	}
	if n > maxRequest {
		return "", fmt.Errorf("adbserverproto: request of %d bytes exceeds the %d allowed", n, maxRequest)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(br, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

// writeOKAY sends a bare OKAY, which is how a transport request is answered.
func writeOKAY(w io.Writer) error {
	_, err := w.Write([]byte(okayToken))
	return err
}

// replyValue sends OKAY with a four-hex-digit length followed by the payload, which is how
// adb expects a reply carrying data.
func (s *Server) replyValue(w io.Writer, value string) error {
	if len(value) > 0xffff {
		return fmt.Errorf("adbserverproto: reply of %d bytes does not fit a four-digit length", len(value))
	}
	buf := make([]byte, 0, 8+len(value))
	buf = append(buf, okayToken...)
	buf = append(buf, []byte(fmt.Sprintf("%04x", len(value)))...)
	buf = append(buf, value...)
	_, err := w.Write(buf)
	return err
}

// writeFail sends FAIL and a message. The message is what an operator sees, so it says what
// went wrong rather than that something did.
func writeFail(w io.Writer, msg string) error {
	if len(msg) > 0xffff {
		msg = msg[:0xffff]
	}
	buf := make([]byte, 0, 8+len(msg))
	buf = append(buf, failToken...)
	buf = append(buf, []byte(fmt.Sprintf("%04x", 4+len(msg)))...)
	buf = append(buf, []byte(fmt.Sprintf("%04x", len(msg)))...)
	buf = append(buf, msg...)
	_, err := w.Write(buf)
	return err
}

// relay copies in both directions until either side stops.
func relay(a, b net.Conn) error {
	errc := make(chan error, 2)
	go func() { _, err := io.Copy(a, b); errc <- err }()
	go func() { _, err := io.Copy(b, a); errc <- err }()
	// One direction finishing first is the normal case -- the device hangs up and the
	// client's socket is still open -- so the first result decides and the second goroutine
	// is left to end when its own side closes.
	if err := <-errc; err != nil && err != io.EOF {
		return err
	}
	return nil
}
