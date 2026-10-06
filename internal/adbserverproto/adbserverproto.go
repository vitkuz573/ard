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

// Service replies. adb asks for the protocol version first and compares it against what it
// knows, so the payload is exactly the four characters a real adb server sends.
const (
	versionReply = "0029"
	okayToken    = "OKAY"
	failToken    = "FAIL"
)

// featureReply is the answer to host:features, and the reply that decides whether adb speaks
// the shell v2 protocol at all.
//
// Measured against the stock server on a machine with a device attached:
//
//	host:features            -> OKAY 00f5 "shell_v2,cmd,stat_v2,ls_v2,fixed_push_mkdir,apex,
//	                                        abb,fixed_push_symlink_timestamp,abb_exec,
//	                                        remount_shell,track_app,sendrecv_v2,
//	                                        sendrecv_v2_dry_run_send,openscreen_mdns,
//	                                        devicetracker_proto_format,devraw,app_info,
//	                                        server_status,track_mdns,push_sync"
//	host-serial:X:features   -> the identical 253 bytes
//	no device attached       -> FAIL 0016 "ano devices/emulators found"
//
// Only shell_v2 is claimed here, and the reason is not caution about the protocol: the rest
// of the stock list is derived from the devices the server happens to have attached, and
// naming a feature this gateway cannot honour is how a client commits to a path that cannot
// work. shell_v2 is the one that has to be right, and the cost of leaving it out is measured
// in two broken commands that both look like the device's fault:
//
//   - adb sends "shell:false" instead of "shell,v2,TERM=...,raw:false", so the device runs
//     the v1 protocol, sends no exit status frame, and `adb shell false` reports success.
//   - adb writes its stdin as raw bytes and never writes kIdCloseStdin, so a device waiting
//     for the end of input waits forever and `adb shell cat` hangs.
//
// Both were chased as transport bugs before this reply was measured. The transport was fine
// in both cases; the client had simply been told the server does not speak v2.
const featureReply = "shell_v2"

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

	// relayPrefix is whatever the request reader had already buffered when the connection
	// turned into a device transport. It is consumed by the relay before anything is read
	// from the socket; without it those bytes belong to nobody.
	relayPrefix []byte
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

// Serve answers one request on c and returns.
//
// One request per connection is what a real adb server does: adb opens a fresh connection for
// every host service request, and a second request on the same connection is answered with
// silence and then a close. Measured against the stock server, not assumed.
//
// The buffered reader matters more than it looks. adb sends the tport request and the start
// of the device's CNXN in the same segment, so reading the request through a bufio.Reader
// pulls those following bytes into its buffer. Whoever takes the connection next has to be
// given them explicitly, or the device never sees the CNXN and answers nothing -- which looks
// exactly like a broken tunnel and is invisible in a trace that starts after the relay.
func (s *Server) Serve(c net.Conn) error {
	br := bufio.NewReader(c)
	req, err := readRequest(br)
	if err != nil {
		if err == io.EOF {
			return nil
		}
		return err
	}
	becameTransport, err := s.dispatch(c, req)
	if becameTransport {
		// Hand over whatever the reader already holds, ahead of anything still in the
		// socket, or those bytes are read by nobody.
		if n := br.Buffered(); n > 0 {
			held := make([]byte, n)
			if _, rerr := io.ReadFull(br, held); rerr == nil {
				s.relayPrefix = held
			}
		}
	}
	return err
}

// dispatch answers one request. It reports true when the connection has become a device
// transport and the caller must stop speaking this protocol.
func (s *Server) dispatch(c net.Conn, req string) (bool, error) {
	// Every request is logged, not just the ones that fail. adb opens one connection per
	// request, so "it asked and was refused" and "it never asked" produce identical silence
	// in a log that records only failures -- and the second is the interesting one.
	s.debugf("adbserverproto: request %q", req)

	switch {
	case req == "host:version":
		// The payload is four characters and nothing else: a real adb server answers
		// OKAY 0004 0029, where 0004 is this field's length and 0029 is the protocol
		// version. It does not append a version banner, and guessing that it did is what
		// made adb stop talking to this port -- it read a length that matched the banner
		// rather than the version, concluded nothing sensible, and then tried to start a
		// server of its own on a port already taken.
		return false, s.replyValue(c, versionReply)

	case req == "host:features":
		// The list of features this server supports, and it is the most load-bearing reply
		// in the protocol. Measured, because getting it wrong fails quietly:
		//
		//	stock server: OKAY 00f5 "shell_v2,cmd,stat_v2,...,push_sync"   (245 bytes)
		//	this server:  OKAY 0000 ""                                     (an empty list)
		//
		// With an empty list adb still runs every command, still prints output, and still
		// exits zero. What it stops doing is upgrading the shell service: `adb shell whoami`
		// then sends the service request as the bare "shell:whoami" instead of
		// "shell,v2,TERM=xterm-256color,raw:whoami", its stdin goes over as raw bytes
		// instead of shell v2 frames, and no exit status frame is ever produced or read.
		// Two failures come out of that and neither points here: `adb shell false` reports
		// success because a device only sends the exit status under v2, and `adb shell cat`
		// hangs forever because nothing ever says that input has ended.
		//
		// The client does the upgrading, not this server. That is worth stating because the
		// opposite is easy to assume and was assumed here: the stock server rewrites
		// nothing on the way to the device -- a raw client that sends "shell:false" gets
		// "shell:false" in the OPEN, measured -- it only advertises shell_v2, and the
		// client then does the rewrite itself, pty and all.
		//
		// Only shell_v2 is advertised. The stock list is derived from the devices attached
		// to it, and the rest of it names protocols this gateway does not implement;
		// advertising a feature that cannot be honoured is how a client ends up on a path
		// that cannot work, the same mistake a device banner makes when it claims
		// compression it cannot decompress.
		return false, s.replyValue(c, featureReply)

	case req == "host:devices", req == "host:devices-l":
		return false, s.replyValue(c, s.deviceList())

	case strings.HasPrefix(req, "host-serial:"):
		serial, action := splitSerialAction(req)
		switch {
		case action == "features":
			if !s.allowed(serial) {
				return false, writeFail(c, deviceNotFound(serial))
			}
			// The same list as host:features, which is what the stock server answers:
			// measured, `host-serial:SERIAL:features` on a connected device returns the
			// identical 253 bytes as `host:features`. adb asks this one per device while it
			// builds its transport cache, so answering it with something else means the shell
			// v2 upgrade is decided by whichever of the two adb happens to read first.
			return false, s.replyValue(c, featureReply)

		case action == "get-state":
			// `adb get-state` asks the server what it thinks the device's state is, and does
			// not open a transport to find out. Captured from the stock server:
			//
			//	host-serial:SERIAL:get-state -> OKAY 0006 "device"
			//
			// It is answered from the registry rather than by asking the device, because the
			// registry is already the authority on liveness -- the same source the listing
			// uses, so `adb get-state` and `adb devices` cannot disagree. This was missing and
			// `adb get-state` failed with "unknown service" on every device, which reads as a
			// broken gateway rather than as a missing command.
			if !s.allowed(serial) {
				return false, writeFail(c, deviceNotFound(serial))
			}
			state := "offline"
			if s.filter != nil && s.filter.Connected(serial) {
				state = "device"
			}
			return false, s.replyValue(c, state)

		default:
			return false, writeFail(c, fmt.Sprintf("unknown host service %s", quote(action)))
		}

	case strings.HasPrefix(req, "host:tport:serial:"):
		serial := strings.TrimPrefix(req, "host:tport:serial:")
		return s.beginTransport(c, serial, true)

	case strings.HasPrefix(req, "host:transport:"):
		serial := strings.TrimPrefix(req, "host:transport:")
		if !s.allowed(serial) {
			return false, writeFail(c, deviceNotFound(serial))
		}
		// Answer OKAY and make this connection the transport, which is what a client that
		// asked for this expects to follow.
		//
		// It used to be refused with "use host:tport instead", which is advice, not
		// behaviour, and it broke the client: adb asks for host:transport before it asks
		// for host:tport, so a refusal here meant the tport request never arrived at all.
		// No stream was ever opened and `adb shell` hung with no output and no error.
		return s.beginTransport(c, serial, false)

	case strings.HasPrefix(req, "host:connect:"):
		// Opening a TCP device is the gateway's business, not this package's, and the
		// gateway does not implement it. FAIL with a reason: adb prints the message,
		// whereas a silent reply would hang the command.
		return false, writeFail(c, "adb connect is not supported by this gateway")

	default:
		// The stock server's wording, captured for an undefined request:
		//
		//	host:bogus -> FAIL 001c "unknown host service 'bogus'"
		//
		// Naming the request back is what makes this actionable. The message is the only
		// thing adb prints, so a refusal that does not say which service was refused leaves
		// the reader to guess.
		return false, writeFail(c, "unknown host service "+quote(req))
	}
}

// deviceNotFound is how the stock server refuses a serial, whatever asked for it. Captured:
//
//	host:tport:serial:nope   -> FAIL 0017 "device 'nope' not found"
//	host:transport:nope      -> FAIL 0017 "device 'nope' not found"
//	host-serial:nope:...     -> FAIL 0017 "device 'nope' not found"
//
// One message for all three, and the same for an operator who is not entitled to the device as
// for one that does not exist. That is deliberate: a refusal that distinguished the two would
// tell an operator probing for serials which of them exist. The registry has no reason to
// publish that, and a FAIL is not the place to leak it.
func deviceNotFound(serial string) string {
	return fmt.Sprintf("device '%s' not found", serial)
}

// splitSerialAction splits "host-serial:SERIAL:ACTION" into its two halves.
//
// The serial is everything between the prefix and the last colon, because a serial may contain
// a colon -- an adb serial over TCP is host:port -- and splitting on the first one would
// truncate it.
func splitSerialAction(req string) (serial, action string) {
	rest := strings.TrimPrefix(req, "host-serial:")
	i := strings.LastIndexByte(rest, ':')
	if i < 0 {
		return rest, ""
	}
	return rest[:i], rest[i+1:]
}

// beginTransport answers a tport request. On success the connection is the device's
// transport and the relay runs here, so the caller returns true and stops speaking the
// adb server protocol.
// beginTransport turns the connection into a device transport.
//
// The two ways in are not the same protocol and answering them the same way is what broke
// adb for hours. Both were measured against the stock server, byte for byte:
//
//	host:transport:SERIAL   -> OKAY                                    (4 bytes)
//	host:tport:serial:SERIAL -> OKAY 01 00 00 00 00 00 00 00           (12 bytes)
//
// tport is the smart socket handshake: the eight bytes after OKAY are a 64-bit transport id,
// and the client reads all twelve before it does anything at all. Answering with a bare OKAY
// left it waiting for the id, so it never sent the CNXN, and the connection sat there until
// adb's own timeout -- which looked like a tunnel that opened and delivered nothing.
//
// A transport id of 1 is what the stock server hands out for a switched socket and adb echoes
// whatever it is given, so the number itself does not have to be unique here.
func (s *Server) beginTransport(c net.Conn, serial string, smartSocket bool) (bool, error) {
	if !s.allowed(serial) {
		return false, writeFail(c, deviceNotFound(serial))
	}
	dev, err := s.open(serial)
	if err != nil {
		// Logged rather than only returned. The FAIL carries the reason to the operator, which
		// is the audience that matters, but an operator who cannot see it needs someone who can
		// -- and the gateway's log is where that person looks. Without this line a refusal is
		// visible only to the client that was refused, and disappears with it.
		s.debugf("adbserverproto: refusing a transport to %q: %v", serial, err)
		return false, writeFail(c, err.Error())
	}
	// OKAY has to reach the client before the relay starts, or the two sides interleave
	// CNXN with a reply and the device sees rubbish.
	if err := s.writeTransportOKAY(c, smartSocket); err != nil {
		dev.Close()
		return false, err
	}
	if smartSocket {
		// A switched transport is not a raw relay: the client sends a service request and
		// expects the server to have opened the stream already. See serveHostService.
		err = s.serveHostService(c, dev, s.relayPrefix)
	} else {
		err = s.relay(c, dev, s.relayPrefix)
	}
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

// writeTransportOKAY answers a request that turns the connection into a device transport.
//
// smartSocket selects the tport form, which carries a 64-bit transport id after OKAY. The
// reply is written as one buffer rather than two writes so a client reading twelve bytes never
// sees four of them and waits for the rest.
func (s *Server) writeTransportOKAY(w io.Writer, smartSocket bool) error {
	reply := []byte(okayToken)
	if smartSocket {
		reply = append(reply, 1, 0, 0, 0, 0, 0, 0, 0)
	}
	_, err := w.Write(reply)
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
//
// Captured from the stock server, for three refusals:
//
//	host:tport:serial:nope -> FAIL 0017 "device 'nope' not found"
//	host:transport:nope    -> FAIL 0017 "device 'nope' not found"
//	host:bogus             -> FAIL 001c "unknown host service 'bogus'"
//
// One four-digit length and then the message, with no length inside that. The inner length
// this used to write is not a variant adb tolerates: it decodes the four digits after FAIL as
// the message's length, reads that many bytes, and prints what it got -- which is why a
// refusal reached the operator as
//
//	error: 0052operator "bob" may not attach to "dev-a": role "observer" lacks ...
//
// with the digits of the misplaced length welded to the front of the sentence. A refusal is
// read by a person trying to work out why they were stopped, so it has to be the sentence.
func writeFail(w io.Writer, msg string) error {
	if len(msg) > 0xffff {
		msg = msg[:0xffff]
	}
	buf := make([]byte, 0, 4+len(msg))
	buf = append(buf, failToken...)
	buf = append(buf, []byte(fmt.Sprintf("%04x", len(msg)))...)
	buf = append(buf, msg...)
	_, err := w.Write(buf)
	return err
}

// relay copies in both directions until either side stops.
//
// prefix is written to b before the socket is read, because those bytes were taken from the
// socket already when the request was parsed.
func (s *Server) relay(a, b net.Conn, prefix []byte) error {
	errc := make(chan error, 2)
	go func() {
		if len(prefix) > 0 {
			if _, err := b.Write(prefix); err != nil {
				errc <- err
				return
			}
		}
		_, err := io.Copy(a, b)
		errc <- err
	}()
	go func() {
		_, err := io.Copy(b, a)
		errc <- err
	}()
	// One direction finishing first is the normal case -- the device hangs up and the
	// client's socket is still open -- so the first result decides and the second goroutine
	// is left to end when its own side closes.
	if err := <-errc; err != nil && err != io.EOF {
		return err
	}
	return nil
}
