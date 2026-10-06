package mockadbd

// Port forwarding, both directions, as a device implements it.
//
// # The two directions are not the same exchange
//
// `adb forward tcp:LOCAL tcp:REMOTE` is answered by the host, not the device: the host
// binds LOCAL and, for each connection to it, opens a stream to the device asking for
// `tcp:REMOTE`. The device's whole part is that last service -- connect to a port on my
// own loopback and splice the stream onto it. Measured, on a stock adb server:
//
//	client -> host  host:forward:tcp:9910;tcp:9911
//	host   -> client OKAY 0004 "9910"      (the port the host bound, as four digits)
//	host   -> device OPEN arg0=11 arg1=0  "tcp:9911\0"
//	device -> host   OKAY arg0=1 arg1=11
//	... the client's bytes travel as WRTE on that stream, and the device answers with its
//	    socket's bytes on the same stream.
//
// `adb reverse tcp:REMOTE tcp:LOCAL` is answered by the device: the device binds REMOTE
// on its own loopback and, for each connection to it, opens a stream to the host asking
// for `tcp:LOCAL`. Measured, against a stock client:
//
//	client -> device OPEN arg0=14 arg1=0  "reverse:forward:tcp:9911;tcp:9910\0"
//	device -> client WRTE  "OKAY00049911"  (the port the device bound, as four digits)
//	... and then, when something connects to the device's port, the device opens
//	    "tcp:9910" back to the host and splices.
//
// So the asymmetry is real and it decides the code: the device implements one listener
// (tcp:) and one reverse listener (reverse:forward:), and which of them an operator's
// `forward` ends up exercising depends on which end of the tunnel the adb binary is on.
//
// # The reply
//
// Both listeners reply with a command word, a four-hex-digit length, and the bound port as
// four ASCII digits -- not as a 4-byte integer, which is the assumption that looks right.
// Measured, by offering both and watching what the client prints:
//
//	WRTE "OKAY00049911"  ->  adb reverse prints "9911" and exits 0
//	WRTE "OKAY0004" 26 b7 ->  adb reverse prints nothing and exits 0
//	WRTE "9911" (no OKAY) ->  adb: protocol fault (status 00 00 26 ffffffb7?!)
//
// The third case is the interesting one: the client reads four bytes as a status before it
// reads the length, so a reply without the word is not a reply with a different body. It
// is read as a status that is neither OKAY nor FAIL, and the bytes it reports are the
// port it was sent, reinterpreted -- which is the only reason the numbers in that message
// look like nonsense.

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Bounds on the device's side of a forward.
//
// Both are short because the peer is on the other end of a network the device does not
// control, and a forward that waits indefinitely is a forward that holds a socket and a
// goroutine for as long as the far end stays silent.
const (
	forwardDialTimeout = 10 * time.Second
	forwardOpenTimeout = 10 * time.Second
)

// forwardService implements the "tcp:<port>" service.
//
// It is the device half of a forward: connect to a port on this device's own loopback
// and let the stream and the socket be each other's input. A real adbd binds no address
// for it and connects to 127.0.0.1, because the point of the service is to reach something
// listening inside the device rather than something reachable from outside it.
//
// The argument is the port alone: the service spec splits on its first colon, so
// "tcp:9911" arrives here as the service "tcp" and the argument "9911".
func forwardService(cfg Config, s *stream, arg string) {
	port, err := checkPort(arg)
	if err != nil {
		failStream(s, "%v", err)
		return
	}
	addr := "127.0.0.1:" + port
	dialer := &net.Dialer{Timeout: forwardDialTimeout}
	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		failStream(s, "cannot connect to %s: %v", addr, err)
		return
	}
	defer conn.Close()
	spliceStreams(s, conn)
}

// reverseForward is the device's half of a reverse forward: a listener on the device, and
// for each connection to it a stream back to the host.
type reverseForward struct {
	mu       sync.Mutex
	listener net.Listener
	local    string
	remote   string
	// host is the connection every connection to the listener gets spliced onto a new
	// stream of. It is fixed for the forward's lifetime: a reverse forward belongs to
	// the transport it was created on, and a device stream does not outlive its
	// connection.
	host *conn
	// done closes when the listener is closed, so the accept goroutine can exit.
	done chan struct{}
}

// forwards are the reverse forwards this device is currently serving, keyed by the local
// spec so `reverse:killforward:` can find one.
var (
	forwardsMu sync.Mutex
	forwards   = map[string]*reverseForward{}
)

// reverseForwardService answers "reverse:forward:<local>;<remote>".
//
// The reply carries the port that was actually bound, so a client that asked for port 0
// learns which port it got. That is the whole reason the reply carries anything: the
// request's own local spec is an input, and for tcp:0 it is not an answer.
func reverseForwardService(cfg Config, s *stream, arg string) {
	local, remote, ok := strings.Cut(arg, ";")
	if !ok {
		failStream(s, "malformed reverse forward %q: want LOCAL;REMOTE", arg)
		return
	}
	addr, err := loopbackAddr(local)
	if err != nil {
		failStream(s, "%v", err)
		return
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		failStream(s, "cannot listen on %s: %v", local, err)
		return
	}
	fwd := &reverseForward{
		listener: ln,
		local:    local,
		remote:   remote,
		host:     s.conn,
		done:     make(chan struct{}),
	}

	forwardsMu.Lock()
	if _, dup := forwards[local]; dup {
		forwardsMu.Unlock()
		_ = ln.Close()
		failStream(s, "%s is already forwarded", local)
		return
	}
	forwards[local] = fwd
	forwardsMu.Unlock()

	bound := ln.Addr().(*net.TCPAddr).Port
	tracef("reverse:forward %s -> %s bound %d", local, remote, bound)
	cfg.debug("reverse:forward %s -> %s bound %d", local, remote, bound)
	go fwd.serve()

	// The reply goes out before the listener starts being answered, and the stream
	// closes after it. A client that asked for tcp:0 has to be able to read the port
	// and then close, and a reply on a stream that stays open leaves `adb reverse`
	// waiting rather than returning.
	if err := s.writeRaw(replyOKAYPort(bound)); err != nil {
		return
	}
	s.close(nil)
}

// serve accepts connections on the listener until it is closed.
func (f *reverseForward) serve() {
	for {
		conn, err := f.listener.Accept()
		if err != nil {
			return
		}
		go f.handle(conn)
	}
}

// handle opens a stream back to the host for one accepted connection and splices them.
func (f *reverseForward) handle(conn net.Conn) {
	defer conn.Close()
	s, err := f.host.openService(f.remote)
	if err != nil {
		tracef("reverse:forward cannot open %s: %v", f.remote, err)
		return
	}
	defer s.close(nil)
	spliceStreams(s, conn)
}

// replyOKAYPort renders the reply a listener makes: OKAY, the length of the port in
// decimal characters, and those characters.
//
// Four digits is a format rather than a fact about ports: a device that binds an ephemeral
// port above 9999 would need five, and the measured shape is a length-prefixed string, so
// the count follows the number.
func replyOKAYPort(port int) []byte {
	digits := strconv.Itoa(port)
	return []byte(fmt.Sprintf("OKAY%04x%s", len(digits), digits))
}

// reverseKillForwardService answers "reverse:killforward:<local>".
func reverseKillForwardService(cfg Config, s *stream, arg string) {
	forwardsMu.Lock()
	fwd, ok := forwards[arg]
	if ok {
		delete(forwards, arg)
	}
	forwardsMu.Unlock()

	if ok {
		close(fwd.done)
		_ = fwd.listener.Close()
		cfg.debug("reverse:killforward %s", arg)
	} else {
		cfg.debug("reverse:killforward %s: nothing there", arg)
	}
	// The measured reply is a bare OKAY, with no length and no body. Measured by
	// asking a stock server's equivalent and reading what came back:
	//
	//	host:killforward:tcp:9930  ->  OKAY
	//
	// and a client that reads a length where there is none reports a protocol fault.
	_ = s.writeRaw([]byte("OKAY"))
	s.close(nil)
}

// reverseListForwardService answers "reverse:list-forward".
//
// The reply is status-framed rather than bare, which is measured: a client reads a status
// message here and refuses to continue without one -- an empty reply is reported as
// "protocol fault (couldn't read status length)", while OKAY with a zero length is
// accepted and prints an empty listing.
//
// The entry format inside that payload is not established by the captures available here:
// every shape offered to a stock client -- "host fwd A B", "<serial> <local> <remote>",
// two fields, three fields, NUL- or newline-terminated -- was accepted without a protocol
// fault and printed nothing, so the width of an entry cannot be told from whether the
// command works. An empty listing is therefore what this replies with rather than a guess
// at a format no measurement distinguishes.
func reverseListForwardService(cfg Config, s *stream) {
	var entries []string
	forwardsMu.Lock()
	for _, fwd := range forwards {
		entries = append(entries, fwd.local+";"+fwd.remote)
	}
	forwardsMu.Unlock()

	var body strings.Builder
	for _, e := range entries {
		body.WriteString(e)
		body.WriteByte('\n')
	}
	payload := body.String()
	_ = s.writeRaw([]byte(fmt.Sprintf("OKAY%04x%s", len(payload), payload)))
	s.close(nil)
}

// reverseKillForwardAllService answers "reverse:killforward-all".
func reverseKillForwardAllService(cfg Config, s *stream) {
	forwardsMu.Lock()
	all := forwards
	forwards = map[string]*reverseForward{}
	forwardsMu.Unlock()

	for _, fwd := range all {
		close(fwd.done)
		_ = fwd.listener.Close()
	}
	cfg.debug("reverse:killforward-all: closed %d", len(all))
	_ = s.writeRaw([]byte("OKAY"))
	s.close(nil)
}

// loopbackAddr turns a socket spec into an address on this device's own loopback.
//
// Only "tcp:" is accepted, and only a numeric port. A device that accepted a hostname would
// resolve it, and a name in a service request is a name the requesting host chose; resolving
// it here would let that host pick where the connection lands. An operator's
// `adb forward tcp:A tcp:B` names a port, and refusing anything else says so rather than
// quietly listening somewhere.
func loopbackAddr(spec string) (string, error) {
	kind, port, ok := strings.Cut(spec, ":")
	if !ok || kind != "tcp" {
		return "", fmt.Errorf("unsupported socket specification %q: only tcp:PORT is served", spec)
	}
	if _, err := checkPort(port); err != nil {
		return "", fmt.Errorf("in %q: %w", spec, err)
	}
	return "127.0.0.1:" + port, nil
}

// checkPort accepts a decimal port and nothing else.
func checkPort(port string) (string, error) {
	n, err := strconv.Atoi(port)
	if err != nil || n < 0 || n > 65535 {
		return "", fmt.Errorf("malformed port %q", port)
	}
	return port, nil
}

// failStream reports a failure in the sync protocol's own shape and closes the stream.
func failStream(s *stream, format string, args ...any) {
	failMsg(s, format, args...)
	s.close(nil)
}

// spliceStreams copies in both directions until either side stops.
//
// The stream is closed when the copy from it finishes, so the socket sees the end of the
// peer's input rather than waiting for a read that will never come.
func spliceStreams(s *stream, conn net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(conn, s)
		if cw, ok := conn.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = conn.Close()
		}
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(s, conn)
		done <- struct{}{}
	}()
	<-done
}

// pendingOpen is a stream this device opened and is waiting for the host to accept.
//
// It exists because the OKAY arrives on the connection's single read loop, so it cannot be
// waited for by the goroutine that wrote the OPEN: doing that would need a second reader on
// the same socket, and two readers on one socket is how a connection ends up with each of
// them holding half of a packet. The read loop completes the pending stream instead, and
// the goroutine that asked waits on a channel.
type pendingOpen struct {
	// hostID is the id the host named in its OKAY, which is what this device's packets
	// on the stream have to address it by. Zero until the OKAY arrives.
	hostID uint32
	ready  chan error
}

// openService opens a stream of this device's own to the host, asking for a service.
//
// This is the device-initiated direction, and it exists for the reverse forward's callback:
// the device is the one that needs the connection to the host's port, so it has to be able
// to ask. A real adbd does the same thing, and the stream it opens is indistinguishable
// from one the host opened -- which is why the host cannot tell a callback from a service
// request by looking at the packet, only by the service name inside it.
func (c *conn) openService(service string) (*stream, error) {
	c.mu.Lock()
	c.nextID++
	id := c.nextID
	s := &stream{
		conn:         c,
		id:           id,
		in:           make(chan []byte, 64),
		done:         make(chan struct{}),
		eofCh:        make(chan struct{}),
		buf:          new(bytes.Buffer),
		onWindowSize: onWindowSizeDefault,
	}
	pending := &pendingOpen{ready: make(chan error, 1)}
	c.streams[id] = s
	c.pending[id] = pending
	c.mu.Unlock()

	open := Message{Cmd: CmdOPEN, Arg0: id, Arg1: 0, Data: append([]byte(service), 0)}
	if err := c.write(open); err != nil {
		c.forgetPending(id)
		return nil, err
	}

	select {
	case err := <-pending.ready:
		if err != nil {
			c.forgetPending(id)
			return nil, err
		}
		c.mu.Lock()
		s.hostID = pending.hostID
		c.mu.Unlock()
		return s, nil
	case <-time.After(forwardOpenTimeout):
		c.forgetPending(id)
		return nil, fmt.Errorf("mockadbd: no OKAY for %q within %s", service, forwardOpenTimeout)
	}
}

// completePending is called by the connection's read loop when a packet names a stream this
// device opened.
func (c *conn) completePending(m Message) bool {
	c.mu.Lock()
	pending, ok := c.pending[m.Arg1]
	if ok {
		pending.hostID = m.Arg0
		delete(c.pending, m.Arg1)
	}
	c.mu.Unlock()
	if !ok {
		return false
	}
	if m.Cmd == CmdCLSE {
		pending.ready <- fmt.Errorf("mockadbd: host closed the stream")
		return true
	}
	pending.ready <- nil
	return true
}

// forgetPending drops a pending open that will not be completed, so a later OKAY for the
// same id is not mistaken for one.
func (c *conn) forgetPending(id uint32) {
	c.mu.Lock()
	delete(c.pending, id)
	s := c.streams[id]
	delete(c.streams, id)
	c.mu.Unlock()
	if s != nil {
		s.setEOF()
	}
}
