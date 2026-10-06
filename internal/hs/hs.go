// Package hs carries ARD's wire framing: the connection handshake, the per-stream
// route header, and the inner multiplexer that lets many operator streams share a
// single adbd connection.
//
// Framing is deliberately text on the control plane and binary on the data plane.
// The handshake lines are line-delimited so they can be inspected by eye and by
// standard tools during an incident; everything after a route header is opaque
// bytes that ARD never parses.
package hs

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"time"
)

// Proto is the protocol version prefix. A mismatch is refused rather than
// downgraded: silently accepting an older peer would mean guessing at framing
// semantics that may have changed.
const Proto = "ARD/1"

// maxControlLine caps the handshake line. A device name is the only unbounded
// field, so this is generous for legitimate input while keeping a hostile peer
// from forcing an unbounded allocation.
const maxControlLine = 8 << 10

// Kind identifies what a stream carries. Only the device-side kinds exist today;
// the operator side reuses them to expose a raw adb transport.
const (
	KindADB    = "adb"
	KindShell  = "shell"
	KindExec   = "exec"
	KindLogcat = "logcat"
	KindFiles  = "files"
	KindRawADB = "raw-adb"

	// KindDeviceOpen is a stream the device opened for itself, named by DeviceOpen's
	// Service rather than by a route of ours.
	//
	// It exists because a device sometimes needs a connection to the host and the only
	// way to get one is to ask: a reverse forward binds a port on the device, and
	// whatever connects to that port has to reach a port on the host. The device cannot
	// open a stream through the gateway -- the gateway opens streams in response to an
	// operator, and a device that could open one would be able to reach any operator's
	// device -- so it asks the agent and the agent relays the ask.
	KindDeviceOpen = "device-open"
)

// DeviceOpen is the service name a device asked for, carried as a route's metadata.
type DeviceOpen struct {
	// Service is the socket specification, such as "tcp:9911".
	Service string `json:"service"`
}

// WriteService announces a device's own request on a stream it opened.
//
// It is a bare NUL-terminated string rather than a route header: this stream was not opened
// by the gateway, so there is no route for it, and the header's own version prefix would be
// indistinguishable from a service name that happened to start with the same letters.
func WriteService(w io.Writer, service string) error {
	if service == "" {
		return errors.New("hs: device stream without a service")
	}
	_, err := w.Write(append([]byte(service), 0))
	return err
}

// ReadService reads a device's own request.
//
// The cap is the same one the control lines use, for the same reason: the peer on this end
// is a device, and a name it never terminates would otherwise make this read until it
// happened to see a zero byte in whatever followed.
func ReadService(r io.Reader) (string, error) {
	var out []byte
	var b [1]byte
	for {
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return "", fmt.Errorf("hs: read device service: %w", err)
		}
		if b[0] == 0 {
			if len(out) == 0 {
				return "", errors.New("hs: device stream without a service")
			}
			return string(out), nil
		}
		out = append(out, b[0])
		if len(out) > maxControlLine {
			return "", fmt.Errorf("hs: device service exceeds cap %d", maxControlLine)
		}
	}
}

// Hello is the device's first message.
type Hello struct {
	Device string `json:"device"`
	Name   string `json:"name"`
	Agent  string `json:"agent"`
	// Features is the feature list from the device's own CNXN banner, verbatim.
	//
	// It travels here rather than being looked up later because the gateway has to
	// answer a feature question before any stream exists: adb asks what a device
	// supports while it is still deciding whether to switch onto it. A device that
	// reported its features on first use would leave that question unanswerable
	// until an operator had already asked one.
	Features string `json:"features,omitempty"`
}

// Welcome is the gateway's answer. A non-empty Error means the device was refused.
type Welcome struct {
	Session   string        `json:"session"`
	Heartbeat time.Duration `json:"heartbeat"`
	Error     string        `json:"error,omitempty"`
}

// Route prefixes a stream. The gateway writes it; the agent reads it. Stream is
// echoed so the agent can include it in its own logs, which is what makes a
// single operator action traceable across the gateway, the transport and the device.
type Route struct {
	Device string          `json:"device"`
	Kind   string          `json:"kind"`
	Stream string          `json:"stream"`
	Meta   json.RawMessage `json:"meta,omitempty"`
}

// ClientHandshake performs the device side of the connection handshake.
func ClientHandshake(rw io.ReadWriter, h Hello) (Welcome, error) {
	if err := writeLine(rw, Proto+" HELLO "+mustJSON(h)); err != nil {
		return Welcome{}, fmt.Errorf("hs: send hello: %w", err)
	}
	line, err := readLine(rw)
	if err != nil {
		return Welcome{}, fmt.Errorf("hs: read welcome: %w", err)
	}
	verb, rest, ok := splitVerb(line)
	if !ok {
		return Welcome{}, fmt.Errorf("hs: malformed welcome %q", line)
	}
	switch verb {
	case "WELCOME":
		var w Welcome
		if err := json.Unmarshal([]byte(rest), &w); err != nil {
			return Welcome{}, fmt.Errorf("hs: parse welcome: %w", err)
		}
		if w.Error != "" {
			return w, fmt.Errorf("hs: refused by gateway: %s", w.Error)
		}
		return w, nil
	case "ERR":
		return Welcome{}, fmt.Errorf("hs: gateway rejected connection: %s", rest)
	default:
		return Welcome{}, fmt.Errorf("hs: unexpected reply %q", verb)
	}
}

// ServerHandshake performs the gateway side. It returns the device's identity,
// which the caller must still check against the registry before serving streams.
func ServerHandshake(rw io.ReadWriter) (Hello, error) {
	line, err := readLine(rw)
	if err != nil {
		return Hello{}, fmt.Errorf("hs: read hello: %w", err)
	}
	verb, rest, ok := splitVerb(line)
	if !ok {
		return Hello{}, fmt.Errorf("hs: malformed hello %q", line)
	}
	if verb != "HELLO" {
		return Hello{}, fmt.Errorf("hs: expected HELLO, got %q", verb)
	}
	var h Hello
	if err := json.Unmarshal([]byte(rest), &h); err != nil {
		return Hello{}, fmt.Errorf("hs: parse hello: %w", err)
	}
	if h.Device == "" {
		return Hello{}, errors.New("hs: hello without device id")
	}
	return h, nil
}

// WriteRoute writes a stream header. It must be the first thing written on a new
// stream, before any payload byte.
func WriteRoute(w io.Writer, r Route) error {
	if r.Kind == "" {
		return errors.New("hs: route without kind")
	}
	if r.Stream == "" {
		return errors.New("hs: route without stream id")
	}
	if err := writeLine(w, Proto+" ROUTE "+mustJSON(r)); err != nil {
		return fmt.Errorf("hs: write route: %w", err)
	}
	return nil
}

// ReadRoute reads a stream header written by the gateway.
func ReadRoute(rd io.Reader) (Route, error) {
	line, err := readLine(rd)
	if err != nil {
		return Route{}, fmt.Errorf("hs: read route: %w", err)
	}
	verb, rest, ok := splitVerb(line)
	if !ok {
		return Route{}, fmt.Errorf("hs: malformed route %q", line)
	}
	if verb != "ROUTE" {
		return Route{}, fmt.Errorf("hs: expected ROUTE, got %q", verb)
	}
	var rt Route
	if err := json.Unmarshal([]byte(rest), &rt); err != nil {
		return Route{}, fmt.Errorf("hs: parse route: %w", err)
	}
	if rt.Kind == "" || rt.Stream == "" {
		return Route{}, errors.New("hs: incomplete route header")
	}
	return rt, nil
}

// inner frame types
const (
	frameOpen  byte = 0x01
	frameData  byte = 0x02
	frameClose byte = 0x03
)

// maxFrame bounds a single data frame. adbd's largest stream payload in practice
// is small (the sync protocol uses 64 KiB); the cap exists so a corrupt length
// prefix cannot cause a huge allocation.
const maxFrame = 1 << 20

// openFrame is the payload of frameOpen.
type openFrame struct {
	Stream string          `json:"stream"`
	Kind   string          `json:"kind"`
	Meta   json.RawMessage `json:"meta,omitempty"`
}

// The inner multiplexer exists for one reason: adbd has historically replaced an
// old host connection when a new one arrived, which would sever an in-flight
// session whenever the transport reconnects. Holding a single adbd connection for
// the life of the agent session and multiplexing over it removes that failure
// mode. If a device is shown to tolerate concurrent adbd connections, the inner
// layer can be removed and each stream given its own connection.

func writeFrame(w io.Writer, typ byte, payload []byte) error {
	if len(payload) > maxFrame {
		return fmt.Errorf("hs: frame of %d bytes exceeds cap %d", len(payload), maxFrame)
	}
	buf := make([]byte, 5+len(payload))
	binary.BigEndian.PutUint32(buf[:4], uint32(len(payload)))
	buf[4] = typ
	copy(buf[5:], payload)
	if _, err := w.Write(buf); err != nil {
		return err
	}
	return nil
}

func readFrame(r io.Reader) (byte, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:4])
	if n > maxFrame {
		return 0, nil, fmt.Errorf("hs: frame length %d exceeds cap %d", n, maxFrame)
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return hdr[4], payload, nil
}

// AcceptStream blocks until the device opens a stream, or the connection ends.
// Link lives in link.go; this file keeps only framing primitives.

func writeLine(w io.Writer, s string) error {
	if len(s) > maxControlLine {
		return fmt.Errorf("hs: control line of %d bytes exceeds cap %d", len(s), maxControlLine)
	}
	_, err := io.WriteString(w, s+"\n")
	return err
}

// readLine reads one newline-terminated control line.
//
// It reads byte at a time on purpose. A bufio.Reader would happily buffer up to
// its window size and swallow the leading bytes of the binary stream that follows
// the route header, silently corrupting the first payload of every stream. Control
// lines are rare and tiny, so the cost of unbuffered reads is irrelevant next to
// that failure mode.
func readLine(r io.Reader) (string, error) {
	var sb strings.Builder
	var b [1]byte
	for {
		if _, err := io.ReadFull(r, b[:]); err != nil {
			if errors.Is(err, io.EOF) {
				if sb.Len() == 0 {
					return "", io.ErrUnexpectedEOF
				}
				return "", fmt.Errorf("hs: unterminated control line %q", sb.String())
			}
			return "", err
		}
		if b[0] == '\n' {
			return strings.TrimRight(sb.String(), "\r"), nil
		}
		sb.WriteByte(b[0])
		if sb.Len() > maxControlLine {
			return "", fmt.Errorf("hs: control line exceeds cap %d", maxControlLine)
		}
	}
}

func splitVerb(line string) (verb, rest string, ok bool) {
	if !strings.HasPrefix(line, Proto+" ") {
		return "", "", false
	}
	body := line[len(Proto)+1:]
	i := strings.IndexByte(body, ' ')
	if i < 0 {
		return body, "", true
	}
	return body[:i], body[i+1:], true
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		// The only inputs are the structs in this package, all of which are
		// always marshalable. A failure here is a programming error.
		panic("hs: marshal control frame: " + err.Error())
	}
	return string(b)
}

// ServerReply answers a device handshake.
//
// The refusal is a distinct verb rather than a WELCOME carrying an error,
// because the agent must be able to tell "you are not enrolled" from "the network
// broke". Only the first is worth retrying, and conflating them produces an agent
// that reconnects forever against a permanent rejection.
func ServerReply(w io.Writer, welcome Welcome) error {
	if welcome.Error != "" {
		return writeLine(w, Proto+" ERR "+welcome.Error)
	}
	return writeLine(w, Proto+" WELCOME "+mustJSON(welcome))
}
