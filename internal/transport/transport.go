// Package transport carries device sessions between an agent and the gateway.
//
// Topology, and why it is shaped this way:
//
//	ard-agent (device)  --dials out-->  ard-server (gateway)  <--dials in--  ard-connect
//
// The device always initiates. It sits behind NAT in practice, often behind
// carrier-grade NAT, so nothing on the gateway can reach it. That single fact
// determines the design: the gateway holds one inbound connection per device and
// multiplexes operator streams over it rather than connecting out per request.
// The operator side dials in on a separate listener and is not multiplexed by this
// package: it speaks adb's own protocol, and each of its connections is one of its own.
//
// One TLS connection per device carries every stream, so a device with twenty
// concurrent operator sessions still costs one TCP connection and one certificate
// validation.
package transport

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/hashicorp/yamux"

	"github.com/vitkuz573/ard/internal/hs"
)

// Tunables. These are deliberately conservative: a mobile agent is often on a lossy
// link, and the gateway fans many streams onto one connection.
const (
	// keepalive detects a dead peer. Without it a silently dropped TCP connection
	// is only discovered when an operator tries to use a session, by which time
	// they see a hang rather than a disconnect.
	keepalive = 30 * time.Second

	// acceptBacklog bounds streams awaiting acceptance, so a device that stops
	// reading its adbd cannot make the gateway queue work without limit.
	acceptBacklog = 256

	// openTimeout bounds opening a stream to a device. An agent that is connected
	// but not draining would otherwise stall the operator indefinitely.
	openTimeout = 15 * time.Second

	// routeTimeout bounds reading a route header, which is the first thing on a
	// new stream and the only part an untrusted peer controls the size of.
	routeTimeout = 15 * time.Second
)

// Session multiplexes streams over one authenticated device connection.
//
// Either end may open or accept: the gateway opens streams in response to an
// operator, and the agent accepts them. Both sides also accept, because a peer
// that opens a stream is either buggy or hostile, and reading its route header
// lets the attempt be refused with a reason rather than left hanging.
type Session struct {
	// Device is the stable UUID. It survives reboot, reinstall and address
	// change, which a connection cannot, and it is what authorization uses.
	Device string
	// Name is the label the agent reported, for operator interfaces only.
	Name string
	// Features is the feature list the device's own adbd reported. It is the
	// device's claim about itself, carried here so the gateway can answer adb's
	// feature question from the device rather than from its own opinion.
	Features string

	mux  *yamux.Session
	conn net.Conn
}

// Role says which end of the connection this process is.
//
// It is not cosmetic, because the multiplexer numbers streams from the end that dialled and
// does not renumber the other end's. Measured: with both ends built the same way, the first
// stream each opened landed on the same number, and the session ended with "duplicate stream
// initiated" on one side and EOF on the other. Every stream on the connection died with it,
// including ones already carrying data. One end Client and the other Server is what lets both
// open streams, which is required here: the gateway opens a stream when an operator connects,
// and the agent opens one when a device asks for a port on the gateway.
type Role int

const (
	// Dialer is the end that opened the connection: the agent, which dials the gateway.
	Dialer Role = iota
	// Acceptor is the end that was connected to: the gateway, which accepts devices.
	Acceptor
)

// New wraps an authenticated connection.
//
// The caller must have completed the ARD handshake and checked the peer against
// the allowlist first. Wrapping an unauthorised connection would hand out a usable
// session, so this constructor trusts its caller completely.
//
// features is the list the device's adbd reported in its CNXN banner, carried
// verbatim from the handshake. The session does not parse it and does not check it:
// a device that advertised nothing is a device that supports nothing, and quietly
// substituting a list would put a client on a path the device cannot serve.
func New(conn net.Conn, device, name, features string, role Role) (*Session, error) {
	cfg := yamux.DefaultConfig()
	cfg.EnableKeepAlive = true
	cfg.KeepAliveInterval = keepalive
	cfg.LogOutput = io.Discard
	cfg.MaxStreamWindowSize = 1 << 20
	cfg.AcceptBacklog = acceptBacklog

	var (
		mux *yamux.Session
		err error
	)
	if role == Acceptor {
		mux, err = yamux.Server(conn, cfg)
	} else {
		mux, err = yamux.Client(conn, cfg)
	}
	if err != nil {
		return nil, fmt.Errorf("transport: start mux: %w", err)
	}
	return &Session{Device: device, Name: name, Features: features, mux: mux, conn: conn}, nil
}

// Open reserves a stream and writes the route header.
//
// The header must precede any payload byte: the peer reads it to learn the stream
// kind, and a payload byte consumed as a header desynchronises its framing for
// every stream that follows.
func (s *Session) Open(ctx context.Context, kind, streamID string, meta any) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	stream, err := s.mux.OpenStream()
	if err != nil {
		return nil, fmt.Errorf("transport: open stream to %s: %w", s.Device, err)
	}
	if err := stream.SetDeadline(time.Now().Add(openTimeout)); err != nil {
		_ = stream.Close()
		return nil, err
	}
	raw, err := encodeMeta(meta)
	if err != nil {
		_ = stream.Close()
		return nil, err
	}
	if err := hs.WriteRoute(stream, hs.Route{
		Device: s.Device,
		Kind:   kind,
		Stream: streamID,
		Meta:   raw,
	}); err != nil {
		_ = stream.Close()
		return nil, fmt.Errorf("transport: write route: %w", err)
	}
	if err := stream.SetDeadline(time.Time{}); err != nil {
		_ = stream.Close()
		return nil, err
	}
	return stream, nil
}

// Accept serves peer-initiated streams until the context ends or the session fails.
//
// Both kinds of stream arrive on the same session and are told apart by their first bytes.
// A stream the gateway opened carries a route header, and a route header begins with this
// protocol's version; a stream the device opened carries a bare service name. Five bytes
// are enough to tell them apart, and both are line-delimited text, so classifying is a peek
// rather than a read: a stream whose header cannot be read is closed and skipped, because a
// malformed header says nothing about the health of the session and one bad stream must not
// cost every other stream.
func (s *Session) Accept(ctx context.Context,
	onRoute func(route hs.Route, conn net.Conn) error,
	onDevice func(service string, conn net.Conn) error) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		stream, err := s.mux.AcceptStream()
		if err != nil {
			return err
		}
		if err := stream.SetReadDeadline(time.Now().Add(routeTimeout)); err != nil {
			_ = stream.Close()
			continue
		}
		br := bufio.NewReader(stream)
		prefix, err := br.Peek(len(hs.Proto))
		if err != nil {
			_ = stream.Close()
			continue
		}
		if string(prefix) == hs.Proto {
			route, err := hs.ReadRoute(br)
			if err != nil {
				_ = stream.Close()
				continue
			}
			if err := stream.SetDeadline(time.Time{}); err != nil {
				_ = stream.Close()
				continue
			}
			go func() {
				defer func() { _ = stream.Close() }()
				_ = onRoute(route, &prefixedConn{Conn: stream, r: br})
			}()
			continue
		}
		service, err := hs.ReadService(br)
		if err != nil {
			_ = stream.Close()
			continue
		}
		if err := stream.SetDeadline(time.Time{}); err != nil {
			_ = stream.Close()
			continue
		}
		go func() {
			defer func() { _ = stream.Close() }()
			_ = onDevice(service, &prefixedConn{Conn: stream, r: br})
		}()
	}
}

// prefixedConn is a stream whose first bytes were buffered to classify it.
//
// The buffered reader has to stay in front of the stream, or the bytes it holds belong to
// nobody: the handler would read from the socket and get whatever came after them.
type prefixedConn struct {
	net.Conn
	r io.Reader
}

func (c *prefixedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// Close ends the mux and the underlying connection.
func (s *Session) Close() error {
	err := s.mux.Close()
	if cerr := s.conn.Close(); err == nil {
		err = cerr
	}
	return err
}

// encodeMeta renders route metadata. A nil value becomes an empty object rather
// than null so the peer never has to distinguish the two.
func encodeMeta(meta any) (json.RawMessage, error) {
	if meta == nil {
		return json.RawMessage(`{}`), nil
	}
	b, err := json.Marshal(meta)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(b), nil
}
