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

	mux  *yamux.Session
	conn net.Conn
}

// New wraps an authenticated connection.
//
// The caller must have completed the ARD handshake and checked the peer against
// the allowlist first. Wrapping an unauthorised connection would hand out a usable
// session, so this constructor trusts its caller completely.
func New(conn net.Conn, device, name string) (*Session, error) {
	cfg := yamux.DefaultConfig()
	cfg.EnableKeepAlive = true
	cfg.KeepAliveInterval = keepalive
	cfg.LogOutput = io.Discard
	cfg.MaxStreamWindowSize = 1 << 20
	cfg.AcceptBacklog = acceptBacklog

	mux, err := yamux.Client(conn, cfg)
	if err != nil {
		return nil, fmt.Errorf("transport: start mux: %w", err)
	}
	return &Session{Device: device, Name: name, mux: mux, conn: conn}, nil
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
// A stream whose route header cannot be read is closed and skipped: a malformed
// header says nothing about the health of the session, so one bad stream must not
// cost every other stream.
func (s *Session) Accept(ctx context.Context, handler func(hs.Route, net.Conn) error) error {
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
		route, err := hs.ReadRoute(stream)
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
			_ = handler(route, stream)
		}()
	}
}

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
