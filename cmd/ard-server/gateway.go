package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/vitkuz573/ard/internal/acl"
	"github.com/vitkuz573/ard/internal/audit"
	"github.com/vitkuz573/ard/internal/enrol"
	"github.com/vitkuz573/ard/internal/hs"
	"github.com/vitkuz573/ard/internal/registry"
	"github.com/vitkuz573/ard/internal/tlsx"
	"github.com/vitkuz573/ard/internal/transport"
)

// gateway is the shared state behind both listeners and the control socket.
type gateway struct {
	// mailbox holds certificate requests from devices that have no identity yet.
	// It is storage and a rendezvous point, never a signing authority: the gateway
	// holds no CA key, so nothing here can produce a certificate on its own.
	mailbox *enrol.Mailbox
	reg     *registry.Registry
	audit   *audit.Auditor
	authz   *acl.Policy
	logger  *log.Logger
}

// serveDevices accepts agent connections.
func (g *gateway) serveDevices(ctx context.Context, ln net.Listener, tlsCfg *tls.Config) {
	for {
		raw, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			// One bad connection must not stop the listener.
			g.logger.Printf("device accept: %v", err)
			continue
		}
		go func() {
			if err := g.handleDevice(ctx, raw, tlsCfg); err != nil && ctx.Err() == nil {
				g.logger.Printf("device session ended: %v", err)
			}
		}()
	}
}

// handleDevice performs device admission.
//
// The order is deliberate and each step is a gate: TLS, then role, then handshake,
// then certificate-identity agreement, then the allowlist, then the registry. The
// allowlist is consulted before a session exists, so an unenrolled device never
// becomes present even briefly and can never be routed to.
func (g *gateway) handleDevice(ctx context.Context, raw net.Conn, tlsCfg *tls.Config) error {
	remote := raw.RemoteAddr().String()
	defer raw.Close()

	_ = raw.SetDeadline(time.Now().Add(30 * time.Second))
	conn := tls.Server(raw, tlsCfg)
	if err := conn.HandshakeContext(ctx); err != nil {
		g.audit.Record(audit.Event{
			Kind: "device.handshake_failed", Actor: "unknown",
			Remote: remote, Detail: err.Error(),
		})
		return err
	}
	certName, err := tlsx.VerifyPeerRole(conn.ConnectionState(), tlsx.OrgUnitDevice)
	if err != nil {
		g.audit.Record(audit.Event{
			Kind: "device.bad_role", Actor: "unknown",
			Remote: remote, Detail: err.Error(),
		})
		return err
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return err
	}

	hello, err := hs.ServerHandshake(conn)
	if err != nil {
		return err
	}

	// The certificate name and the claimed UUID must agree. Without this, a device
	// holding one certificate could claim another device's UUID and inherit its
	// grants, which defeats the allowlist completely.
	if certName != hello.Device {
		_ = refuse(conn, "certificate is for device %q, not %q", certName, hello.Device)
		g.audit.Record(audit.Event{
			Kind: "device.identity_mismatch", Device: hello.Device, Actor: certName,
			Remote: remote, Detail: "certificate name does not match claimed device",
		})
		return fmt.Errorf("device %q presented certificate for %q", hello.Device, certName)
	}
	if !g.reg.Allowed(hello.Device) {
		_ = refuse(conn, "device %q is not enrolled", hello.Device)
		g.audit.Record(audit.Event{
			Kind: "device.not_enrolled", Device: hello.Device, Actor: certName,
			Remote: remote,
		})
		return fmt.Errorf("device %q is not enrolled", hello.Device)
	}

	device, err := transport.New(conn, hello.Device, hello.Name)
	if err != nil {
		return err
	}
	defer device.Close()

	var once sync.Once
	closer := func() error {
		once.Do(func() { _ = device.Close() })
		return nil
	}

	if err := g.reg.Add(hello.Device, hello.Name, hello.Agent, remote,
		func(streamID, kind string) (io.ReadWriteCloser, error) {
			return device.Open(ctx, kind, streamID, nil)
		},
		closer,
	); err != nil {
		_ = refuse(conn, "%s", err.Error())
		return err
	}

	sessionID := newStreamID()
	if err := hs.ServerReply(conn, hs.Welcome{Session: sessionID, Heartbeat: 30 * time.Second}); err != nil {
		_, _ = g.reg.Remove(hello.Device)
		return err
	}
	g.logger.Printf("device %s connected from %s (session %s)", hello.Device, remote, sessionID)

	defer func() {
		closeDevice, _ := g.reg.Remove(hello.Device)
		if closeDevice != nil {
			_ = closeDevice()
		}
	}()

	return device.Accept(ctx, func(route hs.Route, stream net.Conn) error {
		// Devices must not be able to request streams. The gateway opens streams in
		// response to an operator; anything arriving here is a bug or an attempt to
		// invert the model, so the stream is closed and the attempt recorded.
		_ = stream.Close()
		g.audit.Record(audit.Event{
			Kind: "device.stream_rejected", Device: hello.Device, Actor: certName,
			Remote: remote,
			Detail: fmt.Sprintf("device-initiated stream %s kind=%s", route.Stream, route.Kind),
		})
		return fmt.Errorf("device-initiated streams are not permitted")
	})
}

// refuse reports why a device was rejected before closing.
//
// The reason is written first because that is the only chance to deliver it: an
// agent that sees only EOF cannot distinguish a policy decision from a network
// fault, and will retry a permanent rejection forever.
func refuse(conn net.Conn, format string, args ...any) error {
	reason := fmt.Sprintf(format, args...)
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_ = hs.ServerReply(conn, hs.Welcome{Error: reason})
	return errors.New(reason)
}

// serveOperators accepts operator connections.
func (g *gateway) serveOperators(ctx context.Context, ln net.Listener, tlsCfg *tls.Config) {
	for {
		raw, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			g.logger.Printf("operator accept: %v", err)
			continue
		}
		go func() {
			defer raw.Close()
			if err := g.handleOperator(ctx, raw, tlsCfg); err != nil && ctx.Err() == nil {
				g.logger.Printf("operator session ended: %v", err)
			}
		}()
	}
}

func (g *gateway) handleOperator(ctx context.Context, raw net.Conn, tlsCfg *tls.Config) error {
	remote := raw.RemoteAddr().String()
	_ = raw.SetDeadline(time.Now().Add(30 * time.Second))
	conn := tls.Server(raw, tlsCfg)
	if err := conn.HandshakeContext(ctx); err != nil {
		g.audit.Record(audit.Event{
			Kind: "operator.handshake_failed", Actor: "unknown",
			Remote: remote, Detail: err.Error(),
		})
		return err
	}
	name, err := tlsx.VerifyPeerRole(conn.ConnectionState(), tlsx.OrgUnitOperator)
	if err != nil {
		g.audit.Record(audit.Event{
			Kind: "operator.bad_role", Actor: "unknown",
			Remote: remote, Detail: err.Error(),
		})
		return err
	}
	role, ok := g.authz.Describe(name)
	if !ok {
		// Refusing an operator with no role is the point of the policy file.
		g.audit.Record(audit.Event{
			Kind: "operator.no_role", Actor: name, Remote: remote,
		})
		return fmt.Errorf("operator %q has no role", name)
	}
	g.audit.Record(audit.Event{
		Kind: "operator.connected", Actor: name, Remote: remote, Detail: role.Name,
	})
	g.logger.Printf("operator %s connected from %s (role %s, %d grants)",
		name, remote, role.Name, len(role.Grants))

	// The operator leg speaks adb's own server protocol and nothing else.
	//
	// adb asks "which devices exist" and "switch to this one", so the gateway answers those
	// questions and adb discovers the rest. Filtering happens in the adapter against the
	// operator's own policy.
	_ = conn.SetDeadline(time.Time{})
	g.audit.Record(audit.Event{
		Kind: "operator.adb_protocol", Actor: name, Remote: remote, Detail: role.Name,
	})
	g.logger.Printf("operator %s from %s speaking the adb server protocol (role %s, %d grants)",
		name, remote, role.Name, len(role.Grants))
	g.serveAdbServer(conn, name, role.Name)
	return nil
}

// serveControl serves the enrolment control socket.
//
// This is deliberately not exposed on TCP. A loopback TCP port is reachable by
// every local process, whereas socket permissions confine it to the gateway group.
func (g *gateway) serveControl(ctx context.Context, ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			g.logger.Printf("control accept: %v", err)
			continue
		}
		go g.handleControl(ctx, conn)
	}
}

func (g *gateway) handleControl(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Minute))

	var req controlRequest
	if err := json.NewDecoder(io.LimitReader(conn, 8<<10)).Decode(&req); err != nil {
		g.logger.Printf("control: decode: %v", err)
		return
	}

	// Control callers are local and already trusted by filesystem permissions, so
	// the actor recorded in the audit log is the component name rather than a
	// connection identity.
	switch req.Op {
	case "enrol.claim":
		if !g.requireRootControl(conn, req.Op) {
			_ = writeJSON(conn, enrol.Claimed{Error: "enrol: this operation requires uid 0"})
			return
		}
		g.enrolControlClaim(conn, req)
	case "enrol.deliver":
		if !g.requireRootControl(conn, req.Op) {
			_ = writeJSON(conn, enrol.Outcome{Error: "enrol: this operation requires uid 0"})
			return
		}
		g.enrolControlDeliver(conn, req)
	default:
		_ = writeJSON(conn, controlError{Error: fmt.Sprintf("unknown op %q", req.Op)})
	}
}

func writeJSON(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = w.Write(append(b, '\n'))
	return err
}
