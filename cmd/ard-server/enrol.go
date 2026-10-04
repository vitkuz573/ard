package main

// Enrolment: the path by which a device obtains its certificate.
//
// Two channels, deliberately asymmetric in how much they trust each other.
//
// The device side is a TCP listener with server-authenticated TLS and *no* client
// certificate, because the device has none yet -- that is the entire problem. So this
// port is reachable by anyone who can open a connection to the gateway, and it is
// treated as untrusted input throughout: bounded reads, a capped mailbox, short
// deadlines, and a claim code instead of anything that would let a stranger's request
// reach a signature.
//
// The operator side is the existing unix control socket, and it is where the signing
// decision is authorised. That socket is mode 0660 and group-owned by the gateway's own
// user, so filesystem permissions alone are not enough here: anything running as that
// user could otherwise ask the gateway to hand a certificate to a device, and a
// process that can do that can mint device identities -- the one thing this gateway
// must never be able to do. Enrolment operations therefore additionally require the
// peer's uid to be 0.
//
// The gateway never signs. It stores requests, forwards CSRs to the operator, and
// delivers certificates back. The CA key stays with the operator, so this design needs
// no secret on the gateway at all.

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/vitkuz573/ard/internal/audit"
	"github.com/vitkuz573/ard/internal/enrol"
)

// enrolAckTimeout bounds how long the operator waits for a device to confirm.
const enrolAckTimeout = 60 * time.Second

// enrolServerTLS builds the enrolment listener's TLS config.
//
// No ClientCAs and NoClientCert, which is the whole point: a device cannot present a
// certificate, and asking it to would make the port useless. The server identity is the
// same one the other listeners present, so the device is talking to the same host it
// will talk to afterwards.
//
// A certificate supplied anyway is refused rather than ignored. A client that offers a
// certificate unprompted here is either misconfigured or probing, and either way it
// should not proceed as if it had authenticated.
func enrolServerTLS(serverCert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.NoClientCert,
		MinVersion:   tls.VersionTLS13,
	}
}

// serveEnrol accepts certificate requests from devices that have no identity yet.
func (g *gateway) serveEnrol(ctx context.Context, ln net.Listener, tlsCfg *tls.Config) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			g.logger.Printf("enrol accept: %v", err)
			continue
		}
		go g.handleEnrol(ctx, conn, tlsCfg)
	}
}

func (g *gateway) handleEnrol(ctx context.Context, raw net.Conn, tlsCfg *tls.Config) {
	remote := raw.RemoteAddr().String()

	// One device, one conversation, one decision by a human. Long enough that an
	// operator can find the code, type it and approve; short enough that an abandoned
	// attempt does not pin a mailbox slot.
	_ = raw.SetDeadline(time.Now().Add(5 * time.Minute))
	conn := tls.Server(raw, tlsCfg)
	if err := conn.HandshakeContext(ctx); err != nil {
		g.audit.Record(audit.Event{
			Kind: "enrol.handshake_failed", Actor: "unknown", Remote: remote,
			Detail: err.Error(),
		})
		_ = conn.Close()
		return
	}
	if len(conn.ConnectionState().PeerCertificates) != 0 {
		// Nothing here should present a client certificate. Refusing is louder than
		// carrying on, and it cannot be reached by accident.
		g.audit.Record(audit.Event{
			Kind: "enrol.unexpected_client_cert", Actor: "unknown", Remote: remote,
			Detail: "a client certificate was offered on the enrolment port",
		})
		_ = conn.Close()
		return
	}

	var sub enrol.Submit
	if err := enrol.ReadJSON(conn, &sub, enrol.MaxCSRBytes+1024); err != nil {
		g.logger.Printf("enrol: read submit from %s: %v", remote, err)
		_ = conn.Close()
		return
	}

	pending, code, err := g.mailbox.Put(sub)
	if err != nil {
		// The device gets a refusal it can show a human rather than a dropped socket,
		// because "connection reset" tells nobody whether to retry or give up.
		g.audit.Record(audit.Event{
			Kind: "enrol.rejected", Actor: sanitizeActor(sub.DeviceID), Remote: remote,
			Detail: err.Error(),
		})
		_ = enrol.WriteJSON(conn, enrol.Outcome{Error: err.Error()})
		_ = conn.Close()
		return
	}

	g.audit.Record(audit.Event{
		Kind: "enrol.requested", Actor: sanitizeActor(sub.DeviceID), Remote: remote,
		Detail: fmt.Sprintf("request %s awaiting operator approval", pending.RequestID),
	})
	g.logger.Printf("enrol: %s requested a certificate, code %s", sub.DeviceID, code)

	if err := enrol.WriteJSON(conn, enrol.Receipt{
		Code:                       code,
		RequestID:                  pending.RequestID,
		ValidFor:                   g.mailbox.TTL().String(),
		ObservedGatewayFingerprint: sub.GatewayCertSHA256,
	}); err != nil {
		g.mailbox.Cancel(code)
		_ = conn.Close()
		return
	}

	certPEM, caPEM, ack, err := pending.Receive(ctx)
	if err != nil {
		g.audit.Record(audit.Event{
			Kind: "enrol.abandoned", Actor: sanitizeActor(sub.DeviceID), Remote: remote,
			Detail: fmt.Sprintf("request %s: %v", pending.RequestID, err),
		})
		g.mailbox.Cancel(code)
		_ = conn.Close()
		return
	}

	if err := enrol.WriteJSON(conn, enrol.Grant{CertPEM: certPEM, CAPEM: caPEM}); err != nil {
		ack(fmt.Errorf("send certificate: %w", err))
		g.mailbox.Cancel(code)
		_ = conn.Close()
		return
	}

	// Read the device's own verdict before closing, or the operator would be told
	// "delivered" for a device that stored nothing.
	_ = conn.SetDeadline(time.Now().Add(enrolAckTimeout))
	var outcome enrol.Outcome
	if err := enrol.ReadJSON(conn, &outcome, 8<<10); err != nil {
		ack(fmt.Errorf("read outcome: %w", err))
		g.mailbox.Cancel(code)
		_ = conn.Close()
		return
	}
	_ = conn.Close()

	if outcome.Error != "" {
		ack(errors.New(outcome.Error))
		g.mailbox.Cancel(code)
		return
	}
	ack(nil)

	g.audit.Record(audit.Event{
		Kind: "enrol.enrolled", Actor: sanitizeActor(sub.DeviceID), Remote: remote,
		Detail: fmt.Sprintf("request %s confirmed by the device", pending.RequestID),
	})
	g.logger.Printf("enrol: %s enrolled", sub.DeviceID)
}

// enrolControlClaim returns a pending request so the operator can sign it.
//
// Everything needed to approve is included: which device, which request id, and the CSR
// itself. An operator approving "device-7" must be approving *this* request, not
// whatever happens to be queued under that name later.
func (g *gateway) enrolControlClaim(conn net.Conn, req controlRequest) {
	pending, err := g.mailbox.Claim(req.Code)
	if err != nil {
		_ = writeJSON(conn, enrol.Claimed{Error: err.Error()})
		g.audit.Record(audit.Event{
			Kind: "enrol.claim_failed", Actor: "root", Remote: conn.RemoteAddr().String(),
			Detail: err.Error(),
		})
		return
	}
	g.audit.Record(audit.Event{
		Kind: "enrol.claimed", Actor: "root", Remote: conn.RemoteAddr().String(),
		Detail: fmt.Sprintf("request %s for device %s", pending.RequestID, pending.DeviceID),
	})
	_ = writeJSON(conn, enrol.Claimed{
		RequestID:                  pending.RequestID,
		DeviceID:                   pending.DeviceID,
		DeviceName:                 pending.DeviceName,
		CSRPEM:                     pending.CSRPEM,
		ObservedGatewayFingerprint: pending.GatewayCertSHA256,
	})
}

// enrolControlDeliver hands a signed certificate to the waiting device.
func (g *gateway) enrolControlDeliver(conn net.Conn, req controlRequest) {
	outcome, err := g.mailbox.Deliver(req.Code, req.CertPEM, req.CAPEM, enrolAckTimeout)
	if err != nil {
		_ = writeJSON(conn, enrol.Outcome{Error: err.Error()})
		g.audit.Record(audit.Event{
			Kind: "enrol.deliver_failed", Actor: "root", Remote: conn.RemoteAddr().String(),
			Detail: err.Error(),
		})
		return
	}
	g.audit.Record(audit.Event{
		Kind: "enrol.delivered", Actor: "root", Remote: conn.RemoteAddr().String(),
		Detail: fmt.Sprintf("request %s for device %s", outcome.RequestID, outcome.DeviceID),
	})
	_ = writeJSON(conn, *outcome)
}

// peerUID reports the uid of the process on the other end of a unix socket.
//
// ok is false for anything that is not a unix socket or when the kernel declines to
// answer, and that is the answer an authorisation check must act on: refuse rather than
// guess.
func peerUID(conn net.Conn) (uid uint32, ok bool) {
	uc, isUnix := conn.(*net.UnixConn)
	if !isUnix {
		return 0, false
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, false
	}
	var (
		cred    *syscall.Ucred
		callErr error
	)
	if err := raw.Control(func(fd uintptr) {
		cred, callErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil || callErr != nil || cred == nil {
		return 0, false
	}
	return cred.Uid, true
}

// requireRootControl authorises an enrolment operation on the control socket.
//
// The pre-existing control ops stay on filesystem permissions alone, because their worst
// outcome is proxying a stream an authorised operator could have asked for anyway. This
// one is different: it decides whether a certificate gets signed, so "the caller could
// read the socket" is not the question being asked. Only root may answer it.
func (g *gateway) requireRootControl(conn net.Conn, op string) bool {
	remote := conn.RemoteAddr().String()
	if os.Geteuid() != 0 {
		// getpeereid reports the real uid regardless of the server's privileges, but if
		// the server is not root the uid==0 branch is unreachable and the check is
		// vacuous. Say so rather than let it look like it is working.
		g.audit.Record(audit.Event{
			Kind: "enrol.unauthorised", Actor: "unknown", Remote: remote,
			Detail: fmt.Sprintf("%s refused: the gateway is not running as root", op),
		})
		return false
	}
	uid, ok := peerUID(conn)
	if !ok {
		g.audit.Record(audit.Event{
			Kind: "enrol.unauthorised", Actor: "unknown", Remote: remote,
			Detail: fmt.Sprintf("%s from a connection with no verifiable peer credentials", op),
		})
		return false
	}
	if uid != 0 {
		g.audit.Record(audit.Event{
			Kind: "enrol.unauthorised", Actor: fmt.Sprintf("uid:%d", uid), Remote: remote,
			Detail: fmt.Sprintf("%s requires uid 0", op),
		})
		return false
	}
	return true
}

// sanitizeActor keeps an untrusted device-supplied string out of the audit log verbatim.
//
// The device chooses this text and the audit log is often shipped off-host and
// rendered. Newlines in particular would let a caller forge log lines.
func sanitizeActor(s string) string {
	const max = 64
	out := make([]rune, 0, max)
	for _, r := range s {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			out = append(out, ' ')
		case r < 0x20:
			// Drop other control characters entirely.
		default:
			out = append(out, r)
		}
		if len(out) >= max {
			break
		}
	}
	if len(out) == 0 {
		return "unknown"
	}
	return string(out)
}
