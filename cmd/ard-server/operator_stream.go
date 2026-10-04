package main

// The operator's data path.
//
// Until this existed, the gateway could identify an operator and nothing more: the
// operator port authenticated the peer, sent a device list, and then held the connection
// open doing nothing. The only working route to a device was running adb on the gateway
// host and connecting to its loopback port, which means handing every operator SSH access
// to the VPS. That is not a product: SSH access is all-or-nothing, it cannot be scoped
// per device, it cannot be revoked for one person without disturbing the others, and it
// hands out root on the machine holding the CA keys.
//
// So the operator runs ard-connect instead. It binds a loopback port per device the
// operator is entitled to, and for each adb connection it opens a mutual-TLS connection
// here and splices bytes. The stock adb binary is unmodified and speaks nothing but
// plaintext TCP to 127.0.0.1 -- which is exactly why the helper is unavoidable: adb
// cannot do TLS, so something has to terminate it locally on the operator's machine.
//
// Authorization happens here, never in the client. The device list in the greeting is
// already filtered by role, and every attach is checked again, so a client that asks for
// a device it was not shown is refused rather than trusted.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/vitkuz573/ard/internal/audit"
	"github.com/vitkuz573/ard/internal/hs"
)

// operatorRequest is what an operator client sends after the greeting.
//
// One request per connection, then raw bytes. The framing is explicit rather than a
// stream multiplexer because there is exactly one decision to make before the bytes
// start flowing, and because the thing on the other end is the ADB protocol itself,
// which has its own framing and must not be interleaved with ours.
type operatorRequest struct {
	Op     string `json:"op"`
	Device string `json:"device,omitempty"`
}

// serveOperatorStreams reads one request per connection and, for an attach, pipes the
// device end of the relay to the client.
//
// Sequential rather than concurrent on purpose: one adb connection means one TLS
// connection, because adb already multiplexes everything it needs over the single TCP
// connection it opens to a given device. Opening several would buy nothing.
func (g *gateway) serveOperatorStreams(ctx context.Context, conn net.Conn, operator, role string) {
	// The deadline covered the handshake and the greeting. From here the connection is a
	// relay that lives as long as adb needs it, which can be minutes or hours.
	_ = conn.SetDeadline(time.Time{})

	var req operatorRequest
	if err := json.NewDecoder(io.LimitReader(conn, 8<<10)).Decode(&req); err != nil {
		g.logger.Printf("operator %s: read request: %v", operator, err)
		return
	}
	if req.Op != "attach" {
		_ = writeJSON(conn, attachResponse{Error: fmt.Sprintf("unknown op %q", req.Op)})
		return
	}

	// The gate is operator-bridge, which requires PermShell.
	//
	// A raw ADB bridge cannot be separated by permission: one TCP connection carries
	// shell, install, file transfer and port forwarding, because ADB itself multiplexes
	// them. So the check is deliberately the strongest of the interactive permissions --
	// anything weaker would silently hand shell to an operator whose role excluded it.
	// What that costs is documented rather than hidden: holding shell on a device means
	// holding adb on that device.
	if d := g.authz.Authorize(operator, req.Device, "operator-bridge"); !d.Allowed {
		g.audit.Record(audit.Event{
			Kind: "operator.attach_denied", Actor: operator, Device: req.Device,
			Remote: conn.RemoteAddr().String(), Detail: d.Reason,
		})
		g.logger.Printf("operator %s denied %s on %s: %s", operator, "attach", req.Device, d.Reason)
		_ = writeJSON(conn, attachResponse{Error: d.Reason})
		return
	}

	streamID := newStreamID()
	stream, err := g.reg.Open(req.Device, streamID, hs.KindADB)
	if err != nil {
		_ = writeJSON(conn, attachResponse{Error: err.Error()})
		g.audit.Record(audit.Event{
			Kind: "stream.refused", Actor: operator, Device: req.Device,
			Stream: streamID, Remote: conn.RemoteAddr().String(), Detail: err.Error(),
		})
		return
	}
	if err := writeJSON(conn, attachResponse{Device: req.Device}); err != nil {
		_ = stream.Close()
		return
	}
	g.audit.Record(audit.Event{
		Kind: "stream.open", Actor: operator, Device: req.Device, Stream: streamID,
		Remote: conn.RemoteAddr().String(),
	})
	g.logger.Printf("operator %s attached to %s as %s", operator, req.Device, role)

	_ = pump(conn, stream)
	_ = stream.Close()
	g.audit.Record(audit.Event{
		Kind: "stream.close", Actor: operator, Device: req.Device, Stream: streamID,
	})
}
