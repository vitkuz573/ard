package main

// Adapters between the adb server protocol and the gateway's existing pieces.
//
// internal/adbserverproto answers adb's device-discovery and transport-switching protocol
// and needs two things from the gateway: a way to ask whether this operator may see a
// device, and a way to open one. Both already exist -- the ACL policy and the registry --
// so this file only translates between them. That translation is the point: it is what lets
// the operator path drop its device list without adding a second authorisation mechanism
// that could disagree with the first.
//
// Why the serial is the UUID
//
// adb's protocol asks for a device by serial, and adb is what an operator will type. The
// registry has no separate adb serial, because the device on the far end is not an adbd the
// operator ever saw: it is a gateway abstraction in front of a phone whose own adbd is
// reached over a tunnel. So the identifier handed to adb is the UUID -- stable across
// reconnects, already what the ACL policy is written against, and meaningful to an operator
// reading an audit log. Inventing a second identifier and translating between them would add
// a mapping that can disagree with the registry; using the UUID outright removes the class
// of bug rather than handling it.
//
// A consequence worth stating: a device with no adb serial of its own is exactly why `adb
// devices` output will look unlike a local phone's. That is honest. The alternative is a
// fabricated serial that looks familiar and matches nothing.

import (
	"fmt"
	"io"
	"net"
	"time"

	"github.com/vitkuz573/ard/internal/adbserverproto"
	"github.com/vitkuz573/ard/internal/audit"
	"github.com/vitkuz573/ard/internal/hs"
	"github.com/vitkuz573/ard/internal/registry"
)

// operatorFilter presents one operator's entitlements to the adb server protocol.
type operatorFilter struct {
	gw     *gateway
	op     string
	role   string
	remote string
}

// Allows is asked on every listing and every transport request, and answers from the
// operator's own policy. A serial this operator's role does not cover is refused by name, not merely left out of the listing: a client can ask for anything, so hiding is
// not enough on its own.
func (f operatorFilter) Allows(serial string) bool {
	if serial == "" {
		return false
	}
	return f.gw.authz.CanSee(f.op, serial)
}

// Connected decides whether a listing says "device" or "offline". The registry is the
// authority on liveness, so an entitled device that is registered but not attached shows up
// as offline rather than disappearing -- an operator who cannot see a device they are
// entitled to has no way to tell "not mine" from "not there".
func (f operatorFilter) Connected(serial string) bool {
	if serial == "" {
		return false
	}
	_, ok := f.gw.reg.Get(serial)
	return ok
}

// Features is what the device's own adbd said it supports, handed to adb verbatim.
//
// It comes from the registry because the agent put it there after reading the device's
// banner, and it is passed through unchanged for two reasons. adb chooses the spelling of
// every command it sends from this list, so a list rebuilt here could differ from the
// device's in a way nothing reports until a command chooses a path because of it. And a
// list invented here would be a claim about the device made by something that has not
// spoken to it, which is how a client ends up sending STA2 to an adbd that only knows STAT.
//
// A device that is not attached has no features to report, and the empty string is that:
// the registry entry is gone, and a client asking about a device that is not there is
// refused before it gets this far.
func (f operatorFilter) Features(serial string) string {
	if serial == "" {
		return ""
	}
	d, ok := f.gw.reg.Get(serial)
	if !ok {
		return ""
	}
	return d.Features
}

// Serials is what host:devices renders. It walks the registry so the states are the
// registry's, and filters through Allows so a device outside the operator's role cannot
// appear even by name.
func (f operatorFilter) Serials() []string {
	var out []string
	for _, d := range f.gw.reg.List() {
		if d.UUID == "" || !f.Allows(d.UUID) {
			continue
		}
		out = append(out, d.UUID)
	}
	return out
}

// Open returns a connection carrying the raw ADB transport to one device.
//
// It reuses the registry call and the same authorization the old per-device bridge used, so a
// client that forges a serial gains nothing: Allows has already answered, and the bridge
// permission is checked again here rather than assumed from it.
func (f operatorFilter) Open(serial string) (net.Conn, error) {
	if !f.Allows(serial) {
		return nil, fmt.Errorf("operator %q may not attach to %q", f.op, serial)
	}
	if d := f.gw.authz.Authorize(f.op, serial, "operator-bridge"); !d.Allowed {
		return nil, fmt.Errorf("operator %q may not attach to %q: %s", f.op, serial, d.Reason)
	}
	streamID := newStreamID()
	// The kind is "adb", not "operator-bridge". Those two are different things and the
	// difference is not cosmetic: "operator-bridge" is the name the ACL file gives this
	// permission check, while "adb" is the stream kind the agent dispatches on. Passing the
	// permission name opened a stream of a kind nothing on the device handles, so the
	// connection was accepted and then nothing was ever read from it -- the shell request
	// produced no output and no error, which is the worst of both.
	stream, err := f.gw.reg.Open(serial, streamID, hs.KindADB)
	if err != nil {
		return nil, err
	}
	f.gw.audit.Record(audit.Event{
		Kind: "stream.open", Actor: f.op, Device: serial,
		Stream: streamID, Remote: f.remote, Detail: "adb server protocol",
	})
	return &registryStream{rw: stream}, nil
}

// serveAdbServer answers adb's discovery and transport protocol on one connection, on behalf
// of one operator.
//
// The connection arrives already authenticated: the caller has completed mutual TLS and
// identified the operator, so the only question left is which devices this operator may
// have. That is why this is one function rather than a listener of its own -- it is a
// different protocol on the same authenticated port, and a second port would mean a second
// TLS policy to keep in step with the first.
func (g *gateway) serveAdbServer(conn net.Conn, operator, role string) {
	filter := operatorFilter{gw: g, op: operator, role: role, remote: conn.RemoteAddr().String()}
	srv := adbserverproto.New(filter, filter.Open, func(format string, args ...any) {
		g.logger.Printf("operator adb session (%s/%s): %s", operator, role, fmt.Sprintf(format, args...))
	})
	if err := srv.Serve(conn); err != nil {
		g.logger.Printf("operator adb session (%s) ended: %v", operator, err)
	}
	_ = conn.Close()
}

// registryStream adapts a registry stream to net.Conn, which is what the relay and
// adbserverproto expect.
//
// A registry stream is a logical stream on a multiplexed session, not a socket: it carries a
// stream id and lives inside one connection to the agent. Hence this type rather than the
// registry returning a net.Conn directly. The deadline methods are the honest part -- there
// is no socket to set a deadline on, and reporting success would tell a caller it had bounded
// a wait it had not.
type registryStream struct {
	rw io.ReadWriteCloser
}

func (s *registryStream) Read(p []byte) (int, error)  { return s.rw.Read(p) }
func (s *registryStream) Write(p []byte) (int, error) { return s.rw.Write(p) }
func (s *registryStream) Close() error                { return s.rw.Close() }

// LocalAddr and RemoteAddr are placeholders. The relay does not use them and adb never sees
// them, but net.Conn requires them, and an obviously empty address is better than a
// fabricated one that looks like a socket.
func (s *registryStream) LocalAddr() net.Addr              { return streamAddr{} }
func (s *registryStream) RemoteAddr() net.Addr             { return streamAddr{} }
func (s *registryStream) SetDeadline(time.Time) error      { return errNoDeadline }
func (s *registryStream) SetReadDeadline(time.Time) error  { return errNoDeadline }
func (s *registryStream) SetWriteDeadline(time.Time) error { return errNoDeadline }

// streamAddr is the zero net.Addr.
type streamAddr struct{}

func (streamAddr) Network() string { return "ard-stream" }
func (streamAddr) String() string  { return "ard-stream" }

// errNoDeadline says plainly that a deadline cannot be honoured on a multiplexed stream.
var errNoDeadline = fmt.Errorf("ard: deadlines are not supported on a multiplexed stream")

// Compile-time proof the filter really is wired to the policy, so a future change to either
// signature breaks the build rather than quietly widening access.
var _ adbserverproto.Filter = operatorFilter{}

// The feature list is a second, separate interface on purpose: what a device supports is a
// fact about the device, and a Filter that had to answer it would be asking every
// implementation of Filter for something only a gateway with a registry has.
var _ adbserverproto.Features = operatorFilter{}

// registry is referenced so the import documents what the adapter depends on.
var _ = registry.Device{}
