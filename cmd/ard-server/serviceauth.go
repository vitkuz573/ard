package main

// Deciding what an operator's adb may ask for, from the service name it sent.
//
// Every command an operator runs arrives the same way: adb asks the server for a transport
// to the device, gets one, and then sends the service it wants on that connection. The
// transport is the same for all of them. The service name is the only thing that says what
// this particular request is, which makes it the only place a stream kind can be decided.
//
// So the check is here rather than at the transport, and it is made per request. Caching a
// decision per session would be cheaper and wrong: an operator's role can be changed while
// their session is open, and the request in hand is the thing being decided.
//
// Measured against a stock adb binary, the service names that arrive and the kinds they
// mean are listed in acl.KindForService, which is where the table lives. This file is the
// part that turns a table entry into a decision, and a decision into a sentence an operator
// can act on.

import (
	"fmt"

	"github.com/vitkuz573/ard/internal/acl"
	"github.com/vitkuz573/ard/internal/adbserverproto"
	"github.com/vitkuz573/ard/internal/audit"
)

// serviceAuthorizer decides whether one operator may open one service on one device.
//
// It is per operator rather than per gateway so that the identity is the operator's own
// certificate name and not anything the client wrote: the service name is attacker-supplied
// text, and an authorizer that read the operator out of it would be checking the client's
// claim about itself.
type serviceAuthorizer struct {
	gw *gateway
	op string
}

// authorizerFor binds the gateway's policy to one operator's identity.
func (g *gateway) authorizerFor(operator string) serviceAuthorizer {
	return serviceAuthorizer{gw: g, op: operator}
}

// AuthorizeService reports whether this operator may open this service on this device.
//
// The refusal names the operator, the device, the kind and the policy's own reason, because
// the four together are what an operator needs to act and the rest is what an administrator
// needs to review. It travels back as the FAIL payload adb prints on its own terminal.
//
// A service with no classified kind is refused. That is the whole point of the table: adb
// can send any service name at all, and one nobody has classified has had nobody decide who
// may use it. Refusing says so in words, because the alternative is relaying a request
// nobody reviewed.
func (a serviceAuthorizer) AuthorizeService(device, service string) error {
	kind, ok := acl.KindForService(service)
	if !ok {
		reason := "this gateway defines no permission for this kind of request"
		a.record(device, service, reason)
		return fmt.Errorf("operator %q may not use %q on device %q: %s", a.op, service, device, reason)
	}
	d := a.gw.authz.Authorize(a.op, device, kind)
	if !d.Allowed {
		a.record(device, fmt.Sprintf("%s (%s)", service, kind), d.Reason)
		return fmt.Errorf("operator %q may not use %q on device %q: %s", a.op, kind, device, d.Reason)
	}
	return nil
}

// record writes a refusal where an administrator will look for it.
//
// The audit log is the durable half: an operator who asked and was stopped left a connection
// and a message, both of which disappear with the session. The gateway log is the half that
// is read while something is going wrong.
func (a serviceAuthorizer) record(device, service, reason string) {
	a.gw.audit.Record(audit.Event{
		Kind: "operator.service_refused", Actor: a.op, Device: device,
		Detail: fmt.Sprintf("%s: %s", service, reason),
	})
	a.gw.logger.Printf("operator %s refused %s on device %s: %s", a.op, service, device, reason)
}

// Compile-time proof the callback is what the protocol layer calls, so a change to either
// signature breaks the build rather than leaving the gateway wired to nothing.
var _ adbserverproto.ServiceAuthorizer = serviceAuthorizer{}
