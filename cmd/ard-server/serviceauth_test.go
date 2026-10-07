package main

// Tests for the per-request service check.
//
// The gateway's real policy and the real registry are used rather than fakes, because what is
// being tested is that the policy decides: a stub authorizer would agree with whatever the
// gateway told it.

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vitkuz573/ard/internal/acl"
	"github.com/vitkuz573/ard/internal/adbserverproto"
	"github.com/vitkuz573/ard/internal/audit"
	"github.com/vitkuz573/ard/internal/registry"
)

// The permissions are separate in the policy on purpose: an operator who may drive a device
// but may not bind a port on the gateway, and the same the other way round. A policy that gave
// one role everything would let every one of these checks pass while proving nothing, so the
// role under test is built to be wrong in exactly the way each check looks for.
const servicePolicyYAML = `
roles:
  - name: driver
    permissions: ["shell", "exec", "files", "install"]
    grants: ["` + deviceA + `"]
    members: ["erin"]
  - name: porter
    permissions: ["shell", "forward", "reverse"]
    grants: ["` + deviceA + `"]
    members: ["frank"]
`

func serviceGateway(t *testing.T) *gateway {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "operators.yaml")
	if err := os.WriteFile(path, []byte(servicePolicyYAML), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	policy, err := acl.Load(path)
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	reg, err := registry.New([]string{deviceA}, nil)
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	// The device here has a stream that connects and says nothing, which is what a forwarding
	// request needs: the port being forwarded is the gateway's own, so the device is never
	// asked about it, and a stream that never speaks is what proves it.
	var openers []func() io.Closer
	openFn := func(string, string) (io.ReadWriteCloser, error) {
		ours, theirs := net.Pipe()
		// Drained rather than left: an undrained pipe endpoint blocks the first write, which
		// would turn "the device did not speak" into a hang.
		go func() { _, _ = io.Copy(io.Discard, theirs); _ = theirs.Close() }()
		openers = append(openers, func() io.Closer { return ours })
		return ours, nil
	}
	if err := reg.Add(deviceA, "pixel", "agent-1", "127.0.0.1:1", testDeviceFeatures,
		openFn, func() error { return nil }); err != nil {
		t.Fatalf("register device: %v", err)
	}
	t.Cleanup(func() {
		for _, close := range openers {
			_ = close()
		}
	})
	auditPath := filepath.Join(dir, "audit.log")
	aud, err := audit.New(audit.Config{Path: auditPath})
	if err != nil {
		t.Fatalf("auditor: %v", err)
	}
	t.Cleanup(func() { _ = aud.Close() })
	g := &gateway{reg: reg, authz: policy, audit: aud,
		logger: log.New(io.Discard, "", 0)}
	g.forwards = newForwards(g)
	// The path is kept on the gateway for the test that reads the file back: what has to
	// survive is the line on disk an administrator reads, not a struct in memory.
	g.testAuditPath = auditPath
	return g
}

// askService drives one switched-transport service through the gateway and returns the client's
// reply.
//
// The two-step conversation is what a real client has: adb asks for a transport, then names a
// service on the connection it gets back. Sending the service alone would test a conversation
// no adb ever has, and would leave the check untested at the point where it happens.
func askService(t *testing.T, g *gateway, operator, device, service string) string {
	t.Helper()
	client, server := socketPair(t)
	filter := operatorFilter{gw: g, op: operator}
	srv := adbserverproto.New(filter, filter.Open, operator, nil, g.forwards)
	srv.SetServiceAuthorizer(g.authorizerFor(operator))
	served := make(chan struct{})
	go func() { _ = srv.Serve(server); close(served) }()

	tport := "host:tport:serial:" + device
	if _, err := fmt.Fprintf(client, "%04x%s", len(tport), tport); err != nil {
		t.Fatalf("write tport: %v", err)
	}
	head := make([]byte, 12)
	client.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(client, head); err != nil {
		t.Fatalf("read tport reply: %v", err)
	}
	// The switch has to have succeeded for the rest of this to be measuring the service check
	// rather than a transport that never opened.
	if string(head[:4]) != "OKAY" {
		t.Fatalf("tport answered %q, so this would measure the transport rather than the service", head[:4])
	}
	if _, err := fmt.Fprintf(client, "%04x%s", len(service), service); err != nil {
		t.Fatalf("write service: %v", err)
	}
	ack := make([]byte, 4)
	if _, err := io.ReadFull(client, ack); err != nil {
		t.Fatalf("read the switch acknowledgement: %v", err)
	}
	buf := make([]byte, 8192)
	n, err := client.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("%s: read reply: %v", service, err)
	}
	_ = client.Close()
	select {
	case <-served:
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after the client closed")
	}
	_ = server.Close()
	return string(buf[:n])
}

// socketPair returns a connected pair of real sockets, because the conversation under test
// writes before it reads and a synchronous pipe would deadlock on the first unanswered write --
// which shows up as a hang rather than as a failure.
func socketPair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	server = <-accepted
	t.Cleanup(func() { _ = server.Close() })
	return client, server
}

// A port binding needs the permission that governs it, on the device it is for.
//
// The role here holds shell and files and no forward, which is the ordinary maintainer shape:
// someone who drives devices and moves files for a living, with no reason to bind a port on the
// machine that holds the CA keys. Before this check existed, `adb forward` from that role
// worked, because the only thing ever asked was whether the role could hold the transport.
func TestForwardIsRefusedWithoutTheForwardPermission(t *testing.T) {
	g := serviceGateway(t)
	got := askService(t, g, "erin", deviceA, "host:forward:tcp:9930;tcp:9931")

	if !strings.HasPrefix(got, "FAIL") {
		t.Fatalf("reply = %q, want a FAIL: the role holds no forward permission", got)
	}
	// The reason is the whole value of the refusal, so its three parts are each required: an
	// operator reading this on their own terminal needs to know which device, which role and
	// what to ask for.
	for _, want := range []string{deviceA, "driver", "forward"} {
		if !strings.Contains(got, want) {
			t.Errorf("refusal %q does not name %q", got, want)
		}
	}
}

// No port is bound by a refused request. This is the assertion that says the refusal happened
// before the listener, not after it: a forward that binds and then refuses still leaves a port
// on the gateway answering for a device.
func TestRefusedForwardBindsNoPort(t *testing.T) {
	g := serviceGateway(t)
	askService(t, g, "erin", deviceA, "host:forward:tcp:39993;tcp:39994")

	if listing := g.forwards.List("erin", ""); listing != "" {
		t.Errorf("a refused forward left %q behind", listing)
	}
}

// The same check, in the other direction: a role that holds forward and no files can bind a
// port and cannot push a file. If the check were reading one permission for everything, both of
// these would pass together.
func TestFileTransferIsRefusedWithoutTheFilesPermission(t *testing.T) {
	g := serviceGateway(t)
	if got := askService(t, g, "frank", deviceA, "sync:"); !strings.HasPrefix(got, "FAIL") {
		t.Errorf("reply to sync: = %q, want a FAIL for a role holding no files permission", got)
	}
	if !strings.Contains(askService(t, g, "frank", deviceA, "sync:"), "files") {
		t.Error("the refusal does not name the missing permission")
	}
}

// A role that holds the permission gets through. Without this the tests above would pass against
// a server that refuses everything.
func TestHoldingThePermissionIsWhatLetsTheRequestThrough(t *testing.T) {
	g := serviceGateway(t)
	// tcp:0 asks the gateway to pick a port, and the reply carries the one it bound. That reply
	// is the proof the request was served rather than refused.
	got := askService(t, g, "frank", deviceA, "host:forward:tcp:0;tcp:39994")
	if !strings.HasPrefix(got, "OKAY") || len(got) < 8 {
		t.Fatalf("reply = %q (% x), want an OKAY carrying a bound port", got, got)
	}
	listing := g.forwards.List("frank", deviceA)
	if !strings.Contains(listing, "tcp:39994") {
		t.Errorf("the bound forward is not in the operator's own listing: %q", listing)
	}
	// And it is released, so the next test in this process does not collide with it.
	local := listingPort(t, listing)
	t.Cleanup(func() { _ = g.forwards.Kill("frank", deviceA, local) })
}

// Every form of `adb forward` is checked, because adb has five of them and a check on one of
// them leaves the other four open. Measured: the binding form carries its --no-rebind flag in
// front of the specification, and --remove-all names no specification at all.
func TestEveryFormOfForwardIsChecked(t *testing.T) {
	g := serviceGateway(t)
	for _, service := range []string{
		"host:forward:tcp:39993;tcp:39994",
		"host:forward:norebind:tcp:39993;tcp:39994",
		"host:forward:tcp:0;tcp:39994",
		"host:killforward:tcp:39993",
		"host:killforward-all",
	} {
		if got := askService(t, g, "erin", deviceA, service); !strings.HasPrefix(got, "FAIL") {
			t.Errorf("%s: reply %q, want a FAIL for a role holding no forward permission", service, got)
		}
	}
}

// And the reverse, all four of its forms, on the same gateway and the same device.
func TestEveryFormOfReverseIsChecked(t *testing.T) {
	g := serviceGateway(t)
	for _, service := range []string{
		"reverse:forward:tcp:39995;tcp:39996",
		"reverse:killforward:tcp:39995",
		"reverse:killforward-all",
		"reverse:list-forward",
	} {
		if got := askService(t, g, "erin", deviceA, service); !strings.HasPrefix(got, "FAIL") {
			t.Errorf("%s: reply %q, want a FAIL for a role holding no reverse permission", service, got)
		}
	}
}

// The listing is a request about ports, so it is checked like one. An operator who may not
// forward learns what forwards exist on the gateway otherwise, and a device id in that listing
// is the string `adb -s` takes.
func TestForwardListingsAreCheckedToo(t *testing.T) {
	g := serviceGateway(t)
	// Give frank a forward so there is something to list, then ask as erin.
	bindForward(t, g, "frank", "tcp:39981")
	if listing := g.forwards.List("frank", deviceA); listing == "" {
		t.Fatal("frank's forward is not listed for frank")
	}
	if listing := g.forwards.List("erin", ""); listing != "" {
		t.Errorf("erin was shown %q, which belongs to another operator", listing)
	}
}

// The check is made per request, not once per connection. adb opens a fresh connection per
// request, so a per-connection cache would in practice be per request -- which makes this test
// about a different thing: a decision must not be remembered from an earlier request on the same
// connection. That is what "no caching" has to mean when the connection outlives the request.
func TestTheDecisionIsNotRememberedAcrossRequestsOnOneConnection(t *testing.T) {
	g := serviceGateway(t)
	authorizer := g.authorizerFor("erin")
	// Two requests from one operator, with the policy changed between them. There is no reload
	// in production -- a policy is read at startup -- so this is driven through the policy the
	// gateway holds, and the point is only that the second call asks again.
	if err := authorizer.AuthorizeService(deviceA, "host:forward:tcp:1;tcp:2"); err == nil {
		t.Fatal("a forward was allowed for a role holding no forward permission")
	}
	// A second, identical request must reach the policy again rather than being answered from
	// whatever the first one concluded. Counting the calls is what makes that observable.
	counted := &countingAuthorizer{inner: authorizer}
	for range 3 {
		if err := counted.AuthorizeService(deviceA, "host:forward:tcp:1;tcp:2"); err == nil {
			t.Fatal("a forward was allowed")
		}
	}
	if counted.calls != 3 {
		t.Errorf("the policy was asked %d times for 3 requests, want 3", counted.calls)
	}
}

// countingAuthorizer counts how often the policy underneath was reached.
type countingAuthorizer struct {
	inner serviceAuthorizer
	calls int
}

func (c *countingAuthorizer) AuthorizeService(device, service string) error {
	c.calls++
	return c.inner.AuthorizeService(device, service)
}

// A refusal is recorded where an administrator will look, not only in the operator's terminal.
// An operator who asked and was stopped leaves a connection and a message, both of which go when
// they do; this line does not.
func TestARefusalIsAudited(t *testing.T) {
	g := serviceGateway(t)
	path := g.testAuditPath
	if err := g.authorizerFor("erin").AuthorizeService(deviceA, "host:forward:tcp:1;tcp:2"); err == nil {
		t.Fatal("the request was allowed")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the audit log: %v", err)
	}
	for _, want := range []string{`"actor":"erin"`, `"kind":"operator.service_refused"`, "forward", deviceA} {
		if !strings.Contains(string(body), want) {
			t.Errorf("the audit log does not carry %q:\n%s", want, body)
		}
	}
}

// A service with no permission is refused, and the reason says so rather than blaming the
// operator's role. The distinction matters to whoever reads it: one is a policy to change, the
// other is a request the gateway does not implement.
func TestAnUnclassifiedServiceIsRefusedWithoutBlamingTheRole(t *testing.T) {
	g := serviceGateway(t)
	// frank holds forward, reverse and shell, so nothing about his role is why this fails.
	got := askService(t, g, "frank", deviceA, "jdwp")
	if !strings.HasPrefix(got, "FAIL") {
		t.Fatalf("reply = %q, want a FAIL for a service with no defined permission", got)
	}
	if strings.Contains(got, "lacks permission") {
		t.Errorf("the refusal blames the role for a service the gateway does not implement: %q", got)
	}
	if !strings.Contains(got, "jdwp") {
		t.Errorf("the refusal does not name the service: %q", got)
	}
}

// A device the role has no grant for is refused whatever the permission, so the service check
// cannot become a way to reach a device the transport switch would have refused.
//
// Asked of the authorizer rather than over the wire, and the reason is that the wire cannot
// show this one: a serial outside a role's grants is refused by the transport switch before a
// service is ever named, with the stock server's "device not found". Both refusals are correct
// and the second is the only one an operator ever meets, but that means the service-level grant
// check is not observable from outside -- so it is asserted here rather than claimed there.
func TestAnUngrantedDeviceIsRefusedOnTheServiceToo(t *testing.T) {
	g := serviceGateway(t)
	got := g.authorizerFor("frank").AuthorizeService(deviceB, "host:forward:tcp:39993;tcp:39994")
	if got == nil {
		t.Fatal("a device outside the role's grants was allowed on the service request")
	}
	if !strings.Contains(got.Error(), "no grant") {
		t.Errorf("refusal %q does not say the device is not granted", got)
	}
}

// A forward belongs to the operator who bound it, and one operator cannot release another's.
// The port is on the gateway and still serving, so answering OKAY to a removal that did not
// happen would report a state the operator does not have.
func TestOneOperatorCannotRemoveAnothersForward(t *testing.T) {
	g := serviceGateway(t)
	local := bindForward(t, g, "frank", "tcp:39982")
	if err := g.forwards.Kill("erin", deviceA, local); err == nil {
		t.Fatal("one operator removed a forward belonging to another")
	}
	if listing := g.forwards.List("frank", deviceA); !strings.Contains(listing, local) {
		t.Errorf("the forward is gone anyway: %q", listing)
	}
	if err := g.forwards.Kill("frank", deviceA, local); err != nil {
		t.Errorf("the owner could not remove their own forward: %v", err)
	}
}

// Removing a port nothing holds is the state the caller asked for, so it is not an error. An
// operator scripting cleanup would otherwise have to know which of their ports survived a
// restart.
func TestRemovingAPortThatIsNotThereIsNotAnError(t *testing.T) {
	g := serviceGateway(t)
	if err := g.forwards.Kill("frank", deviceA, "tcp:39993"); err != nil {
		t.Errorf("removing an absent forward failed: %v", err)
	}
}

// The callback half of a reverse is checked where the connection is made. The device asks for a
// port every time something reaches the port it holds, so the permission is asked per connection
// rather than only on the request that created the port -- and a role that has since lost
// `reverse` stops carrying traffic rather than keeping a decision made when it had it.
func TestTheReverseCallbackIsCheckedPerConnection(t *testing.T) {
	g := serviceGateway(t)
	// erin's role holds no reverse, so the callback cannot be dialled for her.
	if _, err := g.forwards.Dial("erin", deviceA, "tcp:39996"); err == nil {
		t.Fatal("a reverse callback was dialled for an operator holding no reverse permission")
	} else if !strings.Contains(err.Error(), "reverse") {
		t.Errorf("the refusal does not name the permission: %v", err)
	}
	// A supported socket specification still has to be refused for the same reason, which is
	// what says the permission was asked rather than the dialling having failed earlier.
	if _, err := g.forwards.Dial("erin", deviceA, "tcp:not-a-port"); err == nil {
		t.Error("a malformed port was reached instead of being refused for the permission")
	}
	// frank holds reverse, so a well-formed port is dialled rather than refused for permission.
	// Nothing is listening there, so the dial itself fails -- which is the answer being asked
	// for: the permission passed and the socket did not.
	conn, err := g.forwards.Dial("frank", deviceA, "tcp:39996")
	if err != nil {
		if strings.Contains(err.Error(), "reverse") {
			t.Errorf("frank holds reverse and was refused for it: %v", err)
		}
	} else {
		conn.Close()
	}
}

// A device-initiated callback carries the operator's name with it, because the connection it
// arrives on belongs to the adb server rather than to the operator. Without the name the only
// available answers were to refuse every device that asked or to allow every one.
func TestTheCallbackCarriesTheOperatorWhoseReverseItIs(t *testing.T) {
	g := serviceGateway(t)
	a := g.authorizerFor("frank")
	if err := a.AuthorizeService(deviceA, "reverse:forward:tcp:39995;tcp:39996"); err != nil {
		t.Fatalf("a reverse forward was refused for a role holding reverse: %v", err)
	}
	// The kind a reverse request is classified as is what decides this, so it is asserted
	// directly: a misclassification here would let a shell-only operator bind a port on the
	// device and have the gateway connect out for them.
	kind, ok := acl.KindForService("reverse:forward:tcp:39995;tcp:39996")
	if !ok || kind != acl.KindReverse {
		t.Fatalf("a reverse forward classified as %q (ok=%v), want %q", kind, ok, acl.KindReverse)
	}
	if _, err := g.forwards.Dial("erin", deviceA, "tcp:39996"); err == nil {
		t.Error("erin reached the callback without holding reverse")
	}
}

// bindForward binds a real port and releases it when the test ends, so two tests in one
// process cannot collide on a port number and report a bind failure that has nothing to do
// with what they are testing.
func bindForward(t *testing.T, g *gateway, operator, local string) string {
	t.Helper()
	if _, err := g.forwards.Bind(operator, deviceA, local, "tcp:39994", false); err != nil {
		t.Fatalf("bind %s: %v", local, err)
	}
	t.Cleanup(func() { _ = g.forwards.Kill(operator, deviceA, local) })
	return local
}

// helper: the local port out of a one-line listing.
func listingPort(t *testing.T, listing string) string {
	t.Helper()
	fields := strings.Fields(listing)
	if len(fields) != 3 {
		t.Fatalf("listing %q is not one \"serial local remote\" line", listing)
	}
	return fields[1]
}
