package main

// Tests for the adb server protocol adapter.
//
// These use the real acl.Policy and the real registry rather than fakes, because the whole
// point of the adapter is that an operator's visible set is computed by the same code that
// authorized the old bridge. A test with a stub filter would pass while that equivalence
// quietly broke, which is the failure this file exists to prevent.

import (
	"bufio"
	"fmt"
	"io"
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

// deviceA is entitled to alice, deviceB is not, deviceC is entitled but never connected.
const (
	deviceA = "11111111-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	deviceB = "22222222-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
	deviceC = "33333333-cccc-cccc-cccc-cccccccccccc"
)

const policyYAML = `
roles:
  - name: maintainer
    permissions: ["shell", "exec", "files", "install", "logcat"]
    grants: ["` + deviceA + `", "` + deviceC + `"]
    members: ["alice"]
  - name: stranger
    permissions: ["logcat"]
    grants: ["` + deviceB + `"]
    members: ["bob"]
`

func testGateway(t *testing.T) *gateway {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "operators.yaml")
	if err := os.WriteFile(path, []byte(policyYAML), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	policy, err := acl.Load(path)
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}

	reg, err := registry.New([]string{deviceA, deviceC}, 15000, nil)
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	// Register one entitled device. deviceC is deliberately absent so the listing has to
	// decide between "offline" and "absent", and the test pins that choice.
	openFn := func(string, string) (io.ReadWriteCloser, error) {
		return nil, fmt.Errorf("no agent session in this test")
	}
	if err := reg.Add(deviceA, "pixel", "agent-1", "127.0.0.1:1", openFn, func() error { return nil }); err != nil {
		t.Fatalf("register device: %v", err)
	}

	aud, err := audit.New(audit.Config{Path: filepath.Join(dir, "audit.log")})
	if err != nil {
		t.Fatalf("auditor: %v", err)
	}
	t.Cleanup(func() { _ = aud.Close() })

	return &gateway{reg: reg, authz: policy, audit: aud, logger: nil}
}

// ask drives one adb server protocol request through a server built from the gateway and
// returns the client's reply.
func ask(t *testing.T, g *gateway, operator string, service string) string {
	t.Helper()

	client, server := net.Pipe()
	filter := operatorFilter{gw: g, op: operator}
	srv := adbserverproto.New(filter, filter.Open, nil)
	go srv.Serve(server)

	go func() {
		fmt.Fprintf(client, "%04x%s", len(service), service)
	}()

	client.SetReadDeadline(time.Now().Add(5 * time.Second))
	// A tport to an offline device gets OKAY and then holds the pipe open relaying, so
	// reading only the first reply is the correct amount to read for every service.
	buf := make([]byte, 8192)
	n, err := client.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("%s: read reply: %v", service, err)
	}
	client.Close()
	return string(buf[:n])
}

func TestOperatorSeesOnlyItsOwnDevices(t *testing.T) {
	g := testGateway(t)
	got := ask(t, g, "alice", "host:devices")
	if !strings.HasPrefix(got, "OKAY") {
		t.Fatalf("host:devices: reply %q is not OKAY", got)
	}
	listing := got[8:]
	if !strings.Contains(listing, deviceA) {
		t.Errorf("listing %q omits the device alice is entitled to", listing)
	}
	// Entitled but not connected: it must appear as offline, not vanish.
	if !strings.Contains(listing, deviceC+"\toffline") {
		t.Errorf("listing %q omits the entitled but unconnected device, or does not mark it offline", listing)
	}
	if strings.Contains(listing, deviceB) {
		t.Errorf("listing %q leaks a device alice is not entitled to", listing)
	}
}

func TestOperatorCannotTransportToADeviceItWasNotShown(t *testing.T) {
	g := testGateway(t)
	for _, service := range []string{
		"host:tport:serial:" + deviceB,
		"host:transport:" + deviceB,
		"host-serial:" + deviceB + ":features",
	} {
		got := ask(t, g, "alice", service)
		if !strings.HasPrefix(got, "FAIL") {
			t.Errorf("%s: reply %q is not a FAIL -- a device outside alice's role was not refused", service, got)
		}
	}
}

// The other direction matters as much: an operator must not be able to reach a device that
// does not exist at all, and a serial nobody has must not resolve to something.
func TestUnknownAndEmptySerialsAreRefused(t *testing.T) {
	g := testGateway(t)
	for _, serial := range []string{"no-such-device", ""} {
		got := ask(t, g, "alice", "host:tport:serial:"+serial)
		if !strings.HasPrefix(got, "FAIL") {
			t.Errorf("serial %q: reply %q is not a FAIL", serial, got)
		}
	}
}

// An operator with no role at all sees nothing and reaches nothing. The old policy admits
// nobody by default and that property has to survive the change of mechanism.
func TestOperatorWithNoRoleSeesNothing(t *testing.T) {
	g := testGateway(t)
	got := ask(t, g, "mallory", "host:devices")
	if !strings.HasPrefix(got, "OKAY") {
		t.Fatalf("host:devices: reply %q is not OKAY", got)
	}
	if listing := got[8:]; strings.TrimSpace(listing) != "" {
		t.Errorf("an operator with no role was shown %q", listing)
	}
	if r := ask(t, g, "mallory", "host:tport:serial:"+deviceA); !strings.HasPrefix(r, "FAIL") {
		t.Errorf("an operator with no role reached a device: reply %q", r)
	}
}

// Two operators in different roles must see different things on the same gateway, or the
// filtering is not per-connection at all.
func TestFilteringIsPerOperatorNotGlobal(t *testing.T) {
	g := testGateway(t)
	alice := ask(t, g, "alice", "host:devices")
	bob := ask(t, g, "bob", "host:devices")
	if strings.Contains(alice[8:], deviceB) {
		t.Error("alice's listing contains bob's device")
	}
	if strings.Contains(bob[8:], deviceA) {
		t.Error("bob's listing contains alice's device")
	}
}

// Connecting requires a stream from the registry, which means a real agent session. The
// gateway here has none, so an entitled attach must fail with a reason rather than hang --
// an operator who is entitled to a device that is not attached should be told so.
func TestAttachToAnEntitledButUnattachedDeviceFails(t *testing.T) {
	g := testGateway(t)
	got := ask(t, g, "alice", "host:tport:serial:"+deviceC)
	if !strings.HasPrefix(got, "FAIL") {
		t.Fatalf("reply %q is not a FAIL", got)
	}
	if len(got) < 12 {
		t.Fatalf("FAIL %q carries no reason", got)
	}
}

// An unknown service must be answered, not left hanging: adb waits forever for a reply that
// does not arrive, and a silent hang is the failure mode that costs an operator an afternoon.
func TestUnknownServiceIsAnswered(t *testing.T) {
	g := testGateway(t)
	if got := ask(t, g, "alice", "host:invented-later"); !strings.HasPrefix(got, "FAIL") {
		t.Errorf("reply %q is not a FAIL", got)
	}
}

// The reply framing has to be exactly what adb expects: OKAY, a four-digit length, and a
// payload of that length. A reply that is nearly right still breaks adb's parser.
func TestReplyFramingIsExact(t *testing.T) {
	g := testGateway(t)
	// Drive the connection by hand so the framing can be inspected byte by byte.
	client, server := net.Pipe()
	filter := operatorFilter{gw: g, op: "alice"}
	srv := adbserverproto.New(filter, filter.Open, nil)
	go srv.Serve(server)

	go func() {
		fmt.Fprintf(client, "%04x%s", len("host:version"), "host:version")
	}()

	client.SetReadDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(client)
	tok := make([]byte, 4)
	if _, err := io.ReadFull(br, tok); err != nil {
		t.Fatalf("read token: %v", err)
	}
	if string(tok) != "OKAY" {
		t.Fatalf("token %q, want OKAY", tok)
	}
	if _, err := io.ReadFull(br, tok); err != nil {
		t.Fatalf("read length: %v", err)
	}
	n := 0
	for _, c := range tok {
		n = n<<4 | int(hexVal(c))
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(br, payload); err != nil {
		t.Fatalf("read payload: %v", err)
	}
	// The payload starts with its own four-digit length followed by the version line. That
	// looks like a doubled prefix and is not: a stock adb server answers host:version with
	// "0029host::version=41", where 0029 is the length of the rest of that string and is
	// part of the version format rather than of the reply envelope. Stripping it would make
	// adb print an empty version.
	if want := "0029host::version=41"; string(payload) != want {
		t.Errorf("payload %q, want exactly %q", payload, want)
	}
	client.Close()
}

func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	default:
		return 0
	}
}
