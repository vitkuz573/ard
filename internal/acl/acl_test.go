package acl

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The operator bridge carries raw ADB, and raw ADB cannot be separated by permission:
// one TCP connection carries shell, install, file transfer and port forwarding, because
// ADB multiplexes them itself. So the gate has to be the strongest interactive permission
// available.
//
// If this mapping were weakened to PermExec or PermFiles, an operator whose role
// deliberately excluded shell would reach a shell by asking for a bridge instead. That is
// the exact mistake the table exists to prevent, so it is asserted rather than assumed.
func TestOperatorBridgeRequiresShell(t *testing.T) {
	perm, ok := KindToPermission[KindOperatorBridge]
	if !ok {
		t.Fatalf("stream kind %q is unmapped, so every attach would be refused", KindOperatorBridge)
	}
	if perm != PermShell {
		t.Fatalf("%s requires %q, want %q", KindOperatorBridge, perm, PermShell)
	}
}

// The service names below are what a stock adb binary sends, captured by asking a real one to
// run each command against a real adb server. The kind each maps to is the whole permission
// model on the operator leg, so it is pinned by name rather than inferred: a misclassification
// here hands one permission to another permission's commands, which no test on the check itself
// would notice.
func TestKindForServiceMatchesWhatAdbSends(t *testing.T) {
	for _, tc := range []struct {
		service string
		kind    string
	}{
		// A shell, and the services that are a shell in another spelling. Measured, because
		// the case decides whether a log permission could exist at all: `adb logcat` arrives
		// as `adb shell logcat` with the arguments attached, and `adb shell screenrecord` as
		// itself. Neither has a name to be told apart by.
		{"shell,v2,TERM=xterm-256color,raw:whoami", KindShell},
		{"shell,v2,TERM=xterm-256color:export ANDROID_LOG_TAGS=''; exec logcat '-d'", KindShell},
		{"shell,v2,TERM=xterm-256color:export ANDROID_LOG_TAGS=''; exec logcat", KindShell},
		{"shell,v2,TERM=xterm-256color,raw:screencap -p /sdcard/s.png", KindShell},
		{"shell,v2,TERM=xterm-256color,raw:screenrecord --time-limit 1 /sdcard/v.mp4", KindShell},
		{"shell:ls /sdcard", KindShell},
		{"root:", KindShell},
		{"unroot:", KindShell},
		{"remount:", KindShell},
		// exec-out is a name of its own, and the split is real on the wire.
		{"exec:echo 'hi'", KindExec},
		// File transfer, both the sync service and the sideload one.
		{"sync:", KindFiles},
		{"sideload-host:2273746:65536", KindFiles},
		// Package install. The device is asked twice: once to read a setting, once to install.
		{"abb_exec:settings\\x00get\\x00global\\x00enable_adb_incremental_install_default", KindInstall},
		{"abb_exec:package\\x00install\\x00-r\\x00-S\\x002273746", KindInstall},
		// Every form of `adb forward`, including --no-rebind, which puts its flag in front of
		// the specification.
		{"host:forward:tcp:9930;tcp:9931", KindForward},
		{"host:forward:norebind:tcp:9932;tcp:9933", KindForward},
		{"host:killforward:tcp:9930", KindForward},
		{"host:killforward-all", KindForward},
		{"host:list-forward", KindForward},
		{"host:list-forward-all", KindForward},
		{"host-serial:ABC123:list-forward", KindForward},
		// Every form of `adb reverse`, all of which arrive on the switched transport rather
		// than as a host request.
		{"reverse:forward:tcp:9910;tcp:9911", KindReverse},
		{"reverse:killforward:tcp:9910", KindReverse},
		{"reverse:killforward-all", KindReverse},
		{"reverse:list-forward", KindReverse},
	} {
		kind, ok := KindForService(tc.service)
		if !ok {
			t.Errorf("%q was not classified, so it would be refused whatever the role holds", tc.service)
			continue
		}
		if kind != tc.kind {
			t.Errorf("%q classified as %q, want %q", tc.service, kind, tc.kind)
		}
	}
}

// A service nobody has classified is refused, and the reason says so. adb can send any name at
// all on a switched transport, so this is the check that stops a feature reaching a device
// without anyone having decided who may use it.
func TestKindForServiceRefusesWhatItDoesNotKnow(t *testing.T) {
	for _, service := range []string{
		"",
		"host:version",
		"host:transport:ABC123",
		"host:devices",
		"host-serial:ABC123:get-state",
		"jdwp",
		"track-devices:",
		// A near miss is worse than a miss: it is a name that looks classified.
		"reverse:invented:later",
		"host:forwardish:tcp:1;tcp:2",
		"reverseforward:tcp:1;tcp:2",
	} {
		if kind, ok := KindForService(service); ok {
			t.Errorf("%q was classified as %q; a service with no permission would be served", service, kind)
		}
	}
}

// Every kind the classifier can produce must have a permission, and every permission must be
// reachable from some kind. Either gap is a permission that cannot be granted on the operator
// leg or a kind that is refused for everybody, and both are the same class of bug: the policy
// vocabulary and the requests it governs have drifted apart.
func TestTheKindTableAndThePermissionsAgreeBothWays(t *testing.T) {
	// One real service name per kind, so the walk is over requests rather than over
	// synthesised strings. A probe built by concatenating a kind name would pass while the
	// classifier read a different spelling, which is the whole risk here.
	reachedBy := map[string]string{}
	for _, service := range []string{
		"shell,v2,TERM=xterm-256color,raw:whoami",
		"exec:echo 'hi'",
		"sync:",
		"abb_exec:package\\x00install\\x00-r\\x00-S\\x002273746",
		"host:forward:tcp:9930;tcp:9931",
		"reverse:forward:tcp:9910;tcp:9911",
	} {
		kind, ok := KindForService(service)
		if !ok {
			t.Fatalf("%q was not classified", service)
		}
		if _, dup := reachedBy[kind]; dup {
			t.Errorf("kind %q was reached by both %q and %q; one kind is one capability",
				kind, reachedBy[kind], service)
		}
		reachedBy[kind] = service
	}

	// Every kind with a permission is decided somewhere: by a service name, or at the
	// transport switch, which happens before a service is named and is the one kind that is
	// not a service.
	atSwitch := map[string]bool{KindOperatorBridge: true}
	for kind := range KindToPermission {
		if _, ok := reachedBy[kind]; !ok && !atSwitch[kind] {
			t.Errorf("kind %q requires a permission but no request ever reaches it", kind)
		}
	}
	// And every declared permission is required by some kind, so none is a name that can be
	// written into a policy file and never consulted. The list below is the whole declared
	// vocabulary, and it is compared with the table in both directions: a permission added
	// to the declarations without a kind behind it, and a permission left in this list that
	// the table has dropped, are both failures rather than something a reader has to notice.
	declared := []Permission{
		PermShell, PermExec, PermFiles, PermInstall, PermForward, PermReverse,
	}
	required := map[Permission]bool{}
	for _, perm := range KindToPermission {
		required[perm] = true
	}
	seen := map[Permission]bool{}
	for _, perm := range declared {
		if seen[perm] {
			t.Errorf("permission %q is listed twice in the declared vocabulary", perm)
		}
		seen[perm] = true
		if !required[perm] {
			t.Errorf("permission %q is declared but no kind requires it", perm)
		}
	}
	for perm := range required {
		if perm != PermAll && !seen[perm] {
			t.Errorf("a kind requires permission %q, which is absent from the declared vocabulary", perm)
		}
	}
}

// The permission a kind names has to be one a policy file may hold, or the role that holds it
// cannot be loaded at all.
func TestEveryKindRequiresAKnownPermission(t *testing.T) {
	for kind, perm := range KindToPermission {
		p := policyFrom(t, `
roles:
  - name: probe
    permissions: ["`+string(perm)+`"]
    grants: ["*"]
    members: ["alice"]
`)
		if d := p.Authorize("alice", "device-a", kind); !d.Allowed {
			t.Errorf("kind %q requires %q, which a role cannot hold: %s", kind, perm, d.Reason)
		}
	}
}

// A role that holds the device but not shell must be refused the bridge, while still
// being allowed the file transfers it does hold.
func TestOperatorWithoutShellIsRefusedTheBridge(t *testing.T) {
	p := policyFrom(t, `
roles:
  - name: watcher
    permissions: ["files"]
    grants:
      - "device-a"
    members: ["carol"]
`)
	const op = "carol"

	if d := p.Authorize(op, "device-a", KindFiles); !d.Allowed {
		t.Fatalf("files on a granted device was refused: %s", d.Reason)
	}
	d := p.Authorize(op, "device-a", KindOperatorBridge)
	if d.Allowed {
		t.Fatal("a files-only operator was granted the raw ADB bridge, which includes shell")
	}
	// The refusal has to say why, because this is the message an operator sees.
	if !strings.Contains(d.Reason, "shell") {
		t.Errorf("refusal does not name the missing permission: %s", d.Reason)
	}
}

// Granting a device is not enough on its own, and neither is holding shell without the
// grant. Both directions have to fail closed.
func TestBridgeNeedsBothPermissionAndGrant(t *testing.T) {
	p := policyFrom(t, `
roles:
  - name: maintainer
    permissions: ["shell", "exec"]
    grants:
      - "device-a"
    members: ["alice"]
`)
	const op = "alice"

	if d := p.Authorize(op, "device-a", KindOperatorBridge); !d.Allowed {
		t.Fatalf("a maintainer with the grant was refused: %s", d.Reason)
	}
	// Right permission, wrong device.
	if d := p.Authorize(op, "device-b", KindOperatorBridge); d.Allowed {
		t.Fatal("the bridge was granted for a device outside the role's grants")
	}
}

// The wildcard role is the break-glass case and must still reach the bridge.
func TestWildcardRoleReachesTheBridge(t *testing.T) {
	p := policyFrom(t, `
roles:
  - name: emergency
    permissions: ["*"]
    grants: ["*"]
    members: ["root-operator"]
`)
	if d := p.Authorize("root-operator", "anything", KindOperatorBridge); !d.Allowed {
		t.Fatalf("the wildcard role was refused: %s", d.Reason)
	}
}

// A stream kind nobody has classified is refused rather than allowed by default, so a new
// feature cannot ship without someone deciding who may use it.
func TestUnmappedKindIsRefused(t *testing.T) {
	p := policyFrom(t, `
roles:
  - name: emergency
    permissions: ["*"]
    grants: ["*"]
    members: ["root-operator"]
`)
	d := p.Authorize("root-operator", "device-a", "a-kind-nobody-classified")
	if d.Allowed {
		t.Fatal("an unmapped stream kind was allowed")
	}
	if !strings.Contains(d.Reason, "no defined permission") {
		t.Errorf("unhelpful reason: %s", d.Reason)
	}
}

// The policy the repository ships is the policy an operator's gateway loads, so it is
// checked against the same loader the gateway uses rather than read as documentation.
//
// The vocabulary and this file drift apart silently: a permission removed from the
// declarations stays in a role here, the file still reads like a policy, and the only
// sign is a gateway that will not start with a message naming a role nobody configured on
// purpose. It stops every deployment, which is the right outcome, but it is discovered on
// the machine holding the CA keys rather than in a test.
func TestTheShippedPolicyLoads(t *testing.T) {
	path := filepath.Join("..", "..", "deploy", "operators.yaml")
	if _, err := Load(path); err != nil {
		t.Fatalf("the shipped policy does not load, so no gateway would start with it: %v", err)
	}
}

// Every permission the shipped policy hands out has to be one the code consults, and the
// kind behind it has to be a request a real adb sends. A role naming a permission the
// gateway loads but never asks about would pass the loader and grant something unusable,
// which reads in the policy file as a capability nobody has.
func TestEveryPermissionTheShippedPolicyGrantsIsConsulted(t *testing.T) {
	required := map[Permission]bool{}
	for _, perm := range KindToPermission {
		required[perm] = true
	}
	p, err := Load(filepath.Join("..", "..", "deploy", "operators.yaml"))
	if err != nil {
		t.Fatalf("load shipped policy: %v", err)
	}
	for _, role := range p.roles() {
		for _, perm := range role.Permissions {
			// The wildcard is the exception, and it is a real exception rather than a
			// special case in this check: Authorize compares a role's permissions against
			// whatever a kind requires, so a wildcard is consulted without a kind of its own.
			if perm != PermAll && !required[perm] {
				t.Errorf("role %q grants %q, which no kind ever requires", role.Name, perm)
			}
		}
	}
}

// The loader's vocabulary and the kind table have to be the same set, and this is checked
// against the loader's own set rather than against a list written here.
//
// A permission added to the declarations but left out of the kind table is loadable and
// unused: a role file may grant it, every request is authorized without it, and the policy
// reads as though something is being withheld. That is the failure this asserts against, and
// deriving both halves from the same source is what makes the assertion about the code rather
// than about this test's idea of it.
func TestTheLoadableVocabularyIsExactlyWhatSomeKindRequires(t *testing.T) {
	loadable := loadablePermissions()
	required := map[Permission]bool{}
	for _, perm := range KindToPermission {
		required[perm] = true
	}
	for perm := range loadable {
		if perm != PermAll && !required[perm] {
			t.Errorf("permission %q can be granted by a policy file but no kind ever requires it", perm)
		}
	}
	for perm := range required {
		if !loadable[perm] {
			t.Errorf("a kind requires permission %q, which a policy file cannot grant", perm)
		}
	}
}

func policyFrom(t *testing.T, yaml string) *Policy {
	t.Helper()
	path := filepath.Join(t.TempDir(), "operators.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	p, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return p
}

// A role with no members grants nobody. This is the shape the shipped policy file had, and
// it parsed, loaded and refused every operator -- which reads as deliberate until you
// notice that nobody can ever be admitted.
func TestRoleWithoutMembersAdmitsNobody(t *testing.T) {
	p := policyFrom(t, `
roles:
  - name: maintainer
    permissions: ["shell"]
    grants: ["*"]
`)
	if got := p.Members(); len(got) != 0 {
		t.Fatalf("a role with no members admitted %v", got)
	}
	for _, who := range []string{"maintainer", "alice", ""} {
		if d := p.Authorize(who, "device-a", KindOperatorBridge); d.Allowed {
			t.Errorf("operator %q was admitted by a policy that names nobody", who)
		}
	}
	// And the role itself must still be visible, so the mistake is diagnosable.
	if roles := p.Roles(); len(roles) != 1 || roles[0] != "maintainer" {
		t.Errorf("Roles() = %v, want [maintainer]", roles)
	}
}

// Two roles claiming the same operator is refused rather than resolved by file order.
func TestOperatorInTwoRolesIsRefused(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "operators.yaml")
	body := `
roles:
  - name: a
    permissions: ["shell"]
    grants: ["*"]
    members: ["dana"]
  - name: b
    permissions: ["files"]
    grants: ["*"]
    members: ["dana"]
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("an operator listed in two roles was accepted")
	} else if !strings.Contains(err.Error(), "both role") {
		t.Errorf("unhelpful error: %v", err)
	}
}

// A member list is what makes the difference between a policy that works and one that
// silently admits nobody, so it is worth asserting the wiring directly.
func TestMembersAreIndexed(t *testing.T) {
	p := policyFrom(t, `
roles:
  - name: maintainer
    permissions: ["shell"]
    grants: ["device-a"]
    members: ["alice", "bob"]
`)
	got := p.Members()
	if len(got) != 2 || got[0] != "alice" || got[1] != "bob" {
		t.Fatalf("Members() = %v, want [alice bob]", got)
	}
	r, ok := p.Describe("alice")
	if !ok || r.Name != "maintainer" {
		t.Fatalf("Describe(alice) = %+v, %v", r, ok)
	}
}
