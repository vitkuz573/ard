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
	perm, ok := KindToPermission["operator-bridge"]
	if !ok {
		t.Fatal("stream kind \"operator-bridge\" is unmapped, so every attach would be refused")
	}
	if perm != PermShell {
		t.Fatalf("operator-bridge requires %q, want %q", perm, PermShell)
	}
}

// A role that holds the device but not shell must be refused the bridge, while still
// being allowed the read-only permissions it does hold.
func TestOperatorWithoutShellIsRefusedTheBridge(t *testing.T) {
	p := policyFrom(t, `
roles:
  - name: watcher
    permissions: ["logcat"]
    grants:
      - "device-a"
    members: ["carol"]
`)
	const op = "carol"

	if d := p.Authorize(op, "device-a", "logcat"); !d.Allowed {
		t.Fatalf("logcat on a granted device was refused: %s", d.Reason)
	}
	d := p.Authorize(op, "device-a", "operator-bridge")
	if d.Allowed {
		t.Fatal("a logcat-only operator was granted the raw ADB bridge, which includes shell")
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

	if d := p.Authorize(op, "device-a", "operator-bridge"); !d.Allowed {
		t.Fatalf("a maintainer with the grant was refused: %s", d.Reason)
	}
	// Right permission, wrong device.
	if d := p.Authorize(op, "device-b", "operator-bridge"); d.Allowed {
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
	if d := p.Authorize("root-operator", "anything", "operator-bridge"); !d.Allowed {
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
		if d := p.Authorize(who, "device-a", "operator-bridge"); d.Allowed {
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
    permissions: ["logcat"]
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
