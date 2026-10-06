// Package acl decides whether an operator may act on a device.
//
// Two ideas are kept separate on purpose:
//
//   - a permission answers "may this operator open a shell at all"
//   - a grant answers "may this operator touch this specific device"
//
// Collapsing them into one check is how single-tenant tools grow into
// single-operator tools: every new check then needs a new role, and the operator
// list stops being a policy and becomes a list of exceptions.
package acl

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Permission is a capability an operator role may hold.
type Permission string

const (
	// PermShell allows an interactive shell on a device.
	PermShell Permission = "shell"
	// PermExec allows one-shot commands.
	PermExec Permission = "exec"
	// PermFiles allows push and pull.
	PermFiles Permission = "files"
	// PermInstall allows installing and uninstalling packages.
	PermInstall Permission = "install"
	// PermLogcat allows reading the device log.
	PermLogcat Permission = "logcat"
	// PermScreen allows viewing the screen and injecting input.
	PermScreen Permission = "screen"
	// PermForward allows adb port forwarding. This is the sensitive one: a forward
	// can expose a device port to anyone who can reach the gateway, so it is a
	// separate permission and is off by default.
	PermForward Permission = "forward"
	// PermReverse allows adb reverse forwarding, device to gateway.
	PermReverse Permission = "reverse"
)

// PermAll is the wildcard permission, granting every capability a role has
// grants for.
//
// It exists so a small deployment is not forced to enumerate permissions, and it is
// deliberately not the default: a role that lists nothing gets nothing.
const PermAll Permission = "*"

// KindToPermission maps a stream kind to the permission it requires, so the
// check cannot be forgotten at a call site.
var KindToPermission = map[string]Permission{
	"shell":   PermShell,
	"exec":    PermExec,
	"logcat":  PermLogcat,
	"files":   PermFiles,
	"raw-adb": PermExec,
	"adb":     PermExec,
	// A raw ADB bridge for an operator necessarily includes shell, install, file
	// transfer and port forwarding, because all of them are multiplexed over one
	// TCP connection by ADB itself. Gating it on anything weaker than PermShell
	// would hand shell to an operator whose role deliberately excluded it -- the
	// classic mistake of treating a protocol as if it were separable.
	//
	// So the gate is PermShell, and the honest consequence is documented rather than
	// papered over: holding "shell" on a device means holding adb on that device.
	"operator-bridge": PermShell,
	"screen":          PermScreen,
	"forward":         PermForward,
	"reverse":         PermReverse,
}

// role is one named set of permissions, and the set of operators who hold it.
type role struct {
	Name        string       `yaml:"name"`
	Permissions []Permission `yaml:"permissions"`
	// Grants are device UUIDs, or "*" for every device. Prefer explicit UUIDs:
	// a wildcard in a role that also grants shell is a fleet-wide remote shell.
	Grants []string `yaml:"grants"`
	// Members are the certificate common names that hold this role.
	//
	// This is what connects a role to a person. Without it a policy is unreachable: the
	// authorization check is given the common name out of the TLS handshake and looks
	// that name up, so a file of roles with nobody in them grants exactly nothing. A
	// policy that parses, loads and refuses every operator is the worst kind of broken,
	// because it reads as deliberate.
	Members []string `yaml:"members"`
}

// file is the on-disk shape.
type file struct {
	Roles []role `yaml:"roles"`
}

// Policy is a loaded authorization policy.
//
// Two indexes, because two lookups are needed and conflating them is the bug this
// replaced: byRole answers "what does this role look like", and byOperator answers "what
// may this certificate's common name do". They were one map, which meant a role had to
// be *named* after an operator to have any effect.
type Policy struct {
	byRole     map[string]role
	byOperator map[string]role
}

// Load reads and validates a policy file.
func Load(path string) (*Policy, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("acl: read %s: %w", path, err)
	}
	var f file
	if err := yaml.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("acl: parse %s: %w", path, err)
	}
	if len(f.Roles) == 0 {
		return nil, fmt.Errorf("acl: %s defines no roles; refusing to run with no policy", path)
	}
	p := &Policy{
		byRole:     make(map[string]role, len(f.Roles)),
		byOperator: make(map[string]role),
	}
	known := map[Permission]bool{
		PermAll:   true,
		PermShell: true, PermExec: true, PermFiles: true, PermInstall: true,
		PermLogcat: true, PermScreen: true, PermForward: true, PermReverse: true,
	}
	for _, r := range f.Roles {
		if r.Name == "" {
			return nil, fmt.Errorf("acl: %s has a role with no name", path)
		}
		if _, dup := p.byRole[r.Name]; dup {
			return nil, fmt.Errorf("acl: %s defines role %q twice", path, r.Name)
		}
		for _, perm := range r.Permissions {
			if !known[perm] {
				// An unknown permission silently ignored would look like a working
				// policy while granting less than the author intended.
				return nil, fmt.Errorf("acl: role %q has unknown permission %q", r.Name, perm)
			}
		}
		p.byRole[r.Name] = r
		for _, member := range r.Members {
			// An operator in two roles is ambiguous, and resolving it by file order
			// would mean the answer depends on a reformat. Refuse instead.
			if prev, dup := p.byOperator[member]; dup {
				return nil, fmt.Errorf("acl: operator %q is in both role %q and role %q", member, prev.Name, r.Name)
			}
			p.byOperator[member] = r
		}
	}
	return p, nil
}

// Decision is the outcome of an authorization check.
type Decision struct {
	Allowed bool
	Role    string
	Reason  string
}

// Authorize checks an operator against a device and stream kind.
//
// operator must be the account name from the certificate, never a value supplied
// by the client over the wire.
func (p *Policy) Authorize(operator, device, kind string) Decision {
	perm, ok := KindToPermission[kind]
	if !ok {
		// An unmapped kind is refused rather than allowed by default. New kinds
		// must be classified deliberately, or a feature could ship without anyone
		// deciding who may use it.
		return Decision{Reason: fmt.Sprintf("stream kind %q has no defined permission", kind)}
	}
	r, ok := p.byOperator[operator]
	if !ok {
		return Decision{Reason: fmt.Sprintf("operator %q has no role", operator)}
	}
	hasPerm := false
	// The required permission is `required`. The loop variable used to be called `perm`
	// as well, which shadowed it -- and `perm == perm` is always true, so every role
	// holding any permission at all passed every permission check. The permission model
	// was decorative: a logcat-only role reached shell, install and everything else.
	required := perm
	for _, held := range r.Permissions {
		if held == PermAll || held == required {
			hasPerm = true
			break
		}
	}
	if !hasPerm {
		return Decision{Role: r.Name, Reason: fmt.Sprintf("role %q lacks permission %q", r.Name, required)}
	}
	if !r.allows(device) {
		return Decision{Role: r.Name, Reason: fmt.Sprintf("role %q has no grant for device %q", r.Name, device)}
	}
	return Decision{Allowed: true, Role: r.Name}
}

func (r role) allows(device string) bool {
	for _, g := range r.Grants {
		if g == "*" || g == device {
			return true
		}
		// A trailing "*" grants a prefix, e.g. "lab-*".
		if strings.HasSuffix(g, "*") && strings.HasPrefix(device, strings.TrimSuffix(g, "*")) {
			return true
		}
	}
	return false
}

// Roles lists role names, for diagnostics.
func (p *Policy) Roles() []string {
	out := make([]string, 0, len(p.byRole))
	for name := range p.byRole {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// CanSee reports whether an operator may touch a device at all, whatever the action.
//
// A read-only operator sees a device they legitimately hold logcat for. They cannot drive
// anything, but they can see that their access exists -- and being able to see is what makes
// a denial explicable instead of mysterious.
func (p *Policy) CanSee(operator, device string) bool {
	for kind := range KindToPermission {
		if p.Authorize(operator, device, kind).Allowed {
			return true
		}
	}
	return false
}

// Members lists every operator the policy admits, sorted. An empty result means the
// policy grants nothing at all, which is worth knowing before someone assumes otherwise.
func (p *Policy) Members() []string {
	out := make([]string, 0, len(p.byOperator))
	for name := range p.byOperator {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// Describe returns an operator's effective policy, for an operator to be shown.
func (p *Policy) Describe(operator string) (role, bool) {
	r, ok := p.byOperator[operator]
	return r, ok
}
