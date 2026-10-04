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
	"screen":  PermScreen,
	"forward": PermForward,
	"reverse": PermReverse,
}

// role is one named set of permissions.
type role struct {
	Name        string       `yaml:"name"`
	Permissions []Permission `yaml:"permissions"`
	// Grants are device UUIDs, or "*" for every device. Prefer explicit UUIDs:
	// a wildcard in a role that also grants shell is a fleet-wide remote shell.
	Grants []string `yaml:"grants"`
}

// file is the on-disk shape.
type file struct {
	Roles []role `yaml:"roles"`
}

// Policy is a loaded authorization policy.
type Policy struct {
	byName map[string]role
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
	p := &Policy{byName: make(map[string]role, len(f.Roles))}
	known := map[Permission]bool{
		PermAll:   true,
		PermShell: true, PermExec: true, PermFiles: true, PermInstall: true,
		PermLogcat: true, PermScreen: true, PermForward: true, PermReverse: true,
	}
	for _, r := range f.Roles {
		if r.Name == "" {
			return nil, fmt.Errorf("acl: %s has a role with no name", path)
		}
		if _, dup := p.byName[r.Name]; dup {
			return nil, fmt.Errorf("acl: %s defines role %q twice", path, r.Name)
		}
		for _, perm := range r.Permissions {
			if !known[perm] {
				// An unknown permission silently ignored would look like a working
				// policy while granting less than the author intended.
				return nil, fmt.Errorf("acl: role %q has unknown permission %q", r.Name, perm)
			}
		}
		p.byName[r.Name] = r
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
	r, ok := p.byName[operator]
	if !ok {
		return Decision{Reason: fmt.Sprintf("operator %q has no role", operator)}
	}
	hasPerm := false
	for _, perm := range r.Permissions {
		if perm == PermAll || perm == perm {
			hasPerm = true
			break
		}
	}
	if !hasPerm {
		return Decision{Role: r.Name, Reason: fmt.Sprintf("role %q lacks permission %q", r.Name, perm)}
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
	out := make([]string, 0, len(p.byName))
	for name := range p.byName {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// Describe returns an operator's effective policy, for an operator to be shown.
func (p *Policy) Describe(operator string) (role, bool) {
	r, ok := p.byName[operator]
	return r, ok
}
