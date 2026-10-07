// Package acl decides whether an operator may act on a device.
//
// Three ideas, kept separate on purpose:
//
//   - a kind answers "what is this request for"
//   - a permission answers "may this operator do that at all"
//   - a grant answers "may this operator touch this specific device"
//
// Collapsing permission and grant into one check is how single-tenant tools grow into
// single-operator tools: every new check then needs a new role, and the operator list
// stops being a policy and becomes a list of exceptions.
//
// A kind is a name, never a guess. KindForService turns the service name an operator's
// adb binary sends into one, and a service nobody has classified is refused rather than
// allowed by default: a new feature cannot ship without someone deciding who may use it.
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
	// PermShell allows an interactive shell on a device, and the services that are a
	// shell in another spelling: `adb shell input`, `adb shell screenrecord`,
	// `adb root`. It is also what a raw ADB transport requires, because one such
	// connection carries everything below.
	PermShell Permission = "shell"
	// PermExec allows `adb exec-out`, the non-interactive command service.
	PermExec Permission = "exec"
	// PermFiles allows push, pull and sideload.
	PermFiles Permission = "files"
	// PermInstall allows installing and uninstalling packages.
	PermInstall Permission = "install"
	// PermForward allows adb port forwarding. A forward binds a port on the gateway
	// and reaches the device through it, so the holder decides that a port on the
	// gateway machine answers for something on a phone across the internet.
	PermForward Permission = "forward"
	// PermReverse allows adb reverse forwarding, the other direction: the device binds
	// the port and the gateway connects to its own loopback when something reaches it.
	PermReverse Permission = "reverse"
)

// Stream kinds, which are what a request carries and what a permission is checked
// against. A kind is a property of the request; a permission is a property of the
// role. KindToPermission is the only place the two meet.
const (
	// KindOperatorBridge is the raw ADB transport an operator's adb client switches
	// onto before it names a service.
	KindOperatorBridge = "operator-bridge"
	// KindShell is an interactive shell, and the services that are a shell in another
	// spelling.
	KindShell = "shell"
	// KindExec is `adb exec-out`.
	KindExec = "exec"
	// KindFiles is push, pull and sideload.
	KindFiles = "files"
	// KindInstall is package installation.
	KindInstall = "install"
	// KindForward is `adb forward` in every form, binding and removing.
	KindForward = "forward"
	// KindReverse is `adb reverse` in every form, binding and removing, and the
	// callback a device opens when something reaches a port it holds.
	KindReverse = "reverse"
)

// PermAll is the wildcard permission, granting every capability a role has
// grants for.
//
// It exists so a small deployment is not forced to enumerate permissions, and it is
// deliberately not the default: a role that lists nothing gets nothing.
const PermAll Permission = "*"

// KindToPermission maps a stream kind to the permission it requires, so the
// check cannot be forgotten at a call site.
//
// It is the whole vocabulary: a kind absent from here has no permission and is
// refused by Authorize, and a permission absent from the declarations above cannot be
// named in a policy file. Both directions are asserted in the tests, because a
// permission that can be written down and never consulted is a policy that reads like
// control and is not.
var KindToPermission = map[string]Permission{
	// A raw ADB bridge necessarily carries shell, install, file transfer and
	// forwarding together, because ADB multiplexes them over one TCP connection by
	// itself. Gating it on anything weaker than PermShell would hand shell to a role
	// that deliberately excluded it -- the classic mistake of treating a protocol as
	// if it were separable. So the gate is PermShell, and the consequence is
	// documented rather than papered over: holding "shell" on a device means holding
	// adb on that device, and every other kind below narrows a role that already
	// holds it rather than widening one that does not.
	KindOperatorBridge: PermShell,
	KindShell:          PermShell,
	KindExec:           PermExec,
	KindFiles:          PermFiles,
	KindInstall:        PermInstall,
	KindForward:        PermForward,
	KindReverse:        PermReverse,
}

// KindForService classifies a service request an operator's adb client sends on a
// switched transport, and reports the kind whose permission governs it.
//
// The service name is the whole of what a client says about what it wants: everything
// after the name is a command line or a socket specification, and the gateway relays
// it without reading it. So the name is the only place a kind can be decided, and
// deciding it here is what lets the decision reach Authorize on every request.
//
// Measured against a stock adb binary talking to a stock adb server, one line per
// command, service name as it arrived on the wire:
//
//	adb shell whoami        shell,v2,TERM=xterm-256color,raw:whoami
//	adb shell input tap     shell,v2,TERM=xterm-256color,raw:input tap 100 100
//	adb shell screencap     shell,v2,TERM=xterm-256color,raw:screencap -p /sdcard/s.png
//	adb shell screenrecord  shell,v2,TERM=xterm-256color,raw:screenrecord --time-limit 1 /sdcard/v.mp4
//	adb logcat -d           shell,v2,TERM=xterm-256color:export ANDROID_LOG_TAGS=''; exec logcat '-d'
//	adb logcat              shell,v2,TERM=xterm-256color:export ANDROID_LOG_TAGS=''; exec logcat
//	adb exec-out echo hi    exec:echo 'hi'
//	adb push / adb pull     sync:
//	adb sideload            sideload-host:2273746:65536
//	adb install             abb_exec:settings\0get\0global\0enable_adb_incremental_install_default
//	adb install (the rest)  abb_exec:package\0install-incremental\0-r\0ard-agent.apk:...
//	adb root                root:
//	adb unroot              unroot:
//	adb forward             host:forward:tcp:9930;tcp:9931
//	adb forward --no-rebind host:forward:norebind:tcp:9932;tcp:9933
//	adb forward --remove    host:killforward:tcp:9930
//	adb forward --remove-all host:killforward-all
//	adb reverse             reverse:forward:tcp:9910;tcp:9911
//	adb reverse --list      reverse:list-forward
//	adb reverse --remove    reverse:killforward:tcp:9910
//	adb reverse --remove-all reverse:killforward-all
//
// Three things that measurement settles and that a permission vocabulary has to respect.
//
// `adb logcat` arrives as a shell. It is the device's own `logcat` binary with its
// arguments, spelled as a shell command line, so a permission separating reading the log
// from opening a shell would separate nothing: the identical bytes reach the device
// through `adb shell logcat`. `adb shell screenrecord` and `adb shell screencap` arrive the
// same way. A check can only be made on a name, and these have none of their own, so both
// are governed by the shell permission and neither is a name a policy file may hold.
//
// `exec` is a name of its own: `adb exec-out` sends `exec:` and `adb shell` sends
// `shell:...`, so the two are tellable apart on the wire and the split is real. It
// narrows a role rather than widening it, because reaching either service needs a
// switched transport and a switched transport is KindOperatorBridge.
func KindForService(service string) (string, bool) {
	// A service request is a name, a colon, and a payload that is never interpreted here:
	// a command line, a socket specification, or a NUL-separated argument vector. Splitting
	// at the first colon is what makes the name comparable, and it is also what keeps
	// "reverseforward:tcp:1;tcp:2" from being read as a reverse and "shell,v2,TERM=xterm-
	// 256color,raw:whoami" from being anything but a shell with a feature list on it.
	name, rest, _ := strings.Cut(service, ":")
	switch {
	// The shell service carries its feature list in its name, ahead of the colon:
	// "shell,v2,TERM=xterm-256color,raw:whoami". So the name is compared by its leading
	// component, and the comma is what separates it from the rest rather than the colon.
	case name == "shell" || strings.HasPrefix(name, "shell,"),
		name == "root", name == "unroot", name == "remount":
		// root and remount are here because what they do is decide what a shell can reach:
		// a device that is already rooted answers every shell below with more authority.
		return KindShell, true
	case name == "exec":
		return KindExec, true
	case name == "sync", name == "sideload-host":
		return KindFiles, true
	case name == "abb_exec":
		return KindInstall, true
	case name == "reverse":
		return subKind(rest, KindReverse, "forward", "killforward", "killforward-all", "list-forward")
	case name == "host":
		// The forwarding half of what adb asks about this server rather than about a device.
		// A device is never asked about a port bound here, because the port is here.
		return subKind(rest, KindForward,
			"forward", "killforward", "killforward-all", "list-forward", "list-forward-all")
	case name == "host-serial":
		// The serial-qualified listing, which the stock server accepts as the per-device form
		// of `adb forward --list`. Only that action is a request about a port; the others
		// under this prefix name a device rather than ask anything of it.
		//
		// The action is what follows the LAST colon, because a serial may contain one -- an adb
		// serial over TCP is host:port -- and splitting on the first would compare "9930" or
		// "somehost" against the action instead.
		i := strings.LastIndexByte(rest, ':')
		if i >= 0 && rest[i+1:] == "list-forward" {
			return KindForward, true
		}
		return "", false
	}
	return "", false
}

// subKind classifies the remainder of a service whose name has sub-services, such as
// "reverse:forward:tcp:9910;tcp:9911". Only the listed sub-names are answered: a fifth one
// under a name that exists would be refused, and the reason it is worth refusing is the same
// as for any other service, which is that nobody has decided who may use it.
func subKind(rest, kind string, names ...string) (string, bool) {
	sub, _, _ := strings.Cut(rest, ":")
	for _, name := range names {
		if sub == name {
			return kind, true
		}
	}
	return "", false
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
// Two indexes, because two lookups are asked of it and one map can only answer one of them
// honestly: byRole answers "what does this role look like", and byOperator answers "what may
// this certificate's common name do". Sharing one map would make a role effective only when
// it was named after an operator, which turns the policy file into a list of exceptions
// rather than a statement about people.
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
	known := loadablePermissions()
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

// loadablePermissions is the set of names a policy file may write, derived from the kind
// table rather than written out beside it. Two lists of the same permissions would be two
// places to forget one, and both failures are quiet: a name the loader knows that no kind
// requires grants a role something no request can be refused for, and a name the loader does
// not know that a kind requires cannot be granted at all.
func loadablePermissions() map[Permission]bool {
	out := map[Permission]bool{PermAll: true}
	for _, perm := range KindToPermission {
		out[perm] = true
	}
	return out
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
	// `required` and `held` are the two sides of the comparison, and the names matter:
	// comparing the kind's own permission against a loop variable of the same name
	// compares a value with itself, which is always true, and then every role holding
	// any permission passes every check.
	required, ok := KindToPermission[kind]
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

// roles returns every role in file order, so a caller that has to inspect the whole policy
// rather than answer one question about one operator reads the roles themselves and not a
// projection of them.
func (p *Policy) roles() []role {
	out := make([]role, 0, len(p.byRole))
	for _, r := range p.byRole {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
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
// A read-only operator sees a device they legitimately hold a permission for. They cannot
// drive anything, but they can see that their access exists -- and being able to see is what
// makes a denial explicable instead of mysterious.
//
// It walks the kind table rather than the permission list, so a permission nobody can reach
// through any kind does not make a device visible. That is deliberate: a role holding a
// permission that governs no request has been granted something that cannot be used, and
// showing the device would suggest otherwise.
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
