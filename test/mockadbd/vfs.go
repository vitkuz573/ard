package mockadbd

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"
	"sync"
	"time"
)

// A virtual filesystem, so the mock has somewhere for a file transfer to land and
// something for shell commands to look at.
//
// Without it the mock can only answer eight hardcoded commands, which makes it useless
// for testing the two things operators actually spend their day doing: pushing a build
// and pulling a log. It also means every test that wanted files had to invent its own
// storage, so the behaviour differed between tests and none of it was shared.
//
// It is deliberately in memory. A simulator that wrote to the host filesystem would make
// tests destructive and non-repeatable, and the point of this is to be run in CI.

var (
	// ErrNotExist is returned for a path with nothing at it.
	ErrNotExist = fs.ErrNotExist
	// ErrExist is returned when creating something that is already there.
	ErrExist = fs.ErrExist
	// ErrNotDir is returned when a path component that must be a directory is not.
	ErrNotDir = errors.New("mockadbd: not a directory")
	// ErrIsDir is returned when a directory is used as a file.
	ErrIsDir = errors.New("mockadbd: is a directory")
	// ErrPerm is returned when a mode forbids the operation.
	ErrPerm = fs.ErrPermission
)

// Node is one file or directory in the tree.
type Node struct {
	Name    string
	Dir     bool
	Mode    fs.FileMode
	Data    []byte
	ModTime time.Time
	// Parent is nil for the root. Kept as a pointer so Rename can re-parent a subtree
	// without walking it, which matters because /data can hold a whole tree.
	Parent   *Node
	Children map[string]*Node
}

// VFS is a virtual filesystem rooted at "/".
type VFS struct {
	mu    sync.RWMutex
	root  *Node
	props *Properties
	// Now is injectable so tests can assert on timestamps without sleeping.
	Now func() time.Time
}

// NewVFS returns a filesystem seeded with a plausible Android layout.
//
// The seed matters more than it looks. A mock rooted at an empty directory makes every
// command that touches the world fail in ways real hardware never would, and those
// failures get mistaken for relay bugs. A device has /system, /data, /sdcard, /proc and
// a properties store, and code written against it assumes all of those exist.
func NewVFS() *VFS {
	v := &VFS{Now: time.Now}
	v.root = &Node{Name: "", Dir: true, Mode: 0o755, Children: map[string]*Node{}}

	for _, d := range []struct {
		path string
		mode fs.FileMode
	}{
		{"system", 0o755},
		{"system/bin", 0o755},
		{"system/lib", 0o755},
		{"system/etc", 0o755},
		{"data", 0o700},
		{"data/local", 0o771},
		{"data/local/tmp", 0o771},
		{"data/app", 0o755},
		{"data/data", 0o771},
		{"sdcard", 0o770},
		{"proc", 0o555},
		{"dev", 0o755},
		{"storage", 0o770},
		{"storage/emulated", 0o770},
		{"storage/emulated/0", 0o770},
	} {
		_ = v.MkdirAll(d.path, d.mode)
	}

	// Seed files at their real paths, rather than deriving them: a derived path is how a
	// file ends up somewhere a test never looks and then fails for the wrong reason.
	for full, body := range map[string]string{
		"/system/build.prop": "ro.build.version.sdk=34\nro.build.version.release=14\n",
		"/system/etc/hosts":  "127.0.0.1 localhost\n",
		"/proc/version":      "Linux version 5.15.123-android14 (build@host)\n",
		"/proc/uptime":       "12345.67 98765.43\n",
	} {
		_ = v.WriteFile(full, []byte(body), 0o644)
	}

	v.props = NewProperties(defaultProps)
	return v
}

// Properties returns the property store, so shell and callers share one view.
func (v *VFS) Props() *Properties { return v.props }

// clean normalises a path to an absolute, slash-separated form with "." and ".."
// resolved lexically.
//
// Lexical rather than filesystem-style resolution, which is deliberate: there are no
// symlinks in this filesystem, so the two agree, and not having links means a path can
// never escape the root.
func clean(p string) string {
	if p == "" {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	parts := strings.Split(p, "/")
	out := make([]string, 0, len(parts))
	for _, seg := range parts {
		switch seg {
		case "", ".":
		case "..":
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
		default:
			out = append(out, seg)
		}
	}
	return "/" + strings.Join(out, "/")
}

// resolve walks to a node without taking the lock. Callers hold it.
func (v *VFS) resolve(p string) (*Node, error) {
	n := v.root
	for _, seg := range strings.Split(strings.Trim(clean(p), "/"), "/") {
		if seg == "" {
			continue
		}
		if !n.Dir {
			return nil, ErrNotDir
		}
		next, ok := n.Children[seg]
		if !ok {
			return nil, fmt.Errorf("%s: %w", p, ErrNotExist)
		}
		n = next
	}
	return n, nil
}

func (v *VFS) parentOf(p string) (*Node, string, error) {
	c := clean(p)
	dir, base := path.Split(c)
	if base == "" {
		return nil, "", fmt.Errorf("%s: %w", p, ErrNotExist)
	}
	parent, err := v.resolve(path.Dir(dir))
	if err != nil {
		return nil, "", err
	}
	if !parent.Dir {
		return nil, "", ErrNotDir
	}
	return parent, base, nil
}

// Stat returns a node's metadata.
func (v *VFS) Stat(p string) (*Node, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.resolve(p)
}

// Exists reports whether anything is at p.
func (v *VFS) Exists(p string) bool {
	_, err := v.Stat(p)
	return err == nil
}

// IsDir reports whether p is a directory.
func (v *VFS) IsDir(p string) bool {
	n, err := v.Stat(p)
	return err == nil && n.Dir
}

// ReadFile returns a file's contents.
func (v *VFS) ReadFile(p string) ([]byte, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	n, err := v.resolve(p)
	if err != nil {
		return nil, err
	}
	if n.Dir {
		return nil, fmt.Errorf("%s: %w", p, ErrIsDir)
	}
	out := make([]byte, len(n.Data))
	copy(out, n.Data)
	return out, nil
}

// WriteFile replaces a file's contents, creating it and any missing parents.
//
// Parents are created because sync pushes into paths like /data/local/tmp/<name> that a
// test may not have prepared, and failing on the directory turns a file transfer into a
// permissions puzzle.
func (v *VFS) WriteFile(p string, data []byte, mode fs.FileMode) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	parent, base, err := v.parentOf(p)
	if err != nil {
		if !errors.Is(err, ErrNotExist) {
			return err
		}
		if mkErr := v.mkdirAllLocked(path.Dir(clean(p)), 0o755); mkErr != nil {
			return mkErr
		}
		parent, base, err = v.parentOf(p)
		if err != nil {
			return err
		}
	}
	if existing, ok := parent.Children[base]; ok {
		if existing.Dir {
			return fmt.Errorf("%s: %w", p, ErrIsDir)
		}
		existing.Data = append([]byte(nil), data...)
		existing.ModTime = v.Now()
		return nil
	}
	node := &Node{
		Name:    base,
		Mode:    mode,
		Data:    append([]byte(nil), data...),
		ModTime: v.Now(),
		Parent:  parent,
	}
	parent.Children[base] = node
	return nil
}

// AppendFile adds to the end of a file, creating it if needed.
func (v *VFS) AppendFile(p string, data []byte) error {
	v.mu.Lock()
	existing, err := v.resolve(p)
	if err == nil && !existing.Dir {
		existing.Data = append(existing.Data, data...)
		existing.ModTime = v.Now()
		v.mu.Unlock()
		return nil
	}
	v.mu.Unlock()
	return v.WriteFile(p, data, 0o644)
}

// MkdirAll creates a directory and its parents, like os.MkdirAll.
func (v *VFS) MkdirAll(p string, mode fs.FileMode) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.mkdirAllLocked(p, mode)
}

func (v *VFS) mkdirAllLocked(p string, mode fs.FileMode) error {
	n := v.root
	for _, seg := range strings.Split(strings.Trim(clean(p), "/"), "/") {
		if seg == "" {
			continue
		}
		next, ok := n.Children[seg]
		if !ok {
			next = &Node{
				Name:     seg,
				Dir:      true,
				Mode:     mode,
				ModTime:  v.Now(),
				Parent:   n,
				Children: map[string]*Node{},
			}
			n.Children[seg] = next
		} else if !next.Dir {
			return ErrNotDir
		}
		n = next
	}
	return nil
}

// ReadDir lists a directory, sorted by name.
//
// Sorted because a stable listing is what makes a test assertion possible at all, and
// because real readdir order is not something to depend on.
func (v *VFS) ReadDir(p string) ([]*Node, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	n, err := v.resolve(p)
	if err != nil {
		return nil, err
	}
	if !n.Dir {
		return nil, fmt.Errorf("%s: %w", p, ErrNotDir)
	}
	out := make([]*Node, 0, len(n.Children))
	for _, c := range n.Children {
		out = append(out, &Node{
			Name: c.Name, Dir: c.Dir, Mode: c.Mode,
			Data: c.Data, ModTime: c.ModTime,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Remove deletes a file, or a directory only when it is empty.
//
// Refusing a non-empty directory matches what a shell rm does without -r, and it is the
// behaviour that makes a test that cleans up after itself obvious when it has not.
func (v *VFS) Remove(p string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	parent, base, err := v.parentOf(p)
	if err != nil {
		return err
	}
	n, ok := parent.Children[base]
	if !ok {
		return fmt.Errorf("%s: %w", p, ErrNotExist)
	}
	if n.Dir && len(n.Children) > 0 {
		return fmt.Errorf("%s: directory not empty", p)
	}
	delete(parent.Children, base)
	return nil
}

// RemoveAll deletes a subtree.
func (v *VFS) RemoveAll(p string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	parent, base, err := v.parentOf(p)
	if err != nil {
		if errors.Is(err, ErrNotExist) {
			return nil
		}
		return err
	}
	delete(parent.Children, base)
	return nil
}

// Rename moves a node, refusing to move a directory into itself.
func (v *VFS) Rename(from, to string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	srcParent, srcBase, err := v.parentOf(from)
	if err != nil {
		return err
	}
	node, ok := srcParent.Children[srcBase]
	if !ok {
		return fmt.Errorf("%s: %w", from, ErrNotExist)
	}
	dstParent, dstBase, err := v.parentOf(to)
	if err != nil {
		if !errors.Is(err, ErrNotExist) {
			return err
		}
		if err := v.mkdirAllLocked(path.Dir(clean(to)), 0o755); err != nil {
			return err
		}
		dstParent, dstBase, err = v.parentOf(to)
		if err != nil {
			return err
		}
	}
	if node.Dir && v.isAncestorLocked(node, dstParent) {
		// Moving a directory beneath itself would detach the whole subtree from the
		// tree, leaving it reachable only through the node that is being moved.
		return fmt.Errorf("%s: cannot move a directory into itself", from)
	}
	delete(srcParent.Children, srcBase)
	node.Name = dstBase
	node.Parent = dstParent
	dstParent.Children[dstBase] = node
	return nil
}

// isAncestorLocked reports whether ancestor is n or somewhere above it.
//
// Walking parent pointers is the whole point: the question is about the destination's
// ancestry, not about scanning the destination's children, and getting that backwards
// rejects every ordinary move because the node being moved is usually a sibling of where
// it is going.
func (v *VFS) isAncestorLocked(ancestor, n *Node) bool {
	for cur := n; cur != nil; cur = cur.Parent {
		if cur == ancestor {
			return true
		}
	}
	return false
}

// Size returns the total bytes of all regular files, for df.
func (v *VFS) Size() int64 {
	v.mu.RLock()
	defer v.mu.RUnlock()
	var total int64
	var walk func(*Node)
	walk = func(n *Node) {
		if !n.Dir {
			total += int64(len(n.Data))
			return
		}
		for _, c := range n.Children {
			walk(c)
		}
	}
	walk(v.root)
	return total
}

// Count returns how many nodes exist, so a test can assert that a push created exactly
// one file and did not quietly create a directory too.
func (v *VFS) Count() int {
	v.mu.RLock()
	defer v.mu.RUnlock()
	var n int
	var walk func(*Node)
	walk = func(node *Node) {
		n++
		for _, c := range node.Children {
			walk(c)
		}
	}
	walk(v.root)
	return n
}

// Snapshot returns every file path with its contents.
//
// A test that wants to compare a whole tree needs this; walking it by hand from outside
// would mean taking the lock repeatedly and racing against concurrent writers.
func (v *VFS) Snapshot() map[string][]byte {
	v.mu.RLock()
	defer v.mu.RUnlock()
	// The walk starts at "/" and not at "": path.Join("", "sdcard") is "sdcard", which
	// produced relative keys that did not match the absolute paths every other call in
	// this package accepts.
	out := map[string][]byte{}
	var walk func(string, *Node)
	walk = func(prefix string, n *Node) {
		if !n.Dir {
			data := make([]byte, len(n.Data))
			copy(data, n.Data)
			out[prefix] = data
			return
		}
		for name, c := range n.Children {
			walk(path.Join(prefix, name), c)
		}
	}
	walk("/", v.root)
	return out
}

// defaultProps is the property set a device reports.
//
// Enough to be useful: the values a test is most likely to assert on, and a few that make
// `getprop` output look like a device rather than a stub.
var defaultProps = map[string]string{
	"ro.build.version.sdk":            "34",
	"ro.build.version.release":        "14",
	"ro.build.version.security_patch": "2026-08-01",
	"ro.build.type":                   "user",
	"ro.product.model":                "mockadbd-simulator",
	"ro.product.device":               "simulator",
	"ro.product.manufacturer":         "mockadbd",
	"ro.product.cpu.abi":              "arm64-v8a",
	"ro.product.cpu.abilist":          "arm64-v8a,armeabi-v7a,armeabi",
	"ro.build.fingerprint":            "mockadbd/simulator/simulator:14/UP1A/0001:user/test-keys",
	"ro.serialno":                     "SIM0000001",
	"ro.boot.serialno":                "SIM0000001",
	"ro.debuggable":                   "0",
	"ro.secure":                       "0",
	"service.adb.tcp.port":            "",
	"sys.boot_completed":              "1",
	"net.hostname":                    "localhost",
}

// Touch sets a file's modification time.
//
// A push carries the source's mtime and adbd preserves it, so a pull returns a file whose
// timestamps match what was sent. A simulator that stamped everything with the current
// time would make that untestable.
func (v *VFS) Touch(p string, mod time.Time) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	n, err := v.resolve(p)
	if err != nil {
		return err
	}
	n.ModTime = mod
	return nil
}

// EnsureFile creates an empty file with the given mode if it does not exist, and leaves an
// existing one alone.
//
// A push is a stream of appends, so the file has to exist before the first DATA frame
// arrives. Creating it here rather than on first write is what lets the requested mode be
// applied exactly once, instead of being decided by whichever path happened to run first.
func (v *VFS) EnsureFile(p string, mode os.FileMode) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if existing, err := v.resolve(p); err == nil {
		if existing.Dir {
			return ErrIsDir
		}
		return nil
	}
	return v.WriteFile(p, nil, mode)
}
