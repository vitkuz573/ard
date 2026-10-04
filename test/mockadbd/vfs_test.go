package mockadbd_test

import (
	"os"
	"path"
	"sort"
	"strings"
	"sync"
	"testing"

	mockadbd "github.com/vitkuz573/ard/test/mockadbd"
)

// The seed is what stops every command that touches the world from failing in ways real
// hardware never would, so it is asserted rather than assumed.
func TestVFSSeedsAPlausibleAndroidLayout(t *testing.T) {
	v := mockadbd.NewVFS()
	for _, dir := range []string{
		"/", "/system", "/system/bin", "/system/etc", "/system/lib",
		"/data", "/data/local", "/data/local/tmp", "/data/app",
		"/sdcard", "/proc", "/storage/emulated/0",
	} {
		if !v.IsDir(dir) {
			t.Errorf("seed is missing directory %s", dir)
		}
	}
	for _, file := range []string{"/system/build.prop", "/proc/version"} {
		if !v.Exists(file) {
			t.Errorf("seed is missing file %s", file)
		}
	}
}

// Paths arrive from adb, from test code and from shell redirection, so ".." has to behave.
// The important property is that it cannot climb above the root: a simulator with an
// escapable path is worse than one without the feature, because it turns a bug into a
// write outside the sandbox.
func TestPathCleaningCannotEscapeTheRoot(t *testing.T) {
	v := mockadbd.NewVFS()
	for _, p := range []string{
		"/../../../../etc/passwd",
		"/data/../../../../../../tmp/x",
		"/./././data/./local/./tmp",
		"data/local/tmp",      // relative
		"//data///local//tmp", // repeated separators
	} {
		// Whatever the shape, a write must land under the root and the original path
		// must not resolve to anything outside it.
		target := path.Join("/data/local/tmp", "escapetest")
		if err := v.WriteFile(target, []byte("x"), 0o644); err != nil {
			t.Fatalf("write for %q: %v", p, err)
		}
	}
	if _, err := v.Stat("/../../../../etc/passwd"); err == nil {
		t.Fatal("a path climbing out of the root resolved to something")
	}
	// Relative and absolute forms must name the same file.
	if err := v.WriteFile("relative/path.txt", []byte("same"), 0o644); err != nil {
		t.Fatalf("relative write: %v", err)
	}
	got, err := v.ReadFile("/relative/path.txt")
	if err != nil || string(got) != "same" {
		t.Fatalf("relative and absolute disagree: %q %v", got, err)
	}
	// Traversal that lands back inside must resolve to the inner node.
	inside := path.Join("/data/local/tmp", "inner")
	if err := v.WriteFile(inside, []byte("in"), 0o644); err != nil {
		t.Fatalf("write inner: %v", err)
	}
	resolved, err := v.ReadFile("/data/local/tmp/nested/../inner")
	if err != nil || string(resolved) != "in" {
		t.Fatalf(".. inside a path did not resolve: %q %v", resolved, err)
	}
}

// Push targets paths a test never prepared, so creating parents is required behaviour
// rather than convenience.
func TestWriteFileCreatesParents(t *testing.T) {
	v := mockadbd.NewVFS()
	const target = "/data/local/tmp/deep/nested/dir/file.bin"
	if err := v.WriteFile(target, []byte("payload"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	got, err := v.ReadFile(target)
	if err != nil || string(got) != "payload" {
		t.Fatalf("read back = %q %v", got, err)
	}
	if !v.IsDir("/data/local/tmp/deep/nested/dir") {
		t.Fatal("parents were not created")
	}
}

// Overwriting must replace, not append, and must not leave the mode of whatever was there
// before unless told otherwise.
func TestWriteFileReplacesAndAppendFileExtends(t *testing.T) {
	v := mockadbd.NewVFS()
	const f = "/sdcard/log.txt"
	if err := v.WriteFile(f, []byte("one"), 0o644); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if err := v.WriteFile(f, []byte("two"), 0o644); err != nil {
		t.Fatalf("second write: %v", err)
	}
	got, _ := v.ReadFile(f)
	if string(got) != "two" {
		t.Fatalf("overwrite left %q", got)
	}
	if err := v.AppendFile(f, []byte("+more")); err != nil {
		t.Fatalf("append: %v", err)
	}
	got, _ = v.ReadFile(f)
	if string(got) != "two+more" {
		t.Fatalf("append produced %q", got)
	}
	if err := v.AppendFile("/sdcard/fresh.txt", []byte("new")); err != nil {
		t.Fatalf("append to a missing file should create it: %v", err)
	}
}

// A listing a test can assert on has to be ordered. Real readdir order is not something to
// depend on, so the simulator pins it.
func TestReadDirIsSorted(t *testing.T) {
	v := mockadbd.NewVFS()
	for _, n := range []string{"zebra", "alpha", "middle", "0001"} {
		if err := v.WriteFile("/sdcard/"+n, []byte(n), 0o644); err != nil {
			t.Fatalf("write %s: %v", n, err)
		}
	}
	entries, err := v.ReadDir("/sdcard")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name)
	}
	if !sort.StringsAreSorted(names) {
		t.Fatalf("listing is not sorted: %v", names)
	}
	if len(names) != 4 {
		t.Fatalf("expected 4 entries, got %v", names)
	}
}

// Removing something that is not empty must fail rather than silently take the subtree.
// A simulator that deletes too much produces test failures that point nowhere.
func TestRemoveRefusesANonEmptyDirectory(t *testing.T) {
	v := mockadbd.NewVFS()
	if err := v.WriteFile("/sdcard/dir/child", []byte("x"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := v.Remove("/sdcard/dir"); err == nil {
		t.Fatal("removing a populated directory succeeded")
	}
	if !v.Exists("/sdcard/dir/child") {
		t.Fatal("the failed removal took the subtree with it")
	}
	if err := v.Remove("/sdcard/dir/child"); err != nil {
		t.Fatalf("removing the file: %v", err)
	}
	if err := v.Remove("/sdcard/dir"); err != nil {
		t.Fatalf("removing the now-empty directory: %v", err)
	}
	if v.Exists("/sdcard/dir") {
		t.Fatal("directory still present after removal")
	}
	// RemoveAll is the destructive one, and must be idempotent the way rm -rf is.
	if err := v.WriteFile("/sdcard/tree/a/b", []byte("x"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := v.RemoveAll("/sdcard/tree"); err != nil {
		t.Fatalf("RemoveAll: %v", err)
	}
	if err := v.RemoveAll("/sdcard/tree"); err != nil {
		t.Fatalf("RemoveAll on a missing path should succeed: %v", err)
	}
}

func TestRename(t *testing.T) {
	v := mockadbd.NewVFS()
	if err := v.WriteFile("/sdcard/a.txt", []byte("body"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := v.Rename("/sdcard/a.txt", "/sdcard/b.txt"); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	if v.Exists("/sdcard/a.txt") {
		t.Fatal("the old name still resolves")
	}
	got, err := v.ReadFile("/sdcard/b.txt")
	if err != nil || string(got) != "body" {
		t.Fatalf("contents lost in the move: %q %v", got, err)
	}
	// A directory subtree has to move with its children.
	if err := v.WriteFile("/sdcard/tree/inner/file", []byte("deep"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := v.Rename("/sdcard/tree", "/sdcard/moved"); err != nil {
		t.Fatalf("rename dir: %v", err)
	}
	if got, err := v.ReadFile("/sdcard/moved/inner/file"); err != nil || string(got) != "deep" {
		t.Fatalf("subtree did not move: %q %v", got, err)
	}
	// Moving a directory inside itself would detach the subtree from the tree entirely.
	if err := v.Rename("/sdcard/moved", "/sdcard/moved/self"); err == nil {
		t.Fatal("moving a directory into itself was allowed")
	}
}

// Snapshot exists so a test can compare a whole tree without racing concurrent writers by
// taking the lock itself.
func TestSnapshotAndCount(t *testing.T) {
	v := mockadbd.NewVFS()
	before := v.Count()
	if err := v.WriteFile("/sdcard/one", []byte("1"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := v.Count(); got != before+1 {
		t.Fatalf("Count = %d, want %d: writing a file also created directories?", got, before+1)
	}
	snap := v.Snapshot()
	if string(snap["/sdcard/one"]) != "1" {
		t.Fatalf("snapshot missing the file: %v", snap["/sdcard/one"])
	}
	// The snapshot must be a copy: mutating it cannot corrupt the filesystem.
	snap["/sdcard/one"][0] = 'X'
	if got, _ := v.ReadFile("/sdcard/one"); string(got) != "1" {
		t.Fatalf("snapshot aliases internal storage: %q", got)
	}
	if v.Size() == 0 {
		t.Fatal("Size reported zero on a filesystem with seed files")
	}
}

// A simulator is only useful if concurrent access does not corrupt it, because real adb
// opens several streams at once.
func TestVFSIsSafeUnderConcurrency(t *testing.T) {
	v := mockadbd.NewVFS()
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			p := path.Join("/data/local/tmp", "f"+string(rune('a'+i%26))+".txt")
			if err := v.WriteFile(p, []byte(strings.Repeat("x", i+1)), 0o644); err != nil {
				t.Errorf("write: %v", err)
				return
			}
			if _, err := v.ReadFile(p); err != nil {
				t.Errorf("read: %v", err)
			}
			if _, err := v.ReadDir("/data/local/tmp"); err != nil {
				t.Errorf("readdir: %v", err)
			}
		}(i)
	}
	wg.Wait()
}

// Property lookup has two rules that are easy to miss and that real callers depend on:
// an unset property reads as empty rather than failing, and a trailing dot is a query
// convention rather than part of the name.
func TestPropertySemantics(t *testing.T) {
	p := mockadbd.NewProperties(map[string]string{
		"ro.a":      "1",
		"ro.b":      "2",
		"persist.x": "",
	})

	if got := p.Get("ro.a"); got != "1" {
		t.Fatalf("Get = %q", got)
	}
	// Unset and empty are different, and code checks presence.
	if got := p.Get("nope"); got != "" {
		t.Fatalf("an unset property read as %q, want empty", got)
	}
	if !p.Has("persist.x") {
		t.Error("a property set to the empty string reported as absent")
	}
	if p.Has("nope") {
		t.Error("an unset property reported as present")
	}

	// "ro." and "ro" must agree.
	withDot := p.List("ro.")
	withoutDot := p.List("ro")
	if len(withDot) != 2 || len(withoutDot) != 2 {
		t.Fatalf("prefix query disagrees: with dot %v, without %v", withDot, withoutDot)
	}
	if !sort.StringsAreSorted(withDot) {
		t.Fatalf("prefix query is not sorted: %v", withDot)
	}
	if got := p.List(""); len(got) != 3 {
		t.Fatalf("empty prefix returned %v, want everything", got)
	}

	p.Set("ro.c", "3")
	if got := p.List("ro."); len(got) != 3 {
		t.Fatalf("Set did not appear in the prefix query: %v", got)
	}
	p.Unset("ro.c")
	if got := p.List("ro."); len(got) != 2 {
		t.Fatalf("Unset left the property visible: %v", got)
	}
	// ro.a, ro.b and persist.x are set; the two ro.* keys plus one empty one.
	if all := p.All(); len(all) != 3 || !sort.StringsAreSorted(all) {
		t.Fatalf("All = %v", all)
	}
	if p.Len() != 3 {
		t.Fatalf("Len = %d, want 3", p.Len())
	}
}

// Modes are carried so a test can assert on them, which is how a permissions test would
// check that a push produced a private file.
func TestFileModesAreRecorded(t *testing.T) {
	v := mockadbd.NewVFS()
	if err := v.WriteFile("/data/local/tmp/secret", []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	n, err := v.Stat("/data/local/tmp/secret")
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if n.Mode.Perm() != os.FileMode(0o600) {
		t.Fatalf("mode = %v, want 0600", n.Mode.Perm())
	}
	if n.Dir {
		t.Fatal("a regular file reported as a directory")
	}
	if n.Name != "secret" {
		t.Fatalf("Name = %q", n.Name)
	}
}
