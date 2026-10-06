package mockadbd

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The device shell.
//
// It used to be a switch over eight hardcoded commands with no access to storage, which
// made the filesystem pointless: nothing could look at it. This runs commands against the
// VFS and the property store instead, so `ls`, `cat` and `stat` describe the same tree a
// push writes into.
//
// Commands are deliberately boring and Unix-shaped rather than clever. A relay test writes
// something like `adb shell ls -l /data/local/tmp` because that is what it would run
// against a device, and the point of the mock is that the command a test uses works the
// same way here.
//
// Exit statuses follow a real shell, because tests assert on them: 0 success, 1 for a
// usage or lookup failure, 2 for a misuse, 127 for an unknown command.

// shellRunner holds per-session state.
//
// One runner serves a whole session, which is what makes `cd` in one line visible to the
// next: a real `sh` keeps one working directory for the life of the process, and a runner
// rebuilt per command would make an interactive session behave like a pile of unrelated
// `adb shell` invocations.
type shellRunner struct {
	fs    *VFS
	props *Properties
	cwd   string
	env   map[string]string
	// now is injectable so timestamps in output are assertable.
	now func() time.Time

	// exited records that a line asked to end the session, and exitCode is the status to
	// report for it. A session loop that runs a line at a time cannot get this from run()'s
	// return value: `exit` with no argument means "the status of the last command", which is
	// a different answer from any status of its own.
	exited   bool
	exitCode int
	// last is the status of the most recent command, which is what a bare `exit` reports.
	last int
}

// newShellRunnerFor builds a session's shell over a filesystem.
func newShellRunnerFor(fs *VFS) *shellRunner {
	return &shellRunner{
		fs:    fs,
		props: fs.Props(),
		cwd:   "/",
		env:   defaultShellEnv(),
		now:   time.Now,
	}
}

// prompt is what an interactive session prints before each line.
//
// The shape is a real Android shell's: hostname, colon, working directory, space, dollar, space
// -- captured from a device as "<hostname>:/ $ ". The working directory is live, so a `cd` is
// visible in the very next prompt.
//
// The hostname is a constant rather than the system's, because this simulator has no hostname
// and printing the host's would be claiming a detail it does not have while making every test
// that saw a prompt depend on the machine it ran on.
func (r *shellRunner) prompt() string {
	return r.env["HOST"] + ":" + r.cwd + " $ "
}

func defaultShellEnv() map[string]string {
	return map[string]string{
		"ANDROID_DATA":     "/data",
		"ANDROID_ROOT":     "/system",
		"EXTERNAL_STORAGE": "/sdcard",
		"HOME":             "/",
		"PATH":             "/system/bin:/system/xbin",
		"SHELL":            "/system/bin/sh",
		"TMPDIR":           "/data/local/tmp",
		"PWD":              "/",
		// HOST backs the interactive prompt. See prompt() for why it is a constant.
		"HOST": "localhost",
	}
}

// abs resolves a possibly relative path against the session's cwd.
func (r *shellRunner) abs(p string) string {
	if p == "" {
		return r.cwd
	}
	if strings.HasPrefix(p, "/") {
		return p
	}
	return strings.TrimRight(r.cwd, "/") + "/" + p
}

// run executes one command line and returns its status.
//
// Every command records its status in r.last, because a bare `exit` reports the status of
// the command before it. That is set here rather than at the call sites: a caller that
// forgets loses the status silently, and the mistake shows up as an `exit` reporting 0
// after a failure.
func (r *shellRunner) run(argv []string, stdin io.Reader, stdout, stderr io.Writer) int {
	code := r.dispatch(argv, stdin, stdout, stderr)
	r.last = code
	return code
}

func (r *shellRunner) dispatch(argv []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(argv) == 0 {
		fmt.Fprintln(stderr, "shell: empty command")
		return 1
	}
	cmd, args := argv[0], argv[1:]
	switch cmd {
	case "echo":
		fmt.Fprintln(stdout, strings.Join(args, " "))
	case "pwd":
		fmt.Fprintln(stdout, r.cwd)
	case "cd":
		return r.cmdCd(args, stderr)
	case "ls":
		return r.cmdLs(args, stdout, stderr)
	case "cat":
		return r.cmdCat(args, stdin, stdout, stderr)
	case "mkdir":
		return r.cmdMkdir(args, stderr)
	case "rm":
		return r.cmdRm(args, stderr)
	case "mv":
		return r.cmdMv(args, stderr)
	case "cp":
		return r.cmdCp(args, stderr)
	case "stat":
		return r.cmdStat(args, stdout, stderr)
	case "df":
		return r.cmdDf(stdout)
	case "du":
		return r.cmdDu(args, stdout, stderr)
	case "ps":
		return r.cmdPs(stdout)
	case "getprop":
		return r.cmdGetprop(args, stdout)
	case "setprop":
		return r.cmdSetprop(args, stderr)
	case "id":
		fmt.Fprintln(stdout, "uid=0(root) gid=0(root) groups=0(root),1000(system)")
	case "whoami":
		fmt.Fprintln(stdout, "shell")
	case "uname":
		if len(args) > 0 && args[0] == "-a" {
			fmt.Fprintf(stdout, "Linux localhost 5.15.123-android14 #1 SMP PREEMPT aarch64 Android\n")
			return 0
		}
		fmt.Fprintln(stdout, "Linux")
	case "env":
		keys := make([]string, 0, len(r.env))
		for k := range r.env {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(stdout, "%s=%s\n", k, r.env[k])
		}
	case "sleep":
		if len(args) != 1 {
			fmt.Fprintln(stderr, "sleep: usage: sleep N")
			return 2
		}
		secs, err := strconv.ParseFloat(args[0], 64)
		if err != nil || secs < 0 {
			fmt.Fprintln(stderr, "sleep: invalid duration")
			return 2
		}
		time.Sleep(time.Duration(secs * float64(time.Second)))
	case "true":
		return 0
	case "false", "fail":
		return 1
	case "exit":
		return r.cmdExit(args, stderr)
	default:
		// 127 is what a real shell reports, and code depends on distinguishing "no such
		// command" from "the command failed".
		fmt.Fprintf(stderr, "mockadbd: %s: command not found\n", cmd)
		return 127
	}
	return 0
}

func (r *shellRunner) cmdCd(args []string, stderr io.Writer) int {
	target := r.cwd
	if len(args) > 0 {
		target = r.abs(args[0])
	}
	if !r.fs.IsDir(target) {
		// Into the command's stderr, not the process's: a test asserting on output would
		// otherwise see nothing and a leaked message would land in the test runner's log.
		fmt.Fprintf(stderr, "cd: %s: No such file or directory\n", target)
		return 1
	}
	r.cwd = target
	r.env["PWD"] = target
	return 0
}

// cmdLs lists a directory or describes files.
//
// -l is the long form and is what a test actually wants, because it shows size and mode.
// Names are printed one per line rather than in columns: column layout depends on terminal
// width, and a simulator has no terminal, so the one-per-line form is both what adb gets
// and something a test can assert on exactly.
func (r *shellRunner) cmdLs(args []string, stdout, stderr io.Writer) int {
	long := false
	var paths []string
	for _, a := range args {
		switch {
		case a == "-l" || a == "-la" || a == "-al":
			long = true
		case strings.HasPrefix(a, "-"):
			fmt.Fprintf(stderr, "ls: unsupported option %s\n", a)
			return 2
		default:
			paths = append(paths, a)
		}
	}
	if len(paths) == 0 {
		paths = []string{r.cwd}
	}
	rc := 0
	for _, p := range paths {
		full := r.abs(p)
		n, err := r.fs.Stat(full)
		switch {
		case err != nil:
			fmt.Fprintf(stderr, "ls: %s: No such file or directory\n", p)
			rc = 1
		case !n.Dir:
			fmt.Fprintln(stdout, p)
		default:
			entries, err := r.fs.ReadDir(full)
			if err != nil {
				fmt.Fprintf(stderr, "ls: %s: %v\n", p, err)
				rc = 1
				continue
			}
			for _, e := range entries {
				if long {
					fmt.Fprintf(stdout, "%s %8d %s %s\n",
						formatMode(e.Dir, e.Mode), len(e.Data),
						e.ModTime.UTC().Format("Jan _2 15:04"), e.Name)
				} else {
					fmt.Fprintln(stdout, e.Name)
				}
			}
		}
	}
	return rc
}

// formatMode renders a mode the way ls does: a type character then nine permission
// characters. Written out bit by bit rather than with FileMode.String(), because that
// renders the type differently depending on which other bits are set and produced an
// extra leading dash.
func formatMode(dir bool, mode os.FileMode) string {
	kind := byte('-')
	if dir {
		kind = 'd'
	}
	const rwx = "rwxrwxrwx"
	perm := mode.Perm()
	out := make([]byte, 0, 10)
	out = append(out, kind)
	for i := 0; i < 9; i++ {
		if perm&(1<<uint(8-i)) != 0 {
			out = append(out, rwx[i])
		} else {
			out = append(out, '-')
		}
	}
	return string(out)
}

func (r *shellRunner) cmdCat(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		// cat with no argument copies stdin, which is how it is used in a pipeline and why
		// the round-trip test exercises the stdin path at all.
		_, _ = io.Copy(stdout, stdin)
		return 0
	}
	rc := 0
	for _, p := range args {
		data, err := r.fs.ReadFile(r.abs(p))
		if err != nil {
			fmt.Fprintf(stderr, "cat: %s: No such file or directory\n", p)
			rc = 1
			continue
		}
		stdout.Write(data)
	}
	return rc
}

func (r *shellRunner) cmdMkdir(args []string, stderr io.Writer) int {
	parents := false
	var paths []string
	for _, a := range args {
		if a == "-p" {
			parents = true
			continue
		}
		paths = append(paths, a)
	}
	if len(paths) == 0 {
		fmt.Fprintln(stderr, "mkdir: missing operand")
		return 2
	}
	rc := 0
	for _, p := range paths {
		full := r.abs(p)
		if parents {
			if err := r.fs.MkdirAll(full, 0o755); err != nil {
				fmt.Fprintf(stderr, "mkdir: %s: %v\n", p, err)
				rc = 1
			}
			continue
		}
		if r.fs.Exists(full) {
			fmt.Fprintf(stderr, "mkdir: cannot create directory '%s': File exists\n", p)
			rc = 1
			continue
		}
		if err := r.fs.MkdirAll(full, 0o755); err != nil {
			fmt.Fprintf(stderr, "mkdir: %s: %v\n", p, err)
			rc = 1
		}
	}
	return rc
}

func (r *shellRunner) cmdRm(args []string, stderr io.Writer) int {
	recursive := false
	var paths []string
	for _, a := range args {
		if a == "-r" || a == "-rf" || a == "-fr" {
			recursive = true
			continue
		}
		paths = append(paths, a)
	}
	if len(paths) == 0 {
		fmt.Fprintln(stderr, "rm: missing operand")
		return 2
	}
	rc := 0
	for _, p := range paths {
		var err error
		if recursive {
			err = r.fs.RemoveAll(r.abs(p))
		} else {
			err = r.fs.Remove(r.abs(p))
		}
		if err != nil {
			fmt.Fprintf(stderr, "rm: %s: %v\n", p, err)
			rc = 1
		}
	}
	return rc
}

func (r *shellRunner) cmdMv(args []string, stderr io.Writer) int {
	if len(args) != 2 {
		fmt.Fprintln(stderr, "mv: usage: mv SRC DST")
		return 2
	}
	if err := r.fs.Rename(r.abs(args[0]), r.abs(args[1])); err != nil {
		fmt.Fprintf(stderr, "mv: %v\n", err)
		return 1
	}
	return 0
}

func (r *shellRunner) cmdCp(args []string, stderr io.Writer) int {
	if len(args) != 2 {
		fmt.Fprintln(stderr, "cp: usage: cp SRC DST")
		return 2
	}
	data, err := r.fs.ReadFile(r.abs(args[0]))
	if err != nil {
		fmt.Fprintf(stderr, "cp: %s: %v\n", args[0], err)
		return 1
	}
	if err := r.fs.WriteFile(r.abs(args[1]), data, 0o644); err != nil {
		fmt.Fprintf(stderr, "cp: %s: %v\n", args[1], err)
		return 1
	}
	return 0
}

func (r *shellRunner) cmdStat(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "stat: missing operand")
		return 2
	}
	rc := 0
	for _, p := range args {
		full := r.abs(p)
		n, err := r.fs.Stat(full)
		if err != nil {
			fmt.Fprintf(stderr, "stat: cannot stat '%s': No such file or directory\n", p)
			rc = 1
			continue
		}
		kind := "regular file"
		if n.Dir {
			kind = "directory"
		}
		fmt.Fprintf(stdout, "  File: %s\n", full)
		fmt.Fprintf(stdout, "  Size: %d\tType: %s\n", len(n.Data), kind)
		fmt.Fprintf(stdout, "Access: (%s)  Uid: (0/%s)  Gid: (0/%s)\n", formatMode(n.Dir, n.Mode), "root", "root")
		fmt.Fprintf(stdout, "Modify: %s\n", n.ModTime.UTC().Format("2006-01-02 15:04:05.000000000 -0700"))
	}
	return rc
}

// cmdDf reports a plausible filesystem.
//
// The sizes are constants rather than derived from the tree, and that is on purpose: df
// reports the partition, which is much larger than whatever a test has written into it.
// Deriving them would make a test that pushed a megabyte report a megabyte free.
func (r *shellRunner) cmdDf(stdout io.Writer) int {
	const total = 128 * 1024 * 1024 * 1024
	const free = 64 * 1024 * 1024 * 1024
	fmt.Fprintln(stdout, "Filesystem     1K-blocks    Used Available Use% Mounted on")
	fmt.Fprintf(stdout, "/dev/block/dm-5 %10d %7d %9d %3d%% /\n",
		total/1024, (total-free)/1024, free/1024, (total-free)*100/total)
	return 0
}

func (r *shellRunner) cmdDu(args []string, stdout, stderr io.Writer) int {
	summary := false
	var paths []string
	for _, a := range args {
		if a == "-s" {
			summary = true
			continue
		}
		paths = append(paths, a)
	}
	if len(paths) == 0 {
		paths = []string{r.cwd}
	}
	rc := 0
	for _, p := range paths {
		full := r.abs(p)
		n, err := r.fs.Stat(full)
		if err != nil {
			fmt.Fprintf(stderr, "du: %s: No such file or directory\n", p)
			rc = 1
			continue
		}
		if n.Dir {
			// A directory's own size is what a recursive walk would total.
			_ = summary
			fmt.Fprintf(stdout, "%d\t%s\n", r.treeSize(full), full)
			continue
		}
		fmt.Fprintf(stdout, "%d\t%s\n", len(n.Data), full)
	}
	return rc
}

// treeSize totals a subtree. The VFS already knows how to do this.
func (r *shellRunner) treeSize(p string) int64 {
	entries, err := r.fs.ReadDir(p)
	if err != nil {
		n, err := r.fs.Stat(p)
		if err != nil {
			return 0
		}
		return int64(len(n.Data))
	}
	var total int64
	for _, e := range entries {
		total += r.treeSize(strings.TrimRight(p, "/") + "/" + e.Name)
	}
	return total
}

// cmdPs lists a stable set of processes.
//
// Fixed content, and deliberately so: a test that greps ps output wants the same answer
// every run, and a simulator inventing process tables would make assertions racy.
func (r *shellRunner) cmdPs(stdout io.Writer) int {
	fmt.Fprintln(stdout, "USER           PID  PPID     VSZ    RSS WCHAN            ADB S")
	rows := []struct {
		user, name string
		pid, ppid  int
	}{
		{"root", "init", 1, 0},
		{"root", "kthreadd", 2, 0},
		{"system", "zygote64", 1192, 1},
		{"root", "adbd", 1301, 1},
		{"shell", "sh", 2100, 1301},
		{"shell", "mockadbd", 2101, 2100},
	}
	for _, r2 := range rows {
		fmt.Fprintf(stdout, "%-8s %6d %6d %8d %6d 0000000000000000 S %s\n",
			r2.user, r2.pid, r2.ppid, 1<<20, 4096, r2.name)
	}
	return 0
}

func (r *shellRunner) cmdGetprop(args []string, stdout io.Writer) int {
	switch len(args) {
	case 0:
		for _, kv := range r.props.All() {
			fmt.Fprintln(stdout, kv)
		}
		return 0
	case 1:
		if !r.props.Has(args[0]) {
			// Real getprop prints nothing and exits zero for an unknown key, which is the
			// behaviour that makes `getprop | grep` the idiom it is.
			return 0
		}
		fmt.Fprintln(stdout, r.props.Get(args[0]))
		return 0
	default:
		// getprop name default -- print the value only when it is missing.
		v := r.props.Get(args[0])
		if v == "" && args[1] != "" {
			v = args[1]
		}
		fmt.Fprintln(stdout, v)
		return 0
	}
}

// cmdExit ends the session.
//
// Three cases, and all three are observable on a device, so all three are here:
//
//   - `exit` alone exits with the status of the last command, which is why
//     `false; exit` reports 1 rather than 0. For a one-shot `adb shell 'exit'` there is no
//     last command and the status is 0.
//   - `exit N` exits with N, truncated to a byte because that is the only thing the shell
//     protocol has room for. `exit 300` is 44, matching what a device reports.
//   - `exit abc` is a usage error: a message on stderr and status 1. Silently exiting 0
//     there would hide a typo in a script that goes on to assert on the status.
func (r *shellRunner) cmdExit(args []string, stderr io.Writer) int {
	r.exited = true
	r.exitCode = r.last
	switch len(args) {
	case 0:
		return r.last
	case 1:
		n, err := strconv.Atoi(args[0])
		if err != nil {
			fmt.Fprintf(stderr, "exit: bad number: %s\n", args[0])
			r.exitCode = 1
			return 1
		}
		// One byte. The v2 exit frame holds a single byte, so a status above 255 truncates
		// here rather than being reported in full and then mangled on the way out. A device
		// behaves the same way; `exit 300` gives 44.
		r.exitCode = n & 0xFF
		return r.exitCode
	default:
		fmt.Fprintf(stderr, "exit: usage: exit [N]\n")
		r.exitCode = 2
		return 2
	}
}

func (r *shellRunner) cmdSetprop(args []string, stderr io.Writer) int {
	if len(args) != 2 {
		fmt.Fprintln(stderr, "setprop: usage: setprop NAME VALUE")
		return 2
	}
	r.props.Set(args[0], args[1])
	return 0
}
