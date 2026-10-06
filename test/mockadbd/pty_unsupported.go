//go:build !linux

package mockadbd

import (
	"errors"
	"io"
	"os"
)

// A pty is only allocated on linux. Elsewhere the mock still builds and still serves
// `adb shell -t`, it just has no terminal behind it: openPTY reports ErrNoPTY and the
// session falls back to a pipe and says so. Failing the session outright would make the
// mock unusable on a developer machine for a reason that has nothing to do with what it is
// for, and the ioctl numbers in pty_linux.go are architecture-specific rather than merely
// platform-specific -- there is no portable spelling of TIOCGPTN to check at runtime.
//
// The behaviour a pty provides on linux and not here: echo of typed input, CRLF line
// endings on output, a window size the host can change, canonical line buffering with its
// 4096-byte limit, and EIO on the slave once the master closes.

var ErrNoPTY = errors.New("mockadbd: no pty available")

type pty struct {
	master *os.File
	slave  *os.File
}

func openPTY() (*pty, error) { return nil, ErrNoPTY }

func (p *pty) Close() error { return nil }

// resize reports that there is no terminal to resize. Callers treat it as best effort
// rather than as a session failure.
func (p *pty) resize(rows, cols uint16) error { return ErrNoPTY }

// compile-time check that the stub satisfies the same shape as the linux implementation,
// so a session cannot grow a method on one platform and not the other.
var _ io.Closer = (*pty)(nil)
