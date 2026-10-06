//go:build linux

package mockadbd

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// A real pseudo-terminal pair, allocated the way a real adbd does when it is asked for
// one: open /dev/ptmx, unlock it, ask the kernel which pts device it is, then open that
// device as the slave.
//
// The standard library has no pty package, and pulling in golang.org/x/sys for three
// ioctls is not worth it for a test fixture, so the calls are made directly. This is
// linux-only, matching where the mock is built and run; pty_unsupported.go stands in
// elsewhere so the package still compiles.
//
// The alternative was to emulate the observable behaviour -- echo, CRLF, a window size --
// inside the mock and call the result a terminal. That is deliberately not done. A pty
// has behaviour emulation gets wrong and that a test would then be written against:
// canonical input buffering with a 4096-byte line limit, a 4096-byte output queue that
// blocks the writer, signal generation, and the EIO a slave read returns once the master
// is closed. Allocating the real thing is less code than justifying the fake one.

// Linux ioctl request numbers. These are architecture-specific -- the _IOC flag bits
// differ between architectures -- so each is spelled out rather than derived from a
// TIOC-prefixed constant that only exists on some of them.
const (
	// tiocGPTN returns the pty number of a master.
	tiocGPTN = 0x80045430
	// tiocSPTLCK unlocks (0) or locks (1) a master.
	tiocSPTLCK = 0x40045431
	// tiocSWINSZ sets the window size on a slave.
	tiocSWINSZ = 0x5414
	// tiocGWINSZ reads it back.
	tiocGWINSZ = 0x5413
)

// winsize is struct winsize from <asm-generic/ioctls.h>. Field order and types are the
// kernel's and cannot be rearranged.
type winsize struct {
	rows uint16
	cols uint16
	x    uint16
	y    uint16
}

// ErrNoPTY says a terminal could not be allocated.
//
// It is not fatal. A session that asked for one falls back to a pipe and says so on
// stderr, because a mock that refuses the session outright is worse than one that
// degrades, and because a machine without /dev/ptmx should still run the suite.
var ErrNoPTY = errors.New("mockadbd: no pty available")

// pty is an allocated pseudo-terminal pair.
//
// master is the end the host talks to: its bytes are input to the terminal, and the
// terminal's output is read from it. slave is the end a process would be attached to.
// Both are *os.File rather than an io.Reader/io.Writer pair because a session reads lines
// from the slave and writes the slave's output through to the host, and an abstraction
// here would hide exactly the queueing that makes a pty behave like a pty.
type pty struct {
	master *os.File
	slave  *os.File
}

// openPTY allocates a pty pair.
//
// The termios is left as the kernel set it, which is already the conventional terminal
// state: canonical input, echo on, ISIG, ICRNL, and ONLCR so a bare newline written to
// the slave reaches the host as CRLF. That is what makes a real device echo what was
// typed and end its lines with \r\n, and it is the kernel doing it rather than the mock
// writing an extra \r. Overriding it would mean claiming the behaviour while also being
// the thing that produces it.
func openPTY() (*pty, error) {
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: open /dev/ptmx: %v", ErrNoPTY, err)
	}
	// A newly opened master is locked, and until it is unlocked the slave cannot be
	// opened at all. The failure then reads "no such device", which points at the wrong
	// thing entirely.
	var unlock int32
	if err := ioctlPtr(master.Fd(), tiocSPTLCK, unsafe.Pointer(&unlock)); err != nil {
		master.Close()
		return nil, fmt.Errorf("%w: TIOCSPTLCK: %v", ErrNoPTY, err)
	}
	var number uint32
	if err := ioctlPtr(master.Fd(), tiocGPTN, unsafe.Pointer(&number)); err != nil {
		master.Close()
		return nil, fmt.Errorf("%w: TIOCGPTN: %v", ErrNoPTY, err)
	}
	name := fmt.Sprintf("/dev/pts/%d", number)
	slave, err := os.OpenFile(name, os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		master.Close()
		return nil, fmt.Errorf("%w: open %s: %v", ErrNoPTY, name, err)
	}
	return &pty{master: master, slave: slave}, nil
}

// ioctlPtr issues an ioctl whose argument is a pointer to a value.
//
// syscall.Syscall rather than a typed wrapper, because there is no ioctl in the standard
// library and the request number is architecture-specific. All this asserts is that the
// pointer reaches the kernel unchanged.
func ioctlPtr(fd, request uintptr, arg unsafe.Pointer) error {
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, request, uintptr(arg)); errno != 0 {
		return errno
	}
	return nil
}

// Close releases both ends. The master goes first: closing it is what unblocks a read on
// the slave, so closing the slave first would leave a reader waiting on a terminal whose
// other end is still open.
func (p *pty) Close() error {
	err := p.master.Close()
	if serr := p.slave.Close(); err == nil {
		err = serr
	}
	return err
}

// resize sets the terminal's window size and reads it back.
//
// The read-back is not ceremony. TIOCSWINSZ is a request with no error return for a size
// the kernel dislikes, so a session can otherwise believe it resized a terminal that did
// not -- and the whole point of handling kIdWindowSizeChange is that a resized terminal
// is observable. Asking TIOCGWINSZ is the difference between claiming a window size and
// having one.
func (p *pty) resize(rows, cols uint16) error {
	ws := winsize{rows: rows, cols: cols}
	if err := ioctlPtr(p.slave.Fd(), tiocSWINSZ, unsafe.Pointer(&ws)); err != nil {
		return err
	}
	var got winsize
	if err := ioctlPtr(p.slave.Fd(), tiocGWINSZ, unsafe.Pointer(&got)); err != nil {
		return err
	}
	if got.rows != rows || got.cols != cols {
		return fmt.Errorf("mockadbd: pty window is %dx%d after asking for %dx%d",
			got.cols, got.rows, cols, rows)
	}
	return nil
}
