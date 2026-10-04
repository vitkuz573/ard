// Package adbdloc finds adbd's address on a device.
//
// Why this exists: after a reboot, adbd has no network socket at all. Enabling one
// requires either USB, or Android 11+ wireless debugging — and wireless debugging
// binds to a DIFFERENT PORT on every boot. So an agent that remembers an address
// finds it correct once and wrong forever after.
//
// What the agent cannot do, and this package does not pretend otherwise:
// it cannot make adbd appear. That needs USB, wireless debugging, or root. The
// honest behaviour is to find the address when one exists and otherwise say
// precisely what a human has to do.
package adbdloc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// ErrNotFound means no adbd socket answered anywhere we looked.
var ErrNotFound = errors.New("adbd: no socket found")

// Well-known ports, tried first.
//
// 5555 is the classic ADB port. 5557-5559 are what "adb tcpip" commonly uses.
// They are cheap to try and, being low, are what a manual setup ends up using.
var wellKnown = []int{5555, 5557, 5558, 5559, 5560, 5561, 5562, 5563, 5564}

// dynamicLow and dynamicHigh bound the scan for a random wireless-debugging port.
//
// Android allocates the wireless debugging port from the ephemeral range, which on
// Linux is typically 32768-60999. Scanning it is not free but it is bounded, runs
// off the hot path, and a wrong guess costs one refused connect. The alternative —
// asking a human for a port that changes every boot — is worse.
const (
	dynamicLow  = 32768
	dynamicHigh = 60999
)

// Options tunes discovery.
type Options struct {
	// Timeout bounds a single connect attempt. Kept short: refused connections on a
	// closed port return immediately, so a long timeout only hurts.
	Timeout time.Duration
	// SkipDynamic disables the ephemeral range scan. Useful in tests and when a
	// device is known to use a fixed port.
	SkipDynamic bool
	// Hosts overrides the addresses to try. Empty means "derive from interfaces".
	Hosts []string
}

// Find returns the address of adbd, host:port.
//
// Addresses are tried in order of preference: loopback first, because adbd bound
// there is reachable no matter which networks are up, and the device's own
// routable addresses afterwards for the case where it bound only to WiFi.
func Find(ctx context.Context, opt Options) (string, error) {
	if opt.Timeout == 0 {
		opt.Timeout = 400 * time.Millisecond
	}
	hosts := opt.Hosts
	if len(hosts) == 0 {
		hosts = candidates()
	}
	ports := wellKnown
	if !opt.SkipDynamic {
		ports = append(append([]int{}, ports...), dynamicRange()...)
	}

	var firstErr error
	for _, port := range ports {
		for _, host := range hosts {
			if err := ctx.Err(); err != nil {
				return "", err
			}
			addr := net.JoinHostPort(host, fmt.Sprint(port))
			d := net.Dialer{Timeout: opt.Timeout}
			conn, err := d.DialContext(ctx, "tcp", addr)
			if err != nil {
				if firstErr == nil && !isRefused(err) {
					firstErr = err
				}
				continue
			}
			ok, verr := speaksAdbd(ctx, conn)
			_ = conn.Close()
			if verr != nil {
				if firstErr == nil {
					firstErr = verr
				}
				continue
			}
			if !ok {
				continue
			}
			return addr, nil
		}
	}
	if firstErr != nil {
		return "", fmt.Errorf("%w (last error: %v)", ErrNotFound, firstErr)
	}
	return "", ErrNotFound
}

// Resolvable resolves a configured address, falling back to discovery.
//
// This is the behaviour an agent wants on every session start: trust the configured
// value when it works, because that is the common case and costs nothing, but never
// depend on it. The port that worked yesterday is not evidence about today.
func Resolvable(ctx context.Context, configured string, opt Options) (string, error) {
	if configured != "" {
		d := net.Dialer{Timeout: opt.Timeout}
		conn, err := d.DialContext(ctx, "tcp", configured)
		if err == nil {
			_ = conn.Close()
			return configured, nil
		}
	}
	found, err := Find(ctx, opt)
	if err != nil {
		if configured != "" {
			return "", fmt.Errorf("adbd: configured address %s unreachable (%v) and %w", configured, err, ErrNotFound)
		}
		return "", err
	}
	return found, nil
}

// ADB packet constants, needed to tell adbd from anything else that listens.
//
// A bare connect proves nothing. Scanning the ephemeral range on a real phone
// turns up dozens of sockets belonging to other apps and services — on this
// machine a Steam socket was the first thing found. Accepting the first listener
// would point the agent at a random service and fail with a protocol error much
// later, far from the cause. So the probe speaks ADB and checks the reply.
const (
	cmdCNXN uint32 = 0x4e584e43
	cmdAUTH uint32 = 0x48545541

	// adbVersionSkipChecksum is the version that skips the payload checksum, the one
	// every current adb sends. The magic field has been command ^ 0xFFFFFFFF since
	// long before that and is still what identifies a packet.
	adbVersionSkipChecksum uint32 = 0x01000001

	adbHeaderLen = 24
)

// speaksAdbd reports whether conn answered a CNXN with a well-formed ADB packet.
//
// adbd may answer with AUTH when it demands authentication, or with CNXN when it
// does not. Both are valid; anything else means this is some other service that
// happened to accept our connection.
func speaksAdbd(ctx context.Context, conn net.Conn) (bool, error) {
	if dl, ok := conn.(interface{ SetDeadline(time.Time) error }); ok {
		_ = dl.SetDeadline(time.Now().Add(verifyTimeout))
	}
	var hdr [adbHeaderLen]byte
	le32(hdr[0:4], cmdCNXN)
	le32(hdr[4:8], adbVersionSkipChecksum)
	le32(hdr[8:12], 1<<20) // advertised max payload
	le32(hdr[12:16], 0)    // no payload
	le32(hdr[16:20], 0)    // checksum unused at this version
	le32(hdr[20:24], cmdCNXN^0xFFFFFFFF)
	if _, err := conn.Write(hdr[:]); err != nil {
		return false, fmt.Errorf("adbdloc: probe write: %w", err)
	}
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		// A service that accepts the connection and then says nothing is not adbd.
		return false, nil
	}
	cmd := readLE(hdr[0:4])
	magic := readLE(hdr[20:24])
	if magic != cmd^0xFFFFFFFF {
		return false, nil
	}
	switch cmd {
	case cmdCNXN, cmdAUTH:
		return true, nil
	default:
		return false, nil
	}
}

// verifyTimeout bounds the protocol probe. adbd replies immediately to CNXN, so
// anything slower is not it.
const verifyTimeout = 2 * time.Second

func le32(b []byte, v uint32) {
	b[0], b[1], b[2], b[3] = byte(v), byte(v>>8), byte(v>>16), byte(v>>24)
}

func readLE(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

// candidates returns the addresses to try, loopback first.
func candidates() []string {
	out := []string{"127.0.0.1"}
	for _, ip := range localIPv4() {
		if ip == "127.0.0.1" {
			continue
		}
		out = append(out, ip)
	}
	// ::1 last: adbd has historically bound IPv4 loopback, and an IPv6 connect to a
	// v4-only socket wastes a timeout.
	out = append(out, "::1")
	return out
}

func dynamicRange() []int {
	out := make([]int, 0, dynamicHigh-dynamicLow)
	for p := dynamicLow; p <= dynamicHigh; p++ {
		out = append(out, p)
	}
	return out
}

// localIPv4 lists the device's own routable addresses. The agent runs on the
// device, so it must try the addresses it holds itself: adbd bound to WiFi is not
// reachable through loopback.
func localIPv4() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []string
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipnet.IP.To4()
			if ip4 == nil || ip4.IsLoopback() || ip4.IsLinkLocalUnicast() {
				continue
			}
			out = append(out, ip4.String())
		}
	}
	return out
}

func isRefused(err error) bool {
	var oe *net.OpError
	if errors.As(err, &oe) {
		return oe.Err != nil && oe.Err.Error() != "" &&
			(contains(oe.Err.Error(), "connection refused") ||
				contains(oe.Err.Error(), "no route to host"))
	}
	return false
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && indexOf(s, sub) >= 0
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// IsNotFound reports whether the error means "no adbd answered", as opposed to
// the search itself failing.
//
// The distinction matters for the message an operator gets: "enable wireless
// debugging" is useful when nothing was found, and misleading when the network is
// down.
func IsNotFound(err error) bool { return errors.Is(err, ErrNotFound) }
