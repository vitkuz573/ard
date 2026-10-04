// Command ard-agent runs on a device and exposes its ADB daemon to the gateway.
//
// It dials out and stays connected. That is the only viable direction: the device
// is normally behind NAT, often behind carrier-grade NAT, so the gateway cannot
// reach it. The agent therefore holds one outbound TLS connection and serves
// every operator session multiplexed over it.
//
// It talks to adbd over the device's own loopback interface. adbd never listens on
// any other interface, and this program never changes that: ADB has no
// authentication of its own, so an exposed adbd is an open door onto the phone.
package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/vitkuz573/ard/internal/hs"
	"github.com/vitkuz573/ard/internal/tlsx"
	"github.com/vitkuz573/ard/internal/transport"
)

const version = "0.1.0"

// handshakeTimeout bounds connection setup so a stalled gateway produces a log
// line rather than an indefinite block.
const handshakeTimeout = 30 * time.Second

type config struct {
	gateway    string
	serverName string
	deviceID   string
	deviceName string
	adbdAddr   string

	caPath     string
	certPath   string
	keyPath    string
	heartbeat  time.Duration
	maxBackoff time.Duration
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "ard-agent:", err)
		os.Exit(1)
	}
}

func run() error {
	var cfg config
	flag.StringVar(&cfg.gateway, "gateway", "", "gateway address, host:port (required)")
	flag.StringVar(&cfg.serverName, "server-name", "", "TLS server name to verify (defaults to the gateway host)")
	flag.StringVar(&cfg.deviceID, "device", "", "device UUID this agent identifies as (required)")
	flag.StringVar(&cfg.deviceName, "name", "", "human-readable label shown to operators")
	flag.StringVar(&cfg.adbdAddr, "adbd", "127.0.0.1:5555", "adbd address on this device's loopback")
	flag.StringVar(&cfg.caPath, "ca", "", "server CA certificate (required)")
	flag.StringVar(&cfg.certPath, "cert", "", "this device's certificate (required)")
	flag.StringVar(&cfg.keyPath, "key", "", "this device's private key (required)")
	flag.DurationVar(&cfg.heartbeat, "heartbeat", 30*time.Second, "gateway heartbeat interval")
	flag.DurationVar(&cfg.maxBackoff, "max-backoff", 2*time.Minute, "ceiling for reconnect backoff")
	flag.Parse()

	missing := func(name, value string) {
		if value == "" {
			fmt.Fprintf(os.Stderr, "ard-agent: -%s is required\n", name)
			os.Exit(2)
		}
	}
	missing("gateway", cfg.gateway)
	missing("device", cfg.deviceID)
	missing("ca", cfg.caPath)
	missing("cert", cfg.certPath)
	missing("key", cfg.keyPath)
	if cfg.serverName == "" {
		if host, _, err := net.SplitHostPort(cfg.gateway); err == nil {
			cfg.serverName = host
		}
	}
	if cfg.deviceName == "" {
		cfg.deviceName = cfg.deviceID
	}

	log.SetFlags(log.LstdFlags | log.LUTC)
	log.SetPrefix("ard-agent: ")
	log.Printf("version %s, device %s, gateway %s, adbd %s",
		version, cfg.deviceID, cfg.gateway, cfg.adbdAddr)

	// Fail fast on a missing adbd rather than looping forever against a device
	// where USB debugging was never enabled. This is the single most common
	// onboarding failure and it is much easier to diagnose as a startup error.
	if err := probeAdbd(cfg.adbdAddr); err != nil {
		return fmt.Errorf("adbd is not reachable at %s: %w\n"+
			"enable Developer options and USB debugging on the device, or pair over Wi-Fi, then retry",
			cfg.adbdAddr, err)
	}

	ca, err := tlsx.LoadCA(filepath.Dir(cfg.caPath))
	if err != nil {
		return fmt.Errorf("load server CA: %w", err)
	}
	id, err := tlsx.LoadIdentity(trimExt(cfg.certPath))
	if err != nil {
		return fmt.Errorf("load device identity: %w", err)
	}
	if id.OrgUnit != tlsx.OrgUnitDevice {
		return fmt.Errorf("certificate %s is for role %q, not %q",
			cfg.certPath, id.OrgUnit, tlsx.OrgUnitDevice)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	backoff := newBackoff(cfg.maxBackoff)
	for {
		if ctx.Err() != nil {
			return nil
		}
		wait := backoff.next()
		if err := serve(ctx, cfg, ca, id); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			log.Printf("session ended: %v; reconnecting in %s", err, wait.Round(time.Second))
		} else {
			wait = backoff.next()
			log.Printf("session ended; reconnecting in %s", wait.Round(time.Second))
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
	}
}

// serve runs one connection to completion.
func serve(ctx context.Context, cfg config, ca *tlsx.CA, id *tlsx.Identity) error {
	tlsCfg, err := tlsx.ClientTLS(ca, id, cfg.serverName, 0)
	if err != nil {
		return err
	}
	dialer := &net.Dialer{Timeout: 20 * time.Second, KeepAlive: 30 * time.Second}
	raw, err := dialer.DialContext(ctx, "tcp", cfg.gateway)
	if err != nil {
		return fmt.Errorf("dial gateway: %w", err)
	}
	defer raw.Close()

	// A handshake deadline is mandatory. Without one, a gateway that accepts the
	// TCP connection and then stalls leaves the agent blocked forever with no log
	// line explaining why.
	_ = raw.SetDeadline(time.Now().Add(handshakeTimeout))
	conn := tls.Client(raw, tlsCfg)
	if err := conn.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("TLS handshake: %w", err)
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return fmt.Errorf("clear handshake deadline: %w", err)
	}

	// The peer certificate must be checked here as well as by crypto/tls, because
	// a device certificate must never be usable on the operator leg.
	if _, err := tlsx.VerifyPeerRole(conn.ConnectionState(), tlsx.OrgUnitServer); err != nil {
		return fmt.Errorf("peer role: %w", err)
	}

	// A completed TLS handshake is not authorization: under TLS 1.3 the peer
	// verifies our certificate after we consider the handshake done, and the
	// rejection arrives later. The WELCOME reply is the actual decision.
	welcome, err := hs.ClientHandshake(conn, hs.Hello{
		Device: cfg.deviceID,
		Name:   cfg.deviceName,
		Agent:  version,
	})
	if err != nil {
		return err
	}
	log.Printf("connected, session %s", welcome.Session)

	session, err := transport.New(conn, cfg.deviceID, cfg.deviceName)
	if err != nil {
		return err
	}
	defer session.Close()

	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
		case <-done:
		}
		_ = conn.Close()
	}()

	log.Printf("serving")
	return session.Accept(ctx, func(route hs.Route, stream net.Conn) error {
		return handleStream(route, stream, cfg.adbdAddr)
	})
}

// handleStream pipes one operator stream to adbd.
//
// Each stream gets its own adbd connection. That is deliberate: holding a single
// adbd connection and multiplexing over it protects against adbd replacing a host
// connection on reconnect, but it also serialises unrelated sessions behind one
// socket. With a real adb server there is normally one transport per device
// anyway, so the multiplexing case does not arise; if concurrent transports are
// ever observed to upset adbd, this is the place to reintroduce it.
func handleStream(route hs.Route, stream net.Conn, adbdAddr string) error {
	if route.Kind != hs.KindADB {
		log.Printf("stream %s: unsupported kind %q", route.Stream, route.Kind)
		return fmt.Errorf("unsupported stream kind %q", route.Kind)
	}
	upstream, err := net.DialTimeout("tcp", adbdAddr, 10*time.Second)
	if err != nil {
		log.Printf("stream %s: dial adbd: %v", route.Stream, err)
		return err
	}
	defer upstream.Close()

	done := make(chan error, 2)
	go func() {
		_, err := io.Copy(upstream, stream)
		if cw, ok := upstream.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		done <- err
	}()
	go func() {
		_, err := io.Copy(stream, upstream)
		if cw, ok := stream.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		done <- err
	}()
	err = <-done
	log.Printf("stream %s: finished (%v)", route.Stream, err)
	return err
}

// probeAdbd checks that adbd is listening before entering the reconnect loop.
func probeAdbd(addr string) error {
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return err
	}
	return c.Close()
}

// backoff produces growing reconnect delays with jitter.
type backoff struct {
	cur    time.Duration
	max    time.Duration
	jitter func(time.Duration) time.Duration
}

func newBackoff(max time.Duration) *backoff {
	return &backoff{cur: time.Second, max: max, jitter: defaultJitter}
}

func (b *backoff) next() time.Duration {
	d := b.cur
	if b.cur < b.max {
		b.cur *= 2
		if b.cur > b.max {
			b.cur = b.max
		}
	}
	return b.jitter(d)
}

// defaultJitter spreads reconnects so a fleet of devices recovering from an outage
// does not arrive at the gateway in lockstep.
func defaultJitter(d time.Duration) time.Duration {
	if d <= 0 {
		return time.Second
	}
	return d/2 + time.Duration(float64(d)*0.5*randomFraction())
}

func trimExt(p string) string {
	for _, ext := range []string{".crt", ".pem"} {
		if len(p) > len(ext) && p[len(p)-len(ext):] == ext {
			return p[:len(p)-len(ext)]
		}
	}
	return p
}

// randomInt returns a uniform value in [0,n). It is used for jitter only, so a
// failure is not worth propagating.
func randomInt(n int64) int64 {
	v, err := rand.Int(rand.Reader, big.NewInt(n))
	if err != nil {
		return n / 2
	}
	return v.Int64()
}

func randomFraction() float64 { return float64(randomInt(65536)) / 65536.0 }
