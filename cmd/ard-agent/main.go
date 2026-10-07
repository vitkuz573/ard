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
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/vitkuz573/ard/internal/adbdloc"
	"github.com/vitkuz573/ard/internal/adbserverproto"
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

// Limits on how hard this device is asked to work.
//
// agentDialSlots bounds connections to adbd at once. Four is deliberately above the one
// the gateway's adb server normally produces, so the cap only bites when something is
// wrong rather than during ordinary use.
var agentDialSlots = make(chan struct{}, 4)

const (
	// agentDialWait is how long a stream waits for a free adbd slot before giving up.
	agentDialWait = 10 * time.Second
	// agentStallTimeout is how long a stream may carry no bytes before it is considered
	// dead. Long enough to survive a genuinely slow transfer, short enough that an
	// operator finds out within a coffee break rather than an afternoon.
	agentStallTimeout = 5 * time.Minute
	// agentStallCheck is how often the watchdog looks.
	agentStallCheck = 30 * time.Second
)

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
	flag.StringVar(&cfg.adbdAddr, "adbd", "", "address of adbd on this device; discovered when empty")
	flag.StringVar(&cfg.caPath, "ca", "", "path to the server CA certificate file (required)")
	flag.StringVar(&cfg.certPath, "cert", "", "this device's certificate (required)")
	flag.StringVar(&cfg.keyPath, "key", "", "this device's private key (required)")
	flag.DurationVar(&cfg.heartbeat, "heartbeat", 30*time.Second, "gateway heartbeat interval")
	flag.DurationVar(&cfg.maxBackoff, "max-backoff", 2*time.Minute, "ceiling for reconnect backoff")
	// Enrolment is a separate mode, not a flag combination. It runs before the required
	// flags below are checked, because a device enrolling has no certificate yet and
	// therefore nothing to satisfy -cert, -key or -ca with. Sharing one flag set would
	// mean either weakening those checks or adding conditions to every one of them.
	var (
		enrolGateway string
		enrolID      string
		enrolName    string
		enrolOut     string
		enrolWait    time.Duration
	)
	flag.StringVar(&enrolGateway, "enrol", "", "enrol against this gateway address and exit, instead of connecting")
	flag.StringVar(&enrolID, "enrol-id", "", "identity to request a certificate for (required with -enrol)")
	flag.StringVar(&enrolName, "enrol-name", "", "human-readable label for this device")
	flag.StringVar(&enrolOut, "enrol-out", "", "directory to write device.key, device.crt and ca.crt into (required with -enrol)")
	flag.DurationVar(&enrolWait, "enrol-timeout", enrolTimeout, "how long to wait for the operator to approve")
	flag.Parse()

	if enrolGateway != "" {
		if enrolID == "" {
			return errors.New("-enrol-id is required with -enrol")
		}
		if enrolOut == "" {
			return errors.New("-enrol-out is required with -enrol")
		}
		name := cfg.serverName
		if name == "" {
			if host, _, err := net.SplitHostPort(enrolGateway); err == nil {
				name = host
			}
		}
		return runEnrol(enrolOptions{
			Gateway:    enrolGateway,
			ServerName: name,
			DeviceID:   enrolID,
			DeviceName: enrolName,
			OutDir:     enrolOut,
			Timeout:    enrolWait,
		})
	}

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

	// Resolve adbd before connecting.
	//
	// The configured address is tried first because it costs nothing when right,
	// but it is never trusted: after a reboot adbd has no socket at all, and when
	// wireless debugging is the thing that opened it, the port is different every
	// boot. An agent that remembered the address would work once and then fail
	// silently forever.
	//
	// -adbd may be empty, in which case discovery runs unconditionally.
	locateCtx, cancelLocate := context.WithTimeout(context.Background(), 90*time.Second)
	adbdAddr, err := adbdloc.Resolvable(locateCtx, cfg.adbdAddr, adbdloc.Options{})
	cancelLocate()
	if err != nil {
		return fmt.Errorf("%w\n"+
			"this agent cannot make adbd appear, and neither can any app: after a\n"+
			"reboot adbd listens only over USB until wireless debugging is enabled.\n"+
			"either leave Wireless debugging switched on, or attach USB once and run\n"+
			"`adb tcpip 5557`. Then start the agent again.",
			err)
	}
	if adbdAddr != cfg.adbdAddr {
		log.Printf("adbd resolved to %s (configured: %q)", adbdAddr, cfg.adbdAddr)
	}
	cfg.adbdAddr = adbdAddr

	// Verification only: an agent has no reason to hold a CA key, and being
	// unable to load one keeps that property from depending on filesystem
	// permissions alone.
	//
	// The argument is the certificate file itself, not a directory: a directory
	// passed through filepath.Dir looks one level too high and reports a missing file
	// that is present. Flags whose meaning can be misread in one direction are worth
	// fixing rather than documenting.
	ca, err := tlsx.LoadVerifierFile(cfg.caPath)
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
func serve(ctx context.Context, cfg config, ca *tlsx.Verifier, id *tlsx.Identity) error {
	tlsCfg, err := tlsx.ClientTLSFromVerifier(ca, id, cfg.serverName, 0)
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

	// The first resolve scanned the ephemeral range successfully, so subsequent
	// streams in this session skip the scan and only try the known address.
	cached := true
	// The resolver is per session, and remembers nothing: each call re-checks the
	// cached address and re-scans if it is dead.
	resolve := func(c context.Context, hint string) (string, error) {
		if hint == "" {
			hint = cfg.adbdAddr
		}
		return adbdloc.Resolvable(c, hint, adbdloc.Options{SkipDynamic: cached})
	}

	// What this device can do is adbd's to say, so ask it before saying anything to
	// the gateway. The question is one CNXN exchange and then a close: the gateway
	// has to answer an operator's adb about this device's features before any stream
	// exists, so a device that reported them on first use would leave that question
	// unanswerable until somebody had already asked it.
	features, err := readDeviceFeatures(ctx, resolve)
	if err != nil {
		return fmt.Errorf("read adbd's feature list: %w", err)
	}

	welcome, err := hs.ClientHandshake(conn, hs.Hello{
		Device:   cfg.deviceID,
		Name:     cfg.deviceName,
		Agent:    version,
		Features: features,
	})
	if err != nil {
		return err
	}
	log.Printf("connected, session %s, device features %s", welcome.Session, features)

	session, err := transport.New(conn, cfg.deviceID, cfg.deviceName, features, transport.Dialer)
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
	return session.Accept(ctx,
		func(route hs.Route, stream net.Conn) error {
			return handleStream(ctx, route, stream, resolve)
		},
		func(service string, stream net.Conn) error {
			return handleDeviceOpen(ctx, session, service, stream)
		})
}

// handleDeviceOpen relays a stream the device opened on its own adbd connection.
//
// A device opens one when it needs a connection to a port on the gateway: a reverse forward
// binds a port on the device, and whatever connects to that port has to land on the other
// side. The agent is in the middle of that path, so it is the agent that sees the ask.
//
// The relay is a splice and nothing more: the service name goes up as a route's metadata and
// the bytes come back down the same stream. What the gateway does with the name is its
// business -- it owns the ports and the policy -- and what this agent must not do is open a
// stream of its own to adbd, because that would be a second connection to the device for a
// request the device itself made and could have made directly.
func handleDeviceOpen(ctx context.Context, session *transport.Session, service string, stream net.Conn) error {
	log.Printf("device opened %s; relaying it to the gateway", service)
	meta, err := json.Marshal(hs.DeviceOpen{Service: service})
	if err != nil {
		_ = stream.Close()
		return err
	}
	upstream, err := session.Open(ctx, hs.KindDeviceOpen, newStreamID(), json.RawMessage(meta))
	if err != nil {
		_ = stream.Close()
		return fmt.Errorf("relay %s: %w", service, err)
	}
	defer upstream.Close()

	done := make(chan error, 2)
	go func() { _, err := io.Copy(upstream, stream); done <- err }()
	go func() { _, err := io.Copy(stream, upstream); done <- err }()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		log.Printf("device stream %s ended: %v", service, err)
		return nil
	}
}

// readDeviceFeatures asks this device's adbd what it supports and returns the feature list.
//
// It is a separate connection on purpose: the answer describes adbd, not the gateway, and
// the connection to adbd this session already holds is not up yet. The exchange is a
// CNXN in each direction and then a close, which is the whole of the handshake from the
// point of view of somebody who wants the banner and not a session.
func readDeviceFeatures(ctx context.Context, resolve func(context.Context, string) (string, error)) (string, error) {
	addr, err := resolve(ctx, "")
	if err != nil {
		return "", err
	}
	d := &net.Dialer{Timeout: 20 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", fmt.Errorf("dial adbd at %s: %w", addr, err)
	}
	defer conn.Close()

	// A deadline covers the exchange. Without one a device that accepts the connection
	// and then says nothing leaves this blocked, and the agent's reconnect loop never
	// runs because it never gets to report anything.
	if err := conn.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		return "", err
	}
	banner, err := adbserverproto.ReadDeviceBanner(conn)
	if err != nil {
		return "", err
	}
	features := adbserverproto.BannerFeatures(banner)
	if features == "" {
		// A device whose banner names no features supports nothing this gateway could
		// negotiate, and continuing would hand an operator's adb an empty list to act on.
		// Saying so here is what makes the difference between a device that needs
		// replacing and a gateway that quietly speaks less than the device can.
		return "", fmt.Errorf("adbd's banner names no features: %q", banner)
	}
	return features, nil
}

// handleStream pipes one operator stream to adbd.
//
// Each stream gets its own adbd connection. That is correct rather than lazy: the
// gateway terminates the ADB protocol with the real adb server, which multiplexes every
// logical stream a device needs over one transport, so the agent normally sees a single
// stream per device and a single dial. Holding one connection and multiplexing over it
// here would mean putting a framing layer between the operator and adbd -- that is,
// reimplementing the part of ADB this project exists not to reimplement.
//
// Two limits apply, because "normally one" is not "always one", and both were learned
// from a phone that hung:
//
//   - a cap on concurrent dials, so a reconnect storm cannot open connections to adbd
//     faster than they are closed. adbd is a phone process with finite resources and no
//     authentication; flooding it is both the fastest way to make it unresponsive and
//     the fastest way to drain its battery.
//   - a stall watchdog, so a stream that stops moving fails loudly instead of looking
//     like a slow device. The earlier symptom of a connection problem was silence, and
//     silence is what made it expensive to diagnose.
func handleStream(ctx context.Context, route hs.Route, stream net.Conn, resolve func(context.Context, string) (string, error)) error {
	if route.Kind != hs.KindADB {
		log.Printf("stream %s: unsupported kind %q", route.Stream, route.Kind)
		return fmt.Errorf("unsupported stream kind %q", route.Kind)
	}

	// Cap concurrent dials to adbd.
	//
	// The gateway terminates ADB with the real adb server, so it multiplexes everything a
	// device needs over one transport and the agent normally opens a single connection.
	// This cap exists for the case where it does not: a reconnect storm would otherwise
	// open connections to adbd faster than they close, and adbd is an unauthenticated
	// process on a phone with finite memory and battery. Waiting briefly is better than
	// either refusing outright or joining the flood.
	select {
	case agentDialSlots <- struct{}{}:
		defer func() { <-agentDialSlots }()
	case <-time.After(agentDialWait):
		return fmt.Errorf("all %d adbd connection slots are in use on this device", cap(agentDialSlots))
	case <-ctx.Done():
		return ctx.Err()
	}

	upstream, err := dialAdbd(ctx, stream, resolve)
	if err != nil {
		return err
	}
	defer upstream.Close()

	// Stall watchdog.
	//
	// A stream that stops moving fails loudly rather than holding the operator's command
	// open. The earlier symptom of a connection fault was silence, and silence is what
	// made it expensive to diagnose -- so "nothing has happened for N minutes" is now a
	// reportable event rather than something an operator discovers by giving up.
	//
	// Activity is tracked on both directions, because a transfer that is only receiving
	// is just as healthy as one that is only sending.
	activity := &tracker{last: time.Now()}
	go activity.watch(ctx, streamIDOf(route), stream, upstream)

	done := make(chan error, 2)
	go func() {
		_, err := io.Copy(activity.writerTo(upstream), stream)
		if cw, ok := upstream.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		done <- err
	}()
	go func() {
		_, err := io.Copy(activity.writerTo(stream), upstream)
		if cw, ok := stream.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		done <- err
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
		return nil
	}
}

// tracker records when bytes last moved in either direction.
type tracker struct {
	mu   sync.Mutex
	last time.Time
}

func (t *tracker) touch() {
	t.mu.Lock()
	t.last = time.Now()
	t.mu.Unlock()
}

func (t *tracker) quiet() time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	return time.Since(t.last)
}

// writerTo wraps a destination so every write counts as activity.
func (t *tracker) writerTo(dst io.Writer) io.Writer {
	return &countingWriter{dst: dst, onWrite: t.touch}
}

type countingWriter struct {
	dst     io.Writer
	onWrite func()
}

func (w *countingWriter) Write(p []byte) (int, error) {
	n, err := w.dst.Write(p)
	if n > 0 {
		w.onWrite()
	}
	return n, err
}

// watch closes a silent stream. It returns once the context ends or the stream is closed
// by somebody else, so it never outlives the handler that owns it.
func (t *tracker) watch(ctx context.Context, id string, stream, upstream io.Closer) {
	tick := time.NewTicker(agentStallCheck)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if q := t.quiet(); q > agentStallTimeout {
				log.Printf("stream %s: no traffic for %s; closing it rather than hanging", id, q.Round(time.Second))
				_ = stream.Close()
				_ = upstream.Close()
				return
			}
		}
	}
}

func streamIDOf(route hs.Route) string { return route.Stream }

func dialAdbd(parent context.Context, stream net.Conn, resolve func(context.Context, string) (string, error)) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(parent, 20*time.Second)
	defer cancel()

	addr, err := resolve(ctx, "")
	if err != nil {
		log.Printf("stream %s: cannot reach adbd: %v", streamID(stream), err)
		return nil, err
	}
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		log.Printf("stream %s: dial adbd at %s: %v", streamID(stream), addr, err)
		return nil, err
	}
	return conn, nil
}

// streamID reads the stream's id for logging, best effort.
func streamID(c net.Conn) string {
	type stringer interface{ String() string }
	_ = stringer(nil)
	if v, ok := c.(interface{ ID() string }); ok {
		return v.ID()
	}
	return "?"
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

// streamSeq numbers the streams this agent relays, and newStreamID names one.
//
// The name is only for correlation between this agent's log and the gateway's: a route header
// carries it so both ends can talk about the same stream, and neither end decides anything
// from it. The sequence makes it unique within this process, which is all that is asked of it.
var streamSeq atomic.Uint64

func newStreamID() string {
	return "do-" + strconv.FormatUint(streamSeq.Add(1), 36)
}
