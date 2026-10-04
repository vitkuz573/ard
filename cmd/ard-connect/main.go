package main

// ard-connect: the operator's side of remote ADB.
//
// Why this exists
//
// The gateway presents each device to the stock adb server on a loopback port. That works,
// but only for someone with a shell on the gateway host, so every operator would need SSH
// access to the VPS. That does not scale as a product: SSH is all-or-nothing, it is not
// scoped per device, one person's access cannot be revoked without disturbing the rest,
// and it grants root on the machine that holds the CA private keys.
//
// What this does instead
//
// It binds a loopback port per device the operator is entitled to, and for each adb
// connection it opens a mutual-TLS connection to the gateway and splices bytes. The stock
// adb binary is untouched: it still speaks plaintext TCP to 127.0.0.1 and believes it is
// talking to a local adbd.
//
// A local helper is unavoidable, not an architectural preference. adb cannot do TLS -- it
// has no option for it -- so something has to terminate TLS on the operator's own
// machine. `ssh -L` is one such helper, which is exactly why SSH was in the requirements
// before. This is the same shape without handing out a login.
//
// Authorization lives on the gateway. The device list this client receives is already
// filtered by the operator's role, and every attach is checked again server-side, so a
// modified client asking for a device it was not shown gains nothing.

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/vitkuz573/ard/internal/registry"
	"github.com/vitkuz573/ard/internal/tlsx"
)

type config struct {
	gateway    string
	serverName string
	caPath     string
	certPath   string
	keyPath    string
	localBase  int
	localHost  string
	device     string
	once       bool
	timeout    time.Duration
}

func run() error {
	var cfg config
	flag.StringVar(&cfg.gateway, "gateway", "", "gateway operator address, host:port (required)")
	flag.StringVar(&cfg.serverName, "server-name", "", "TLS server name to verify (defaults to the gateway host)")
	flag.StringVar(&cfg.caPath, "ca", "", "path to the server CA certificate (required)")
	flag.StringVar(&cfg.certPath, "cert", "", "this operator's certificate (required)")
	flag.StringVar(&cfg.keyPath, "key", "", "this operator's private key (required)")
	flag.IntVar(&cfg.localBase, "local-base", 15000, "first local port; device n is published on local-base+n")
	flag.StringVar(&cfg.localHost, "local-host", "127.0.0.1", "address to publish local ports on; keep it on loopback")
	flag.StringVar(&cfg.device, "device", "", "publish only this device, instead of everything the role allows")
	flag.BoolVar(&cfg.once, "once", false, "serve one adb connection and exit, instead of running until interrupted")
	flag.DurationVar(&cfg.timeout, "dial-timeout", 15*time.Second, "how long to wait for the gateway")
	flag.Parse()

	for name, value := range map[string]string{
		"gateway": cfg.gateway, "ca": cfg.caPath, "cert": cfg.certPath, "key": cfg.keyPath,
	} {
		if value == "" {
			return fmt.Errorf("-%s is required", name)
		}
	}
	if cfg.serverName == "" {
		if host, _, err := net.SplitHostPort(cfg.gateway); err == nil {
			cfg.serverName = host
		}
	}

	log.SetFlags(0)
	log.SetPrefix("ard-connect: ")

	c, err := tlsClient(cfg)
	if err != nil {
		return err
	}
	defer c.Close()

	greeting, err := greet(c, cfg.device)
	if err != nil {
		return err
	}
	if len(greeting.Devices) == 0 {
		return fmt.Errorf("the %s role has no devices granted, so there is nothing to publish", greeting.Role)
	}
	// Split what may be driven from what may merely be seen. Publishing a read-only
	// device would let `adb connect` succeed and every command fail, which reads as a
	// broken device rather than as policy.
	driveable := make([]int, 0, len(greeting.Devices))
	for i, d := range greeting.Devices {
		if d.Bridgeable {
			driveable = append(driveable, i)
		}
	}
	if len(driveable) == 0 {
		names := make([]string, 0, len(greeting.Devices))
		for _, d := range greeting.Devices {
			names = append(names, d.UUID)
		}
		return fmt.Errorf("this operator can see %s, but the %s role does not permit driving them",
			strings.Join(names, ", "), greeting.Role)
	}

	// Publish loopback ports in the order the gateway listed them, so the numbering is
	// stable for as long as the granted set is. The operator's adb serial is
	// 127.0.0.1:<port>, and that is what appears in `adb devices`.
	published := make(map[int]string, len(greeting.Devices))
	ln := make([]net.Listener, 0, len(greeting.Devices))
	defer func() {
		for _, l := range ln {
			_ = l.Close()
		}
	}()

	fmt.Printf("operator %s, role %s\n", greeting.Operator, greeting.Role)
	fmt.Printf("%-10s %-34s %s\n", "adb serial", "device", "state")
	for n, idx := range driveable {
		d := greeting.Devices[idx]
		port := cfg.localBase + n
		l, err := net.Listen("tcp", net.JoinHostPort(cfg.localHost, fmt.Sprint(port)))
		if err != nil {
			return fmt.Errorf("publish %s on %d: %w", d.UUID, port, err)
		}
		ln = append(ln, l)
		published[port] = d.UUID
		fmt.Printf("127.0.0.1:%-4d %-34s %s\n", port, d.UUID, d.State)
		go serveLocal(l, cfg, d.UUID, greeting.Operator)
	}
	// Mention the rest, so an operator knows the device exists and why it is absent.
	for _, d := range greeting.Devices {
		if !d.Bridgeable {
			fmt.Printf("%-10s %-34s %s\n", "-", d.UUID, "visible, not permitted to drive")
		}
	}
	fmt.Printf("\nnow: adb connect 127.0.0.1:%d && adb -s 127.0.0.1:%d shell\n",
		cfg.localBase, cfg.localBase)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if cfg.once {
		l := ln[0]
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		_ = conn.Close()
		return nil
	}
	<-ctx.Done()
	fmt.Println("\nshutting down")
	return nil
}

// tlsClient builds the operator's mutual-TLS connection to the gateway.
//
// The certificate decides who the operator is, and the gateway reads the identity from
// the handshake rather than from anything sent afterwards, so a client cannot claim to be
// someone else by editing a field.
func tlsClient(cfg config) (*tls.Conn, error) {
	ca, err := tlsx.LoadVerifierFile(cfg.caPath)
	if err != nil {
		return nil, fmt.Errorf("load the server CA: %w", err)
	}
	// LoadIdentity takes a path prefix and appends .crt/.key, which is how the agent
	// loads its own identity too. Keeping both callers on one shape means there is one
	// way this is done rather than two that can drift.
	id, err := tlsx.LoadIdentity(trimExt(cfg.certPath))
	if err != nil {
		return nil, fmt.Errorf("load the operator identity: %w", err)
	}
	conn, err := tlsx.ClientTLSFromVerifier(ca, id, cfg.serverName, tls.VersionTLS13)
	if err != nil {
		return nil, err
	}
	d := &net.Dialer{Timeout: cfg.timeout}
	raw, err := d.Dial("tcp", cfg.gateway)
	if err != nil {
		return nil, fmt.Errorf("connect to the gateway: %w", err)
	}
	return tls.Client(raw, conn), nil
}

// greeting mirrors what the gateway sends first. The device list is already filtered by
// role on the server, which is why this client never needs to decide what it may see.
type greeting struct {
	Operator string `json:"operator"`
	Role     string `json:"role"`
	Devices  []struct {
		registry.Device
		// Bridgeable is the gateway's own decision. The client does not recompute it,
		// because a client that guessed would either refuse a device the operator may
		// use or advertise one they may not.
		Bridgeable bool `json:"bridgeable"`
	} `json:"devices"`
}

func greet(conn *tls.Conn, only string) (*greeting, error) {
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	defer conn.SetDeadline(time.Time{})
	var g greeting
	if err := json.NewDecoder(conn).Decode(&g); err != nil {
		return nil, fmt.Errorf("read the gateway's greeting: %w", err)
	}
	if g.Operator == "" {
		return nil, errors.New("the gateway did not identify the operator")
	}
	if only != "" {
		kept := g.Devices[:0]
		for _, d := range g.Devices {
			if d.UUID == only {
				kept = append(kept, d)
			}
		}
		g.Devices = kept
	}
	return &g, nil
}

// serveLocal handles one adb connection to one device.
func serveLocal(l net.Listener, cfg config, device, operator string) {
	for {
		local, err := l.Accept()
		if err != nil {
			return
		}
		go func(local net.Conn) {
			defer local.Close()
			if err := bridge(local, cfg, device); err != nil {
				log.Printf("%s: %v", device, err)
			}
		}(local)
	}
}

// bridge opens one TLS connection to the gateway, asks for the device, and splices.
//
// A fresh connection per adb connection is deliberate. adb already multiplexes every
// service it needs over the single TCP connection it opens to a given device, so pooling
// would add state without saving anything, and it would leave a connection open with no
// adb connection behind it.
func bridge(local net.Conn, cfg config, device string) error {
	up, err := tlsClient(cfg)
	if err != nil {
		return err
	}
	defer up.Close()

	// The greeting is sent on every connection, so it must be consumed before the
	// attach request. Skipping it would put JSON where the gateway expects a request.
	var hello greeting
	if err := json.NewDecoder(up).Decode(&hello); err != nil {
		return fmt.Errorf("read greeting: %w", err)
	}

	req, err := json.Marshal(map[string]string{"op": "attach", "device": device})
	if err != nil {
		return err
	}
	if _, err := up.Write(append(req, '\n')); err != nil {
		return fmt.Errorf("send attach: %w", err)
	}
	var resp struct {
		Device string `json:"device"`
		Error  string `json:"error"`
	}
	if err := json.NewDecoder(up).Decode(&resp); err != nil {
		return fmt.Errorf("read attach response: %w", err)
	}
	if resp.Error != "" {
		return errors.New(resp.Error)
	}

	// Bidirectional copy. Both directions matter: adb sends commands and reads output,
	// and a half-open relay looks exactly like a hung device.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(up, local)
		// CloseWrite rather than Close: the ADB protocol ends with one side stopping,
		// and a full close here would cut off the reply still in flight.
		_ = up.CloseWrite()
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(local, up)
		if c, ok := local.(*net.TCPConn); ok {
			_ = c.CloseWrite()
		}
	}()
	wg.Wait()
	return nil
}

// trimExt drops a trailing .crt or .key so a path can be used as the prefix
// LoadIdentity expects. An operator will reasonably type the full certificate path.
func trimExt(p string) string {
	for _, ext := range []string{".crt", ".key"} {
		if strings.HasSuffix(p, ext) {
			return strings.TrimSuffix(p, ext)
		}
	}
	return p
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "ard-connect:", err)
		os.Exit(1)
	}
}
