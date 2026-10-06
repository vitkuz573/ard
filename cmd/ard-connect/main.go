// Command ard-connect is the operator's side of remote ADB.
//
// # Why this exists
//
// adb cannot do TLS. There is no option for it. So a remote device cannot be reached by the
// stock adb binary without something terminating TLS on the operator's own machine. That is
// not an architectural preference; it is what the protocol forces, and `ssh -L` is the same
// answer wearing different clothes. This is that answer without handing out a login.
//
// # What it does
//
// It listens on one port, and for every connection adb opens it opens a mutual-TLS
// connection to the gateway and splices the two together. That is all it does.
//
// # What it deliberately does not do
//
// It does not know which devices exist, and it does not care. That is the whole change from
// the version this replaces: the old client was told the device list in a JSON greeting and
// then bound a loopback port per device, so the gateway had to keep a port table whose
// entries had to stay stable across reconnects, and the operator had to learn serials before
// any of this worked. adb already has a protocol for asking which devices exist and for
// switching onto one of them, so this client hands the connection straight through and the
// gateway answers those questions. One port, no list, no serials, nothing to keep in step.
//
// Usage
//
//	ard-connect -gateway host:port -ca server-ca.pem -cert operator.pem -key operator.key
//	adb -P 15000 devices
//	adb -P 15000 -s DEVICE-UUID shell
//
// The port is chosen with -P for adb and with -listen for this program. 15000 is a default,
// not a requirement: nothing else uses it, and any free port works.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/vitkuz573/ard/internal/tlsx"
)

type config struct {
	gateway    string
	serverName string
	caPath     string
	certPath   string
	keyPath    string
	listen     string
	once       bool
	timeout    time.Duration
}

func main() {
	if err := run(); err != nil {
		log.Fatalf("ard-connect: %v", err)
	}
}

func run() error {
	var cfg config
	flag.StringVar(&cfg.gateway, "gateway", "", "gateway operator address, host:port (required)")
	flag.StringVar(&cfg.serverName, "server-name", "", "TLS server name to verify (defaults to the gateway host)")
	flag.StringVar(&cfg.caPath, "ca", "", "path to the server CA certificate (required)")
	flag.StringVar(&cfg.certPath, "cert", "", "this operator's certificate (required)")
	flag.StringVar(&cfg.keyPath, "key", "", "this operator's private key (required)")
	flag.StringVar(&cfg.listen, "listen", "127.0.0.1:15000", "local address to publish the adb port on")
	flag.BoolVar(&cfg.once, "once", false, "serve one adb connection and exit")
	flag.DurationVar(&cfg.timeout, "dial-timeout", 15*time.Second, "how long to wait for the gateway")
	flag.Parse()

	switch {
	case cfg.gateway == "":
		return errors.New("-gateway is required")
	case cfg.caPath == "":
		return errors.New("-ca is required")
	case cfg.certPath == "":
		return errors.New("-cert is required")
	case cfg.keyPath == "":
		return errors.New("-key is required")
	}

	tlsCfg, err := operatorTLS(&cfg)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ln, err := net.Listen("tcp", cfg.listen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.listen, err)
	}
	defer ln.Close()

	log.Printf("publishing the adb port at %s; point adb at it with -P %s",
		ln.Addr(), portOf(ln.Addr()))
	log.Printf("gateway %s, device list and authorization enforced there", cfg.gateway)

	var wg sync.WaitGroup
	defer wg.Wait()

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		local, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept: %w", err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := forward(local, cfg, tlsCfg); err != nil {
				log.Printf("%s: %v", local.RemoteAddr(), err)
			}
			local.Close()
			if cfg.once {
				stop()
			}
		}()
	}
}

// forward splices one local connection to the gateway over mutual TLS.
//
// Each adb connection gets its own TLS connection, because adb opens one connection per
// request it makes to the server and expects each to be answered on that connection. A
// single multiplexed TLS connection carrying several would need a multiplexer of our own on
// both ends, and adb's own protocol already provides the framing; adding a second one would
// mean two places to get a boundary wrong.
func forward(local net.Conn, cfg config, tlsCfg *tls.Config) error {
	d := &net.Dialer{Timeout: cfg.timeout, KeepAlive: 30 * time.Second}
	raw, err := d.DialContext(context.Background(), "tcp", cfg.gateway)
	if err != nil {
		return fmt.Errorf("dial gateway: %w", err)
	}
	defer raw.Close()

	// The deadline covers the handshake only. Past it the connection belongs to adb, and a
	// shell session is meant to be idle for as long as the operator is thinking.
	_ = raw.SetDeadline(time.Now().Add(cfg.timeout))
	remote := tls.Client(raw, tlsCfg)
	if err := remote.Handshake(); err != nil {
		return fmt.Errorf("gateway handshake: %w", err)
	}
	// Check the role rather than trusting the port.
	//
	// The gateway presents its *server* certificate on every listener, including the
	// operator one, and distinguishes listeners by which CA they trust -- not by the leaf
	// role. Requiring an operator role here would reject the gateway this client exists to
	// talk to, and it did: the handshake check failed, the connection was closed, and adb
	// reported "couldn't read status: connection reset by peer" with nothing useful in
	// between. The server role is what the gateway legitimately presents.
	if _, err := tlsx.VerifyPeerRole(remote.ConnectionState(), tlsx.OrgUnitServer); err != nil {
		return fmt.Errorf("peer is not an ard server: %w", err)
	}
	_ = remote.SetDeadline(time.Time{})
	_ = local.SetDeadline(time.Time{})

	return splice(local, remote)
}

// splice copies in both directions and returns when either side stops.
func splice(a, b net.Conn) error {
	errc := make(chan error, 2)
	go func() { _, err := io.Copy(a, b); errc <- err }()
	go func() { _, err := io.Copy(b, a); errc <- err }()

	// The first direction to finish is normally the one that closed: adb closes its end when
	// it is done with a device, and the gateway's socket is still open. Waiting for the
	// second would hang on a connection that is already finished.
	if err := <-errc; err != nil && !isClosed(err) {
		return err
	}
	return nil
}

func isClosed(err error) bool {
	return errors.Is(err, io.EOF) ||
		errors.Is(err, net.ErrClosed) ||
		errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.EPIPE)
}

// operatorTLS builds the client configuration: the server CA for verification and this
// operator's own certificate for mutual authentication.
//
// The certificate is required. An operator endpoint that accepted a one-sided handshake
// would authenticate the server to nobody and the operator to the server, which is the same
// as authenticating neither.
func operatorTLS(cfg *config) (*tls.Config, error) {
	caPEM, err := os.ReadFile(cfg.caPath)
	if err != nil {
		return nil, fmt.Errorf("read -ca: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("-ca %s contains no certificates", cfg.caPath)
	}

	cert, err := tls.LoadX509KeyPair(cfg.certPath, cfg.keyPath)
	if err != nil {
		return nil, fmt.Errorf("load operator certificate: %w", err)
	}

	name := cfg.serverName
	if name == "" {
		host, _, err := net.SplitHostPort(cfg.gateway)
		if err != nil {
			host = cfg.gateway
		}
		name = host
	}

	return &tls.Config{
		RootCAs:      pool,
		Certificates: []tls.Certificate{cert},
		ServerName:   name,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

func portOf(a net.Addr) string {
	if ta, ok := a.(*net.TCPAddr); ok {
		return fmt.Sprint(ta.Port)
	}
	_, port, err := net.SplitHostPort(a.String())
	if err != nil {
		return ""
	}
	return port
}
