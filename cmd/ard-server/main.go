// Command ard-server is the gateway.
//
// It accepts device connections on one TLS listener, holds them in a registry,
// and serves operator access. Two listeners exist because the two legs trust
// different certificate roots and must not be interchangeable:
//
//	device listener    trusts the device CA only
//	operator listener  trusts the operator CA only
//
// A device certificate therefore cannot complete a handshake on the operator
// listener, and an operator certificate cannot register as a device. This is
// enforced by crypto/tls rather than by application code, so it holds even if a
// code path forgets to check.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/vitkuz573/ard/internal/acl"
	"github.com/vitkuz573/ard/internal/audit"
	"github.com/vitkuz573/ard/internal/enrol"
	"github.com/vitkuz573/ard/internal/registry"
	"github.com/vitkuz573/ard/internal/tlsx"
)

const version = "0.1.0"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "ard-server:", err)
		os.Exit(1)
	}
}

type config struct {
	deviceListen   string
	operatorListen string
	enrolListen    string
	enrolTTL       time.Duration
	controlSocket  string
	pkiDir         string
	allowedDevices string
	operatorsFile  string
	auditPath      string
}

func run() error {
	var cfg config
	flag.StringVar(&cfg.deviceListen, "listen-devices", ":7000", "device listener (TLS, device certificates only)")
	flag.StringVar(&cfg.operatorListen, "listen-operators", ":7100", "operator listener (TLS, operator certificates only)")
	flag.StringVar(&cfg.enrolListen, "listen-enrol", ":7200", "enrolment listener (TLS, no client certificate: devices have none yet)")
	flag.DurationVar(&cfg.enrolTTL, "enrol-ttl", 15*time.Minute, "how long a certificate request waits for operator approval")
	flag.StringVar(&cfg.controlSocket, "control-socket", "/run/ard/control.sock", "unix socket for enrolment, mode 0660 and requiring peer uid 0")
	flag.StringVar(&cfg.pkiDir, "pki", "/etc/ard/pki", "directory produced by ard-ca")
	flag.StringVar(&cfg.allowedDevices, "devices", "", "comma-separated device UUIDs permitted to connect (required)")
	flag.StringVar(&cfg.operatorsFile, "operators", "/etc/ard/operators.yaml", "operator roles and device grants")
	flag.StringVar(&cfg.auditPath, "audit", "/var/log/ard/audit.log", "append-only audit log")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.LUTC)
	log.SetPrefix("ard-server: ")
	log.Printf("version %s", version)

	if cfg.allowedDevices == "" {
		return errors.New("-devices is required; refusing to accept any device without an explicit list")
	}
	allowed := splitList(cfg.allowedDevices)

	auditor, err := audit.New(audit.Config{
		Path: cfg.auditPath,
		// A device going offline is not itself auditable, but the state change is
		// logged so a disconnect can be correlated with the session that ended.
		AlsoTo: os.Stderr,
	})
	if err != nil {
		return fmt.Errorf("audit: %w", err)
	}

	authz, err := acl.Load(cfg.operatorsFile)
	if err != nil {
		return fmt.Errorf("authorization: %w", err)
	}

	reg, err := registry.New(allowed, func(d *registry.Device, event string) {
		log.Printf("device %s (%s) %s; streams=%d from %s",
			d.UUID, d.Name, event, d.Streams, d.RemoteAddr)
		auditor.Record(audit.Event{
			Kind:   "device." + event,
			Device: d.UUID,
			Actor:  "device",
			Detail: d.Name,
			Remote: d.RemoteAddr,
		})
	})
	if err != nil {
		return fmt.Errorf("registry: %w", err)
	}

	serverCert, err := tlsx.LoadIdentity(filepath.Join(cfg.pkiDir, "server", "server"))
	if err != nil {
		return fmt.Errorf("load server certificate: %w", err)
	}
	serverTLS, err := serverCert.TLSCertificate()
	if err != nil {
		return err
	}
	// Roots are loaded for verification only. The gateway must never hold a CA
	// private key: it would then be able to mint device and operator identities,
	// turning a single compromised process into authority over the whole fleet.
	// Loading a keypair here would also force the CA key to be readable by the
	// gateway user, which is the exact escalation being avoided.
	deviceCA, err := tlsx.LoadVerifier(filepath.Join(cfg.pkiDir, "devices"))
	if err != nil {
		return fmt.Errorf("load device CA: %w", err)
	}
	operatorCA, err := tlsx.LoadVerifier(filepath.Join(cfg.pkiDir, "operators"))
	if err != nil {
		return fmt.Errorf("load operator CA: %w", err)
	}

	deviceTLS, err := tlsx.ServerTLSFromVerifier(deviceCA, serverTLS, 0)
	if err != nil {
		return err
	}
	operatorTLS, err := tlsx.ServerTLSFromVerifier(operatorCA, serverTLS, 0)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Say what the policy actually admits. A policy whose roles name no members refuses
	// every operator with "has no role", which reads as a deliberate lockdown rather than
	// as the configuration mistake it is -- and it loads without complaint. Stating the
	// count at startup makes it visible, and gives the deploy script something reliable to
	// check instead of grepping YAML for a key it might spell three ways.
	log.Printf("operator policy: %d roles, %d admitted operator(s)%s",
		len(authz.Roles()), len(authz.Members()), describeMembers(authz))
	if len(authz.Members()) == 0 {
		log.Printf("WARNING: no operator can authenticate; every role in %s names no members", cfg.operatorsFile)
	}

	gw := &gateway{
		reg:     reg,
		audit:   auditor,
		authz:   authz,
		logger:  log.Default(),
		mailbox: enrol.NewMailbox(cfg.enrolTTL),
	}

	deviceLn, err := net.Listen("tcp", cfg.deviceListen)
	if err != nil {
		return fmt.Errorf("listen devices: %w", err)
	}
	operatorLn, err := net.Listen("tcp", cfg.operatorListen)
	if err != nil {
		_ = deviceLn.Close()
		return fmt.Errorf("listen operators: %w", err)
	}
	enrolLn, err := net.Listen("tcp", cfg.enrolListen)
	if err != nil {
		_ = deviceLn.Close()
		_ = operatorLn.Close()
		return fmt.Errorf("listen enrol: %w", err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		gw.serveDevices(ctx, deviceLn, deviceTLS)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		gw.serveOperators(ctx, operatorLn, operatorTLS)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Deliberately no client certificate: a device cannot present one before it is
		// enrolled. This is the only listener that accepts an unauthenticated peer, so
		// it is also the one that must assume everything it reads is hostile.
		gw.serveEnrol(ctx, enrolLn, enrolServerTLS(serverTLS))
	}()

	// The control socket is for enrolment, and it is a unix socket rather than TCP
	// because loopback TCP would be reachable by any local process, while socket
	// permissions can confine it to the gateway's own group.
	if err := os.MkdirAll(filepath.Dir(cfg.controlSocket), 0o750); err != nil {
		return fmt.Errorf("control socket dir: %w", err)
	}
	_ = os.Remove(cfg.controlSocket)
	controlLn, err := net.Listen("unix", cfg.controlSocket)
	if err != nil {
		return fmt.Errorf("listen control: %w", err)
	}
	defer controlLn.Close()
	if err := os.Chmod(cfg.controlSocket, 0o660); err != nil {
		return fmt.Errorf("chmod control socket: %w", err)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		gw.serveControl(ctx, controlLn)
	}()

	log.Printf("devices on %s, operators on %s, enrol on %s, control on %s",
		deviceLn.Addr(), operatorLn.Addr(), enrolLn.Addr(), cfg.controlSocket)

	<-ctx.Done()
	log.Printf("shutting down")
	_ = deviceLn.Close()
	_ = operatorLn.Close()
	_ = enrolLn.Close()
	_ = controlLn.Close()
	_ = os.Remove(cfg.controlSocket)
	wg.Wait()
	return nil
}

// describeMembers lists the admitted operator names when there are few enough to be worth
// reading in a log line.
func describeMembers(p *acl.Policy) string {
	m := p.Members()
	if len(m) == 0 || len(m) > 8 {
		return ""
	}
	return " (" + strings.Join(m, ", ") + ")"
}

func splitList(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
