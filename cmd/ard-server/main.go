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

	"github.com/vitkuz573/ard/internal/acl"
	"github.com/vitkuz573/ard/internal/audit"
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
	controlSocket  string
	pkiDir         string
	allowedDevices string
	operatorsFile  string
	loopbackBase   int
	auditPath      string
}

func run() error {
	var cfg config
	flag.StringVar(&cfg.deviceListen, "listen-devices", ":7000", "device listener (TLS, device certificates only)")
	flag.StringVar(&cfg.operatorListen, "listen-operators", ":7100", "operator listener (TLS, operator certificates only)")
	flag.StringVar(&cfg.controlSocket, "control-socket", "/run/ard/control.sock", "unix socket for ard-proxy")
	flag.StringVar(&cfg.pkiDir, "pki", "/etc/ard/pki", "directory produced by ard-ca")
	flag.StringVar(&cfg.allowedDevices, "devices", "", "comma-separated device UUIDs permitted to connect (required)")
	flag.StringVar(&cfg.operatorsFile, "operators", "/etc/ard/operators.yaml", "operator roles and device grants")
	flag.IntVar(&cfg.loopbackBase, "loopback-base", 15000, "first loopback port used to present devices to the stock adb server")
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

	reg, err := registry.New(allowed, cfg.loopbackBase, func(d *registry.Device, event string) {
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
	deviceCA, err := tlsx.LoadCA(filepath.Join(cfg.pkiDir, "devices"))
	if err != nil {
		return fmt.Errorf("load device CA: %w", err)
	}
	operatorCA, err := tlsx.LoadCA(filepath.Join(cfg.pkiDir, "operators"))
	if err != nil {
		return fmt.Errorf("load operator CA: %w", err)
	}

	deviceTLS, err := tlsx.ServerTLS(deviceCA, serverTLS, 0)
	if err != nil {
		return err
	}
	operatorTLS, err := tlsx.ServerTLS(operatorCA, serverTLS, 0)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	gw := &gateway{reg: reg, audit: auditor, authz: authz, logger: log.Default()}

	deviceLn, err := net.Listen("tcp", cfg.deviceListen)
	if err != nil {
		return fmt.Errorf("listen devices: %w", err)
	}
	operatorLn, err := net.Listen("tcp", cfg.operatorListen)
	if err != nil {
		_ = deviceLn.Close()
		return fmt.Errorf("listen operators: %w", err)
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

	// ard-proxy attaches over a unix socket rather than TCP: loopback TCP would be
	// reachable by any local process, while socket permissions can confine it to
	// the gateway's own group.
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

	log.Printf("devices on %s, operators on %s, control on %s",
		deviceLn.Addr(), operatorLn.Addr(), cfg.controlSocket)

	<-ctx.Done()
	log.Printf("shutting down")
	_ = deviceLn.Close()
	_ = operatorLn.Close()
	_ = controlLn.Close()
	_ = os.Remove(cfg.controlSocket)
	wg.Wait()
	return nil
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
