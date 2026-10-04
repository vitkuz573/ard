// Command ard-proxy makes remote devices look like ordinary local ADB devices.
//
// It listens on one loopback port per device on the gateway and pipes each
// connection into that device's stream. The stock `adb server` then treats the
// port as a TCP device and everything works unmodified: shell, push, pull, install,
// logcat, forward and reverse. Nothing is reimplemented, so features added to adb
// upstream are available immediately rather than after someone reimplements them.
//
//	ard-proxy                     (gateway)
//	  127.0.0.1:15000 -> device A
//	  127.0.0.1:15001 -> device B
//	  ...
//	adb connect 127.0.0.1:15000
//	adb -s 127.0.0.1:15000 shell
//
// The port is bound to loopback only. It must never be exposed publicly: the port
// speaks the raw ADB transport, which has no authentication of its own.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/vitkuz573/ard/internal/transport"
)

const version = "0.1.0"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "ard-proxy:", err)
		os.Exit(1)
	}
}

func run() error {
	control := flag.String("control", "/run/ard/control.sock", "gateway control socket")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.LUTC)
	log.SetPrefix("ard-proxy: ")
	log.Printf("version %s, control socket %s", version, *control)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	p := &proxy{
		control:   *control,
		logger:    log.Default(),
		listeners: map[int]net.Listener{},
	}
	return p.run(ctx)
}

// deviceInfo is the gateway's description of one device.
type deviceInfo struct {
	UUID  string `json:"uuid"`
	Name  string `json:"name"`
	State string `json:"state"`
	// LoopbackPort is assigned by the gateway so the mapping survives reconnects.
	LoopbackPort int `json:"loopback_port"`
}

type listResponse struct {
	Devices []deviceInfo `json:"devices"`
}

type request struct {
	Op     string `json:"op"`
	Device string `json:"device,omitempty"`
}

type attachResponse struct {
	Device string `json:"device"`
	Error  string `json:"error,omitempty"`
}

type proxy struct {
	control string
	logger  *log.Logger

	mu        sync.Mutex
	listeners map[int]net.Listener
}

func (p *proxy) run(ctx context.Context) error {
	// Reconcile repeatedly: devices come and go, and a proxy that only reads the
	// list once would leave ports bound to devices that have left.
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		// A reconcile failure is logged and retried rather than fatal: the usual
		// cause is the gateway restarting, and killing the proxy for that would
		// turn a recoverable blip into an outage.
		if err := p.reconcile(ctx); err != nil {
			p.logger.Printf("reconcile: %v", err)
		}
		select {
		case <-ctx.Done():
			p.closeAll()
			return nil
		case <-ticker.C:
		}
	}
}

// reconcile brings the set of listeners in line with the registry.
func (p *proxy) reconcile(ctx context.Context) error {
	devices, err := p.list()
	if err != nil {
		return err
	}
	want := map[int]deviceInfo{}
	for _, d := range devices {
		if d.LoopbackPort == 0 {
			p.logger.Printf("device %s has no loopback port assigned", d.UUID)
			continue
		}
		want[d.LoopbackPort] = d
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// Close listeners for ports that are no longer wanted.
	for port, ln := range p.listeners {
		if _, keep := want[port]; !keep {
			_ = ln.Close()
			delete(p.listeners, port)
			p.logger.Printf("released port %d", port)
		}
	}

	// Open listeners for new ports.
	for port, d := range want {
		if _, exists := p.listeners[port]; exists {
			continue
		}
		// Loopback only. Binding 0.0.0.0 would publish an unauthenticated ADB
		// transport to the internet.
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			p.logger.Printf("listen port %d for device %s: %v", port, d.UUID, err)
			continue
		}
		p.listeners[port] = ln
		p.logger.Printf("device %s (%s) on 127.0.0.1:%d [%s]", d.UUID, d.Name, port, d.State)
		go p.accept(ctx, ln, d)
	}
	return nil
}

func (p *proxy) accept(ctx context.Context, ln net.Listener, d deviceInfo) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go p.handle(ctx, conn, d)
	}
}

// handle attaches one connection to its device and pipes bytes.
//
// Every accepted connection becomes its own stream on the device's session. The
// stock adb server opens one connection per transport, so this is one stream per
// adb session in practice.
func (p *proxy) handle(ctx context.Context, conn net.Conn, d deviceInfo) {
	defer conn.Close()

	up, err := p.attach(ctx, d.UUID)
	if err != nil {
		p.logger.Printf("attach to %s: %v", d.UUID, err)
		return
	}
	defer up.Close()

	_ = transport.Pump(conn, up)
}

func (p *proxy) list() ([]deviceInfo, error) {
	conn, err := p.dial()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	if err := writeJSON(conn, request{Op: "list"}); err != nil {
		return nil, err
	}
	var resp listResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return nil, fmt.Errorf("decode list: %w", err)
	}
	return resp.Devices, nil
}

// attach opens a stream to a device and returns the device-side end.
func (p *proxy) attach(ctx context.Context, device string) (net.Conn, error) {
	conn, err := p.dial()
	if err != nil {
		return nil, err
	}
	if err := writeJSON(conn, request{Op: "attach", Device: device}); err != nil {
		conn.Close()
		return nil, err
	}
	// The reply is read once before the socket becomes an opaque byte pipe.
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	var resp attachResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		conn.Close()
		return nil, fmt.Errorf("decode attach: %w", err)
	}
	if resp.Error != "" {
		conn.Close()
		return nil, errors.New(resp.Error)
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func (p *proxy) dial() (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(context.Background(), "unix", p.control)
}

func (p *proxy) closeAll() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for port, ln := range p.listeners {
		_ = ln.Close()
		delete(p.listeners, port)
	}
}

func writeJSON(w interface{ Write([]byte) (int, error) }, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	_, err = w.Write(b)
	return err
}
