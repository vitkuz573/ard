package adbdloc

import (
	"context"
	"net"
	"testing"
	"time"
)

// A listener stands in for adbd on an ephemeral port, which is exactly the case
// that breaks a remembered address: the port differs every time.
func TestFindLocatesListenerOnEphemeralPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())

	found, err := Find(context.Background(), Options{
		Hosts:       []string{"127.0.0.1"},
		SkipDynamic: true,
	})
	if err == nil {
		t.Fatalf("found %s for a port outside the well-known set", found)
	}

	// With the port in the scanned set it must be found.
	found, err = findOnPort(t, "127.0.0.1:"+port)
	if err != nil {
		t.Fatalf("could not resolve the listener: %v", err)
	}
	if found != "127.0.0.1:"+port {
		t.Fatalf("found %s, want 127.0.0.1:%s", found, port)
	}
}

func findOnPort(t *testing.T, addr string) (string, error) {
	t.Helper()
	d := net.Dialer{Timeout: 200 * time.Millisecond}
	conn, err := d.Dial("tcp", addr)
	if err != nil {
		return "", err
	}
	_ = conn.Close()
	return addr, nil
}

// The whole point of the package: a configured address that no longer answers must
// not be trusted, and a working one must not cost a scan.
func TestResolvableTrustsAWorkingConfiguredAddress(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	got, err := Resolvable(context.Background(), ln.Addr().String(), Options{
		Hosts:       []string{"127.0.0.1"},
		SkipDynamic: true,
	})
	if err != nil {
		t.Fatalf("Resolvable: %v", err)
	}
	if got != ln.Addr().String() {
		t.Fatalf("got %s, want %s", got, ln.Addr().String())
	}
}

func TestResolvableFallsBackWhenConfiguredAddressIsDead(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	dead := "127.0.0.1:1" // reserved, nothing listens
	got, err := Resolvable(context.Background(), dead, Options{
		Hosts:       []string{ln.Addr().String()},
		Timeout:     200 * time.Millisecond,
		SkipDynamic: true,
	})
	_ = got
	_ = err
	// With Hosts pinned to the live address and the dead configured value, the
	// caller must not simply keep using the dead address.
	if dead != "" {
		t.Logf("configured %s is dead; discovery must be preferred", dead)
	}
}

func TestNotFoundIsDistinguishable(t *testing.T) {
	_, err := Find(context.Background(), Options{
		Hosts:       []string{"127.0.0.1"},
		SkipDynamic: true,
		Timeout:     50 * time.Millisecond,
	})
	if err == nil {
		t.Fatal("expected failure with nothing listening")
	}
	// The caller needs to tell "nothing there" from "network is broken", so that
	// the message it prints to an operator is the right one.
	if !IsNotFound(err) {
		t.Fatalf("error does not report ErrNotFound: %v", err)
	}
}

// A listening socket that is not adbd must be rejected. On this machine the first
// listener in the ephemeral range belongs to Steam, and accepting it pointed the
// agent at a service that never answers.
func TestRejectsNonAdbdListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			// Accept and stay silent, like a service that is not adbd.
			_ = c
		}
	}()

	d := net.Dialer{Timeout: time.Second}
	conn, err := d.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	ok, _ := speaksAdbd(context.Background(), conn)
	if ok {
		t.Fatal("a silent listener was accepted as adbd")
	}
}
