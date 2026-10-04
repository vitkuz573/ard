// Command mockadbd runs the mock device from test/mockadbd as a standalone
// listener, for manual pokes and for tracing against the real adb binary.
//
// Usage:
//
//	mockadbd -addr 127.0.0.1:5555
//	ADB_TRACE=transport,adb mockadbd -addr 127.0.0.1:5555
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/vitaly/ard/test/mockadbd"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:5555", "listen address")
	banner := flag.String("banner", "", "override the CNXN banner")
	auth := flag.Bool("auth", false, "demand RSA authentication like ro.adb.secure=1")
	hostKey := flag.String("host-key", defaultHostKey(),
		"adbkey.pub trusted when -auth is set (the HOST key adb signs with)")
	flag.Parse()

	cfg := mockadbd.Config{Banner: *banner, Debug: log.Printf}
	if *auth {
		cfg.TrustedHostKeyPath = *hostKey
	}

	l, err := mockadbd.Listen(*addr, cfg)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	defer l.Close()
	log.Printf("mockadbd listening on %s (auth=%v, host key %s)", l.Addr(), *auth, *hostKey)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	fmt.Fprintln(os.Stderr, "mockadbd: shutting down")
}

// defaultHostKey locates the adb key this host signs with. Authentication is
// worthless if the device verifies against a key the host does not use, so the
// default has to be the real ~/.android/adbkey.pub.
func defaultHostKey() string {
	if v := os.Getenv("ADB_HOST_PUBLIC_KEY"); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "adbkey.pub"
	}
	return filepath.Join(home, ".android", "adbkey.pub")
}
