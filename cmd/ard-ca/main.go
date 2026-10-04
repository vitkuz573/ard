// Command ard-ca manages ARD's certificate infrastructure.
//
// Three independent roots are maintained, because the two legs of the platform
// trust different things:
//
//	server   -> signs the gateway's own certificate, trusted by both legs
//	devices  -> signs device leaves, trusted only by the device listener
//	operators-> signs operator leaves, trusted only by the operator listener
//
// Keeping operators and devices under separate roots is what makes a stolen
// device certificate useless against the operator listener, and vice versa.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vitkuz573/ard/internal/tlsx"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "ard-ca:", err)
		os.Exit(1)
	}
}

func usage() error {
	return errors.New("usage: ard-ca <init|device|operator|list|enrol> [flags]")
}

func run(args []string) error {
	if len(args) == 0 {
		return usage()
	}
	switch args[0] {
	case "init":
		return cmdInit(args[1:])
	case "device":
		return cmdIssue(args[1:], tlsx.OrgUnitDevice, "devices")
	case "operator":
		return cmdIssue(args[1:], tlsx.OrgUnitOperator, "operators")
	case "list":
		return cmdList(args[1:])
	case "enrol":
		return cmdEnrol(args[1:])
	case "-h", "--help", "help":
		return usage()
	default:
		return fmt.Errorf("unknown command %q: %w", args[0], usage())
	}
}

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	dir := fs.String("dir", "pki", "pki directory")
	sans := fs.String("san", "localhost,127.0.0.1", "comma-separated server SANs (DNS names or IPs)")
	serverCA := fs.Duration("server-ca-ttl", 10*365*24*time.Hour, "server CA lifetime")
	leafCA := fs.Duration("leaf-ca-ttl", 5*365*24*time.Hour, "device and operator CA lifetime")
	serverLeaf := fs.Duration("server-ttl", 397*24*time.Hour, "server certificate lifetime")
	if err := fs.Parse(args); err != nil {
		return err
	}

	created := false
	for _, sub := range []string{"server", "devices", "operators"} {
		p := filepath.Join(*dir, sub, "ca.crt")
		if _, err := os.Stat(p); err == nil {
			fmt.Printf("keeping existing CA at %s\n", p)
			continue
		}
		ttl := *leafCA
		if sub == "server" {
			ttl = *serverCA
		}
		ca, err := tlsx.NewCA("ARD "+sub+" CA", ttl)
		if err != nil {
			return err
		}
		if err := ca.SaveDir(filepath.Join(*dir, sub), "ca"); err != nil {
			return err
		}
		fmt.Printf("created %s CA (valid %s)\n", sub, ca.Cert.NotAfter.Sub(ca.Cert.NotBefore).Round(time.Hour))
		created = true
	}

	serverCAObj, err := tlsx.LoadCA(filepath.Join(*dir, "server"))
	if err != nil {
		return err
	}
	dnsNames, ips, err := parseSANs(*sans)
	if err != nil {
		return err
	}
	id, err := serverCAObj.IssueServer("ard-server", dnsNames, ips, *serverLeaf)
	if err != nil {
		return err
	}
	if err := id.SaveDir(filepath.Join(*dir, "server"), "server"); err != nil {
		return err
	}
	fmt.Printf("issued server certificate for %v %v (valid %s)\n", dnsNames, ips, id.Cert.NotAfter.Format(time.RFC3339))

	if created {
		fmt.Printf("\npki initialised in %s\n", *dir)
		fmt.Println("next: ard-ca device -dir " + *dir + " -id <device-uuid>")
		fmt.Println("      ard-ca operator -dir " + *dir + " -name <operator>")
	}
	return nil
}

func cmdIssue(args []string, orgUnit, sub string) error {
	fs := flag.NewFlagSet(sub, flag.ContinueOnError)
	dir := fs.String("dir", "pki", "pki directory")
	name := fs.String("id", "", "device UUID (device role only)")
	opName := fs.String("name", "", "operator name (operator role only)")
	ttl := fs.Duration("ttl", 365*24*time.Hour, "leaf certificate lifetime")
	if err := fs.Parse(args); err != nil {
		return err
	}

	identity := *name
	if sub == "operators" {
		identity = *opName
	}
	if identity == "" {
		flagName := "-id"
		if sub == "operators" {
			flagName = "-name"
		}
		return fmt.Errorf("%s is required", flagName)
	}
	if err := validateIdentity(identity); err != nil {
		return err
	}

	ca, err := tlsx.LoadCA(filepath.Join(*dir, sub))
	if err != nil {
		return err
	}
	id, err := ca.Issue(identity, orgUnit, *ttl)
	if err != nil {
		return err
	}
	outDir := filepath.Join(*dir, sub, "leaves")
	if err := id.SaveDir(outDir, identity); err != nil {
		return err
	}

	// The client also needs the server root to verify the gateway.
	serverCAPath := filepath.Join(*dir, "server", "ca.crt")
	fmt.Printf("issued %s certificate for %q (expires %s)\n", orgUnit, identity, id.Cert.NotAfter.Format(time.RFC3339))
	fmt.Printf("  identity : %s\n", filepath.Join(outDir, identity+".crt"))
	fmt.Printf("  key      : %s\n", filepath.Join(outDir, identity+".key"))
	fmt.Printf("  server CA: %s  (deploy alongside the identity)\n", serverCAPath)
	if id.Cert.NotAfter.Before(time.Now().Add(30 * 24 * time.Hour)) {
		fmt.Fprintln(os.Stderr, "warning: certificate expires in under 30 days")
	}
	return nil
}

func cmdList(args []string) error {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	dir := fs.String("dir", "pki", "pki directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	for _, sub := range []string{"devices", "operators"} {
		leaves := filepath.Join(*dir, sub, "leaves")
		entries, err := os.ReadDir(leaves)
		if err != nil {
			continue
		}
		fmt.Printf("%s:\n", sub)
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".crt") {
				continue
			}
			id, err := tlsx.LoadIdentity(filepath.Join(leaves, strings.TrimSuffix(e.Name(), ".crt")))
			if err != nil {
				fmt.Printf("  %-24s <unreadable: %v>\n", e.Name(), err)
				continue
			}
			state := "valid"
			if time.Now().After(id.Cert.NotAfter) {
				state = "EXPIRED"
			}
			fmt.Printf("  %-24s %s  expires %s\n", id.Name, state, id.Cert.NotAfter.Format(time.RFC3339))
		}
	}
	return nil
}

func validateIdentity(s string) error {
	if s == "" || len(s) > 128 {
		return errors.New("identity must be 1-128 characters")
	}
	for _, r := range s {
		ok := r == '-' || r == '_' || r == '.' ||
			(r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
		if !ok {
			return fmt.Errorf("identity %q contains %q; allowed: A-Za-z0-9._-", s, r)
		}
	}
	return nil
}
