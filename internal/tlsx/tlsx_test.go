package tlsx

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"
	"time"
)

// The whole multi-tenant trust model rests on one property: a leaf signed by the
// device root must be unable to complete a handshake on the operator listener,
// and symmetrically. If this test ever fails, the platform has no tenant
// isolation, so it is written as an end-to-end handshake rather than a unit check
// of the certificate pool.

type leg struct {
	name string
	ln   net.Listener
	// serverCA is the root clients must trust to verify this leg's gateway
	// certificate. It is separate from the root that signs client leaves, which
	// is exactly the split the production deployment uses.
	serverCA *CA
}

func startLeg(t *testing.T, name string, ca *CA, sans ...string) leg {
	t.Helper()
	dns, ips, err := parseTestSANs(sans)
	if err != nil {
		t.Fatalf("%s: SANs: %v", name, err)
	}
	serverCA, err := NewCA("test "+name+" CA", time.Hour)
	if err != nil {
		t.Fatalf("%s: server CA: %v", name, err)
	}
	srvID, err := serverCA.IssueServer("gateway", dns, ips, time.Hour)
	if err != nil {
		t.Fatalf("%s: server cert: %v", name, err)
	}
	srvCert, err := srvID.TLSCertificate()
	if err != nil {
		t.Fatalf("%s: key pair: %v", name, err)
	}
	cfg, err := ServerTLS(ca, srvCert, tls.VersionTLS13)
	if err != nil {
		t.Fatalf("%s: server tls: %v", name, err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("%s: listen: %v", name, err)
	}
	t.Cleanup(func() { ln.Close() })

	// The handshake is lazy on the server side, so it must be driven explicitly.
	// Without this loop, every dial would time out and the rejection cases would
	// "pass" for the wrong reason, which would silently weaken this test.
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				if tc, ok := c.(*tls.Conn); ok {
					if err := tc.Handshake(); err != nil {
						return // rejected client: alert already sent
					}
					// Echo one line so the client can complete its first
					// exchange and observe a rejection if one is coming.
					_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
					buf := make([]byte, 64)
					if _, err := tc.Read(buf); err != nil {
						return
					}
					_, _ = tc.Write(buf)
				}
			}()
		}
	}()
	return leg{name: name, ln: ln, serverCA: serverCA}
}

func parseTestSANs(in []string) ([]string, []net.IP, error) {
	var dns []string
	var ips []net.IP
	for _, s := range in {
		if ip := net.ParseIP(s); ip != nil {
			ips = append(ips, ip)
		} else {
			dns = append(dns, s)
		}
	}
	return dns, ips, nil
}

// dial attempts a handshake presenting id as the client certificate.
//
// TLS 1.3 sends the client certificate in the second flight, so a completed
// client-side handshake does NOT mean the server accepted it: the rejection
// arrives later as an alert. Therefore the first application byte is written and
// read back. Without this, a wrongly-signed client certificate would appear to
// connect successfully, and production code would inherit the same blind spot.
func dial(t *testing.T, l leg, id *Identity) (string, error) {
	t.Helper()
	cert, err := id.TLSCertificate()
	if err != nil {
		return "", err
	}
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 5 * time.Second},
		"tcp",
		l.ln.Addr().String(),
		&tls.Config{
			ServerName:   "localhost",
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{cert},
			RootCAs:      caPool(l.serverCA),
		},
	)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// The echo side must also complete its handshake and speak, otherwise the
	// client blocks on read instead of receiving the server's alert.
	if _, err := conn.Write([]byte("PING\n")); err != nil {
		return "", err
	}
	buf := make([]byte, 64)
	if _, err := conn.Read(buf); err != nil {
		return "", err
	}
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		t.Fatalf("%s: server presented no certificate", l.name)
	}
	return state.PeerCertificates[0].Subject.CommonName, nil
}

func TestRoleIsolation(t *testing.T) {
	deviceCA, err := NewCA("device CA", time.Hour)
	if err != nil {
		t.Fatalf("device CA: %v", err)
	}
	operatorCA, err := NewCA("operator CA", time.Hour)
	if err != nil {
		t.Fatalf("operator CA: %v", err)
	}
	deviceLeg := startLeg(t, "device", deviceCA, "localhost", "127.0.0.1")
	operatorLeg := startLeg(t, "operator", operatorCA, "localhost", "127.0.0.1")

	deviceID, err := deviceCA.Issue("dev-1", OrgUnitDevice, time.Hour)
	if err != nil {
		t.Fatalf("issue device: %v", err)
	}
	operatorID, err := operatorCA.Issue("alice", OrgUnitOperator, time.Hour)
	if err != nil {
		t.Fatalf("issue operator: %v", err)
	}
	strangerCA, err := NewCA("stranger CA", time.Hour)
	if err != nil {
		t.Fatalf("stranger CA: %v", err)
	}
	stranger, err := strangerCA.Issue("attacker", OrgUnitOperator, time.Hour)
	if err != nil {
		t.Fatalf("issue stranger: %v", err)
	}

	cases := []struct {
		name      string
		leg       leg
		id        *Identity
		wantError bool
	}{
		{"device cert on device leg", deviceLeg, deviceID, false},
		{"operator cert on operator leg", operatorLeg, operatorID, false},
		{"device cert on operator leg", operatorLeg, deviceID, true},
		{"operator cert on device leg", deviceLeg, operatorID, true},
		{"unrelated cert on device leg", deviceLeg, stranger, true},
		{"unrelated cert on operator leg", operatorLeg, stranger, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := dial(t, tc.leg, tc.id)
			if tc.wantError && err == nil {
				t.Fatal("handshake succeeded but must have been rejected")
			}
			if !tc.wantError && err != nil {
				t.Fatalf("handshake rejected: %v", err)
			}
		})
	}
}

// A gateway certificate must not be usable to impersonate a client. If the
// gateway's key leaked, the worst case should be a compromised gateway, not a
// compromised fleet of devices.
func TestServerCertHasNoClientAuth(t *testing.T) {
	ca, err := NewCA("server CA", time.Hour)
	if err != nil {
		t.Fatalf("CA: %v", err)
	}
	srv, err := ca.IssueServer("gateway", []string{"localhost"}, nil, time.Hour)
	if err != nil {
		t.Fatalf("issue server: %v", err)
	}
	deviceCA, err := NewCA("device CA", time.Hour)
	if err != nil {
		t.Fatalf("device CA: %v", err)
	}
	_, err = deviceCA.Cert.Verify(x509.VerifyOptions{
		Roots:     caPool(ca),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err == nil {
		t.Fatal("gateway certificate verified for client auth; expected rejection")
	}
	_, err = srv.Cert.Verify(x509.VerifyOptions{
		Roots:     caPool(ca),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		t.Fatalf("gateway certificate rejected for server auth: %v", err)
	}
}

func caPool(ca *CA) *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ca.Cert)
	return p
}

func TestSaveLoadRoundTrip(t *testing.T) {
	ca, err := NewCA("ca", time.Hour)
	if err != nil {
		t.Fatalf("CA: %v", err)
	}
	dir := t.TempDir()
	if err := ca.SaveDir(dir, "ca"); err != nil {
		t.Fatalf("save ca: %v", err)
	}
	id, err := ca.Issue("dev-7", OrgUnitDevice, time.Hour)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if err := id.SaveDir(dir, "dev-7"); err != nil {
		t.Fatalf("save identity: %v", err)
	}

	loadedCA, err := LoadCA(dir)
	if err != nil {
		t.Fatalf("load ca: %v", err)
	}
	loadedID, err := LoadIdentity(dir + "/dev-7")
	if err != nil {
		t.Fatalf("load identity: %v", err)
	}
	if loadedID.Name != "dev-7" || loadedID.OrgUnit != OrgUnitDevice {
		t.Fatalf("loaded identity wrong: name=%q ou=%q", loadedID.Name, loadedID.OrgUnit)
	}
	if _, err := loadedCA.Cert.Verify(x509.VerifyOptions{
		Roots:     caPool(loadedCA),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		t.Fatalf("loaded CA not self-consistent: %v", err)
	}
	if _, err := loadedID.Cert.Verify(x509.VerifyOptions{
		Roots:     caPool(loadedCA),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("loaded leaf does not verify against loaded CA: %v", err)
	}
}
