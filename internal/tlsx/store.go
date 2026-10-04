package tlsx

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"
)

// IssueServer signs a server certificate with DNS names and IP SANs.
//
// Extended key usage is serverAuth only. A server certificate must never be
// usable as a client certificate, so that a stolen gateway key cannot impersonate
// a device or an operator to any other gateway.
func (ca *CA) IssueServer(cn string, dnsNames []string, ips []net.IP, ttl time.Duration) (*Identity, error) {
	return ca.issue(cn, OrgUnitServer, ttl, func(tmpl *x509.Certificate) {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.DNSNames = dnsNames
		tmpl.IPAddresses = ips
	})
}

// Save and load helpers. Loading keeps the trust decisions explicit: a leaf is
// only ever accepted with the CA that is expected to have signed it.

// LoadCA reads <dir>/ca.crt and <dir>/ca.key.
func LoadCA(dir string) (*CA, error) {
	certPEM, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if err != nil {
		return nil, fmt.Errorf("tlsx: read ca.crt: %w", err)
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, "ca.key"))
	if err != nil {
		return nil, fmt.Errorf("tlsx: read ca.key: %w", err)
	}
	cert, err := parseCertPEM(certPEM)
	if err != nil {
		return nil, err
	}
	key, err := parseKeyPEM(keyPEM)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, Key: key, CertPEM: certPEM, KeyPEM: keyPEM}, nil
}

// LoadIdentity reads <dir>/<prefix>.crt and <dir>/<prefix>.key.
func LoadIdentity(dirPrefix string) (*Identity, error) {
	certPEM, err := os.ReadFile(dirPrefix + ".crt")
	if err != nil {
		return nil, fmt.Errorf("tlsx: read cert: %w", err)
	}
	keyPEM, err := os.ReadFile(dirPrefix + ".key")
	if err != nil {
		return nil, fmt.Errorf("tlsx: read key: %w", err)
	}
	cert, err := parseCertPEM(certPEM)
	if err != nil {
		return nil, err
	}
	key, err := parseKeyPEM(keyPEM)
	if err != nil {
		return nil, err
	}
	return &Identity{
		Name:    cert.Subject.CommonName,
		OrgUnit: firstOU(cert),
		Cert:    cert,
		Key:     key,
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
	}, nil
}

func parseCertPEM(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("tlsx: no CERTIFICATE block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("tlsx: parse certificate: %w", err)
	}
	return cert, nil
}

func parseKeyPEM(data []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("tlsx: no PEM block")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("tlsx: parse EC key: %w", err)
	}
	return key, nil
}

// Verification is separated from issuance on purpose.
//
// The gateway verifies device and operator certificates against their roots, and
// never issues anything. If it loaded a CA as a keypair it would be handed a path
// it must never use, and the filesystem would have to make that CA key readable in
// order for the process to start — which is precisely the escalation we are trying
// to prevent. So the gateway loads roots as certificates only, and the CA private
// keys stay unreadable to it. That constraint is now enforced by the type system
// rather than by remembering to pass a flag.

// Verifier is a certificate authority usable for verification only.
type Verifier struct {
	Cert *x509.Certificate
	// Pool trusts this root, for use as a TLS ClientCAs.
	Pool *x509.CertPool
}

// LoadVerifierFile reads a CA certificate file and never touches any key.
func LoadVerifierFile(path string) (*Verifier, error) {
	certPEM, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("tlsx: read CA %s: %w", path, err)
	}
	return verifierFromPEM(certPEM, path)
}

// LoadVerifier reads <dir>/ca.crt and never touches ca.key.
func LoadVerifier(dir string) (*Verifier, error) {
	certPEM, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if err != nil {
		return nil, fmt.Errorf("tlsx: read ca.crt: %w", err)
	}
	return verifierFromPEM(certPEM, dir)
}

func verifierFromPEM(certPEM []byte, origin string) (*Verifier, error) {
	cert, err := parseCertPEM(certPEM)
	if err != nil {
		return nil, err
	}
	if !cert.IsCA {
		return nil, fmt.Errorf("tlsx: %s is not a CA certificate", origin)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &Verifier{Cert: cert, Pool: pool}, nil
}

// ServerTLSFromVerifier builds a listener config trusting exactly one root,
// addressed by the verification-only representation.
func ServerTLSFromVerifier(v *Verifier, serverCert tls.Certificate, minVer uint16) (*tls.Config, error) {
	if minVer == 0 {
		minVer = tls.VersionTLS13
	}
	return &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    v.Pool,
		MinVersion:   minVer,
		// The platform has no use for renegotiation, and pinning it off keeps the
		// post-handshake state machine small.
		Renegotiation: tls.RenegotiateNever,
	}, nil
}

// ClientTLSFromVerifier builds an outbound config that authenticates with id and
// verifies the gateway against a root, without loading any CA key.
func ClientTLSFromVerifier(v *Verifier, id *Identity, serverName string, minVer uint16) (*tls.Config, error) {
	if minVer == 0 {
		minVer = tls.VersionTLS13
	}
	cert, err := id.TLSCertificate()
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      v.Pool,
		ServerName:   serverName,
		MinVersion:   minVer,
	}, nil
}
