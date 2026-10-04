package tlsx

import (
	"crypto/ecdsa"
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