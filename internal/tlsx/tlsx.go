// Package tlsx issues and configures the two-tier PKI that ARD relies on.
//
// There are two independent roots: one for devices, one for operators. They are
// never mixed. A device certificate cannot complete a TLS handshake against the
// operator listener and vice versa, because each listener trusts exactly one
// root. Mixing them into a single pool would be a silent authorization bug.
package tlsx

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// OrgUnit values mark the role of a leaf certificate. The listener that trusts
// the CA already constrains the role, so this is belt-and-braces for operators
// and for audit records that must attribute a certificate to an identity.
const (
	OrgUnitDevice   = "ard-device"
	OrgUnitOperator = "ard-operator"
	OrgUnitServer   = "ard-server"
)

// clockSkew absorbs mild clock drift between device, operator and server so a
// freshly issued certificate is never rejected as "not yet valid".
const clockSkew = 5 * time.Minute

// CA is a certificate authority plus the key that signs with it.
type CA struct {
	Cert    *x509.Certificate
	Key     *ecdsa.PrivateKey
	CertPEM []byte
	KeyPEM  []byte
}

// NewCA generates a self-signed root. P-256 is chosen deliberately: constant time
// software and hardware P-256 is fast on the low-end ARM devices that agents run on.
func NewCA(name string, validFor time.Duration) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ca key: %w", err)
	}
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"ARD"},
			CommonName:   name,
		},
		NotBefore:             time.Now().Add(-clockSkew),
		NotAfter:              time.Now().Add(validFor),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("self-sign ca: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse ca: %w", err)
	}
	ca := &CA{Cert: cert, Key: key}
	if err := ca.derivePEM(); err != nil {
		return nil, err
	}
	return ca, nil
}

// Issue signs a leaf certificate for the given identity and role.
func (ca *CA) Issue(cn, orgUnit string, ttl time.Duration) (*Identity, error) {
	return ca.issue(cn, orgUnit, ttl, nil)
}

// issue is the shared leaf-issuing path. mutate, when non-nil, adjusts the
// template before signing so roles that need extra fields (server SANs, EKU)
// cannot diverge from the serial number, key usage or validity handling.
func (ca *CA) issue(cn, orgUnit string, ttl time.Duration, mutate func(*x509.Certificate)) (*Identity, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate leaf key: %w", err)
	}
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization:       []string{"ARD"},
			OrganizationalUnit: []string{orgUnit},
			CommonName:         cn,
		},
		NotBefore:             time.Now().Add(-clockSkew),
		NotAfter:              time.Now().Add(ttl),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	if mutate != nil {
		mutate(tmpl)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		return nil, fmt.Errorf("sign leaf: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse leaf: %w", err)
	}
	id := &Identity{Name: cn, OrgUnit: orgUnit, Cert: leaf, Key: key, CA: ca}
	if err := id.derivePEM(); err != nil {
		return nil, err
	}
	return id, nil
}

// Identity is an issued leaf certificate and its private key.
type Identity struct {
	Name    string
	OrgUnit string
	Cert    *x509.Certificate
	Key     *ecdsa.PrivateKey
	CA      *CA

	CertPEM []byte
	KeyPEM  []byte
}

// TLSCertificate assembles a value usable by crypto/tls on either side.
func (i *Identity) TLSCertificate() (tls.Certificate, error) {
	return tls.X509KeyPair(i.CertPEM, i.KeyPEM)
}

// ServerTLS builds a listener config that accepts only leaves from ca.
//
// ClientCAs contains exactly one root, so cross-role handshakes fail at the TLS
// layer rather than being rejected later by application code.
func ServerTLS(ca *CA, serverCert tls.Certificate, minVer uint16) (*tls.Config, error) {
	if minVer == 0 {
		minVer = tls.VersionTLS13
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	return &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   minVer,
		// This platform has no use for legacy renegotiation and pinning it off
		// keeps the post-handshake state machine small.
		Renegotiation: tls.RenegotiateNever,
	}, nil
}

// ClientTLS builds an outbound config that authenticates with id and verifies the
// server against ca. serverName is passed separately because the certificate's
// DNS names may not cover a raw IP, and IPAddresses does not cover a hostname.
func ClientTLS(ca *CA, id *Identity, serverName string, minVer uint16) (*tls.Config, error) {
	if minVer == 0 {
		minVer = tls.VersionTLS13
	}
	cert, err := id.TLSCertificate()
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ServerName:   serverName,
		MinVersion:   minVer,
	}, nil
}

// VerifyPeerRole reports the peer certificate's role and name. It is a defensive
// check: the listener already enforced the role by CA, so a mismatch here means
// the deployment is misconfigured.
func VerifyPeerRole(state tls.ConnectionState, wantOrgUnit string) (string, error) {
	if len(state.PeerCertificates) == 0 {
		return "", errors.New("tls: peer presented no certificate")
	}
	leaf := state.PeerCertificates[0]
	ou := firstOU(leaf)
	if wantOrgUnit != "" && ou != wantOrgUnit {
		return "", fmt.Errorf("tls: peer role %q, want %q", ou, wantOrgUnit)
	}
	return leaf.Subject.CommonName, nil
}

func firstOU(cert *x509.Certificate) string {
	if len(cert.Subject.OrganizationalUnit) == 0 {
		return ""
	}
	return cert.Subject.OrganizationalUnit[0]
}

func (ca *CA) derivePEM() error {
	certPEM, err := encodePEM("CERTIFICATE", ca.Cert.Raw)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(ca.Key)
	if err != nil {
		return fmt.Errorf("marshal ca key: %w", err)
	}
	keyPEM, err := encodePEM("EC PRIVATE KEY", keyDER)
	if err != nil {
		return err
	}
	ca.CertPEM, ca.KeyPEM = certPEM, keyPEM
	return nil
}

func (i *Identity) derivePEM() error {
	certPEM, err := encodePEM("CERTIFICATE", i.Cert.Raw)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(i.Key)
	if err != nil {
		return fmt.Errorf("marshal leaf key: %w", err)
	}
	keyPEM, err := encodePEM("EC PRIVATE KEY", keyDER)
	if err != nil {
		return err
	}
	i.CertPEM, i.KeyPEM = certPEM, keyPEM
	return nil
}

func encodePEM(blockType string, der []byte) ([]byte, error) {
	out := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	if out == nil {
		return nil, errors.New("tlsx: pem encode failed")
	}
	return out, nil
}

// SaveDir writes an identity as <prefix>.crt and <prefix>.key with owner-only
// permissions. Private keys are never written world-readable.
func (i *Identity) SaveDir(dir, prefix string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("tlsx: mkdir %s: %w", dir, err)
	}
	if err := os.WriteFile(filepath.Join(dir, prefix+".crt"), i.CertPEM, 0o644); err != nil {
		return fmt.Errorf("tlsx: write crt: %w", err)
	}
	return os.WriteFile(filepath.Join(dir, prefix+".key"), i.KeyPEM, 0o600)
}

func (ca *CA) SaveDir(dir, prefix string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("tlsx: mkdir %s: %w", dir, err)
	}
	if err := os.WriteFile(filepath.Join(dir, prefix+".crt"), ca.CertPEM, 0o644); err != nil {
		return fmt.Errorf("tlsx: write ca crt: %w", err)
	}
	return os.WriteFile(filepath.Join(dir, prefix+".key"), ca.KeyPEM, 0o600)
}

func newSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("tlsx: serial: %w", err)
	}
	return n.Add(n, big.NewInt(1)), nil
}