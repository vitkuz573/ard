package tlsx

// Certificate signing requests.
//
// The reason this file exists: a device private key on a machine, in a chat, in an adb
// push and in the operator's shell history is a private key in four places it should
// never be, and copying one onto a phone by hand means the operator has to be present
// for every device, forever.
//
// With a CSR the device generates its own key and keeps it. The CA only ever sees
// a signature request, so there is nothing to copy and nothing to leak. The
// security property this buys is exactly the one the manual process had no way to
// offer: the private key is never in transit, not even once.

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
	"time"
)

// ErrUnknownRole means the CSR asked for an organisational unit this CA does not
// issue. Allowed is a fixed set rather than "whatever was requested", because the
// OU is what every listener uses to decide which role a peer is claiming: accept a
// CSR requesting an arbitrary OU and a device could ask to be signed as something
// other than a device.
var ErrUnknownRole = errors.New("tlsx: requested role is not issued")

// SigningRequest is a generated key pair plus the PEM request for it.
//
// Key never leaves the device that generated it. It is exported so the caller can
// persist it, not so the caller can transmit it.
type SigningRequest struct {
	Name    string
	OrgUnit string
	Key     *ecdsa.PrivateKey
	CSRPEM  []byte
}

// GenerateRequest creates a key on this machine and a CSR for it.
//
// P-256 matches NewCA and Issue: the same constant-time reasoning applies, and an
// agent on a low-end ARM device has to do this on the main UI thread's behalf.
func GenerateRequest(name, orgUnit string) (*SigningRequest, error) {
	if err := validRole(orgUnit); err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{
			Organization:       []string{"ARD"},
			OrganizationalUnit: []string{orgUnit},
			CommonName:         name,
		},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}, key)
	if err != nil {
		return nil, fmt.Errorf("create csr: %w", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	return &SigningRequest{Name: name, OrgUnit: orgUnit, Key: key, CSRPEM: csrPEM}, nil
}

// validRole restricts issuance to the three roles this PKI defines.
func validRole(orgUnit string) error {
	switch orgUnit {
	case OrgUnitDevice, OrgUnitOperator, OrgUnitServer:
		return nil
	default:
		return fmt.Errorf("%w: %q", ErrUnknownRole, orgUnit)
	}
}

// SignedCertificate is what the CA returns for a CSR: a certificate and no key.
type SignedCertificate struct {
	Name    string
	OrgUnit string
	CertPEM []byte
}

// SignCSR issues a leaf for csrPEM.
//
// The CSR's own signature is verified, which is the proof of possession: the
// requester cannot get a certificate for a public key it does not hold the private
// key for. Everything else in the certificate is decided here, not by the requester,
// so a CSR cannot talk the CA into an unexpected serial, key usage, lifetime or
// extended key usage.
func (ca *CA) SignCSR(csrPEM []byte, ttl time.Duration) (*SignedCertificate, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("csr: not a PEM certificate request")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("csr: parse: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("csr: proof of possession failed: %w", err)
	}
	if len(csr.URIs) != 0 || len(csr.DNSNames) != 0 || len(csr.IPAddresses) != 0 {
		// A leaf whose subjectAltName the requester chose is a leaf the requester
		// partly controls. Nothing in this design needs one, so refuse rather than
		// silently dropping fields the requester believed were in effect.
		return nil, errors.New("csr: subjectAltName is not accepted from a request")
	}
	name := csr.Subject.CommonName
	if name == "" {
		return nil, errors.New("csr: empty common name")
	}
	var orgUnit string
	for _, ou := range csr.Subject.OrganizationalUnit {
		if orgUnit != "" {
			return nil, errors.New("csr: more than one organisational unit")
		}
		orgUnit = ou
	}
	if err := validRole(orgUnit); err != nil {
		return nil, err
	}
	if ttl <= 0 {
		return nil, errors.New("csr: ttl must be positive")
	}
	if ttl > maxLeafTTL {
		return nil, fmt.Errorf("csr: ttl %s exceeds the maximum %s this CA will issue", ttl, maxLeafTTL)
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
			CommonName:         name,
		},
		NotBefore:             time.Now().Add(-clockSkew),
		NotAfter:              time.Now().Add(ttl),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{extKeyUsageFor(orgUnit)},
		BasicConstraintsValid: true,
	}
	// The CA signs the certificate over the key from the CSR, so the leaf and the
	// device's private key are bound by the device's own signature, not by anything
	// this process generated.
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, csr.PublicKey, ca.Key)
	if err != nil {
		return nil, fmt.Errorf("csr: sign: %w", err)
	}
	return &SignedCertificate{
		Name:    name,
		OrgUnit: orgUnit,
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}, nil
}

// maxLeafTTL bounds what a CSR can ask for, so a compromised or buggy operator
// endpoint cannot mint a certificate that outlives the revocation story.
const maxLeafTTL = 365 * 24 * time.Hour

// extKeyUsageFor keeps a CSR from choosing its own. A device must present a client
// certificate; the server presents a server one. Getting this from the OU rather
// than the request means the CA cannot be talked into issuing a server
// certificate to something that is not the gateway.
func extKeyUsageFor(orgUnit string) x509.ExtKeyUsage {
	if orgUnit == OrgUnitServer {
		return x509.ExtKeyUsageServerAuth
	}
	return x509.ExtKeyUsageClientAuth
}

// KeyPEM encodes the request's private key for storage on the device that made it.
func (r *SigningRequest) KeyPEM() ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(r.Key)
	if err != nil {
		return nil, fmt.Errorf("marshal key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}

// TLSCertificateFromPEM pairs a certificate with the key held on this device.
//
// This is the only way a device assembles a TLS identity after enrolment, and it
// takes both halves from local storage, so the private key is never an input from
// anywhere else in the system.
func TLSCertificateFromPEM(certPEM, keyPEM []byte) (tls.Certificate, error) {
	if len(certPEM) == 0 {
		return tls.Certificate{}, errors.New("tlsx: no certificate")
	}
	if len(keyPEM) == 0 {
		return tls.Certificate{}, errors.New("tlsx: no private key")
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}

// PeekCSR returns the common name and organisational unit a request asks for.
//
// It exists so an operator can see who a request claims to be before approving it, and so
// the approver can compare that against the device id printed by the gateway. It parses
// and reports without checking the signature: the signature is checked in SignCSR, which
// is the only place where a decision is made on the contents.
func PeekCSR(csrPEM []byte) (cn, orgUnit string, err error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return "", "", errors.New("tlsx: not a PEM certificate request")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return "", "", fmt.Errorf("tlsx: parse csr: %w", err)
	}
	if len(csr.Subject.OrganizationalUnit) > 1 {
		return "", "", errors.New("tlsx: more than one organisational unit")
	}
	if len(csr.Subject.OrganizationalUnit) == 1 {
		orgUnit = csr.Subject.OrganizationalUnit[0]
	}
	return csr.Subject.CommonName, orgUnit, nil
}
