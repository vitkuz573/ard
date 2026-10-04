package tlsx

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"
)

func testCA(t *testing.T) *CA {
	t.Helper()
	ca, err := NewCA("test-devices", 24*time.Hour)
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	return ca
}

// The whole point of a CSR: the CA signs a key it never sees. If the certificate's
// public key differed from the request's, the device would end up holding a
// certificate it cannot use, and that surfaces as a TLS error much later.
func TestSignCSRProducesCertificateForTheRequestersKey(t *testing.T) {
	ca := testCA(t)
	req, err := GenerateRequest("pixel-8-abc123", OrgUnitDevice)
	if err != nil {
		t.Fatalf("GenerateRequest: %v", err)
	}
	signed, err := ca.SignCSR(req.CSRPEM, 365*24*time.Hour)
	if err != nil {
		t.Fatalf("SignCSR: %v", err)
	}
	if signed.OrgUnit != OrgUnitDevice {
		t.Fatalf("OrgUnit = %q, want %q", signed.OrgUnit, OrgUnitDevice)
	}
	if signed.Name != "pixel-8-abc123" {
		t.Fatalf("Name = %q", signed.Name)
	}
	leaf := parseLeaf(t, signed.CertPEM)
	if !leaf.PublicKey.(*ecdsa.PublicKey).Equal(&req.Key.PublicKey) {
		t.Fatal("certificate public key is not the requester's key")
	}
	if leaf.Subject.CommonName != "pixel-8-abc123" {
		t.Fatalf("CN = %q", leaf.Subject.CommonName)
	}
	if got := leaf.Subject.OrganizationalUnit; len(got) != 1 || got[0] != OrgUnitDevice {
		t.Fatalf("OU = %v", got)
	}
	// The issued certificate must work with the device's own key, which is the only
	// combination the agent will ever hold.
	keyPEM, err := req.KeyPEM()
	if err != nil {
		t.Fatalf("KeyPEM: %v", err)
	}
	if _, err := TLSCertificateFromPEM(signed.CertPEM, keyPEM); err != nil {
		t.Fatalf("pairing the issued certificate with the device key failed: %v", err)
	}
}

// Proof of possession is what makes it safe to relay CSRs: the gateway stores and
// forwards requests it cannot check, so signing has to stay impossible for anyone
// holding only a public key. Corrupting the signature is exactly that attempt.
func TestSignCSRRejectsTamperedSignature(t *testing.T) {
	ca := testCA(t)
	req, err := GenerateRequest("device-1", OrgUnitDevice)
	if err != nil {
		t.Fatalf("GenerateRequest: %v", err)
	}
	block, _ := pem.Decode(req.CSRPEM)
	der := append([]byte{}, block.Bytes...)
	// Flip a bit in the signature, which lives at the end of the structure. The
	// public key still parses, so only CheckSignature can catch this.
	der[len(der)-1] ^= 0xFF
	tampered := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	if _, err := ca.SignCSR(tampered, time.Hour); err == nil {
		t.Fatal("a CSR with a tampered signature was signed")
	} else if !strings.Contains(err.Error(), "proof of possession") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// A public key with no signature at all must not parse as a request.
func TestSignCSRRejectsUnsignedRequest(t *testing.T) {
	ca := testCA(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := ca.SignCSR(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), time.Hour); err == nil {
		t.Fatal("a private key was accepted as a certificate request")
	}
}

// The OU decides which role every listener believes the peer is claiming. Accepting
// an arbitrary one would let a device ask to be signed as something else.
func TestGenerateRequestRejectsUnknownRole(t *testing.T) {
	if _, err := GenerateRequest("device-1", "ard-anything-i-like"); err == nil {
		t.Fatal("GenerateRequest accepted an unknown role")
	} else if !errors.Is(err, ErrUnknownRole) {
		t.Fatalf("error = %v, want ErrUnknownRole", err)
	}
	// The same check must apply to a CSR arriving inside hand-built PEM, because the
	// gateway relays PEM it did not create.
	if _, err := testCA(t).SignCSR(csrWithOU(t, "device-1", "ard-root"), time.Hour); err == nil {
		t.Fatal("a CSR requesting role ard-root was signed")
	}
	if _, err := testCA(t).SignCSR(csrWithOU(t, "device-1", ""), time.Hour); err == nil {
		t.Fatal("a CSR with no role was signed")
	}
}

// A device must not be able to talk the CA into a server certificate. EKU comes
// from the OU, and the OU is allowlisted, so the two cannot be decoupled.
func TestSignCSRCannotChooseItsOwnKeyUsage(t *testing.T) {
	ca := testCA(t)
	req, err := GenerateRequest("gateway-lookalike", OrgUnitDevice)
	if err != nil {
		t.Fatalf("GenerateRequest: %v", err)
	}
	signed, err := ca.SignCSR(req.CSRPEM, time.Hour)
	if err != nil {
		t.Fatalf("SignCSR: %v", err)
	}
	leaf := parseLeaf(t, signed.CertPEM)
	var hasClient, hasServer bool
	for _, eku := range leaf.ExtKeyUsage {
		switch eku {
		case x509.ExtKeyUsageClientAuth:
			hasClient = true
		case x509.ExtKeyUsageServerAuth:
			hasServer = true
		}
	}
	if hasServer {
		t.Fatal("a device certificate was issued with ServerAuth usage")
	}
	if !hasClient {
		t.Fatal("device certificate lacks ClientAuth usage")
	}
}

// A requester must not be able to grant itself an unbounded lifetime.
func TestSignCSRRejectsExcessiveTTL(t *testing.T) {
	ca := testCA(t)
	req, err := GenerateRequest("device-1", OrgUnitDevice)
	if err != nil {
		t.Fatalf("GenerateRequest: %v", err)
	}
	if _, err := ca.SignCSR(req.CSRPEM, 10*365*24*time.Hour); err == nil {
		t.Fatal("a 10-year leaf was issued")
	}
	if _, err := ca.SignCSR(req.CSRPEM, 0); err == nil {
		t.Fatal("a zero-lifetime leaf was issued")
	}
	if _, err := ca.SignCSR(req.CSRPEM, -time.Hour); err == nil {
		t.Fatal("a negative-lifetime leaf was issued")
	}
}

// A leaf with a requester-chosen SAN is a leaf the requester partly controls, and
// nothing in this design needs one.
func TestSignCSRRejectsSubjectAltName(t *testing.T) {
	ca := testCA(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{
			Organization:       []string{"ARD"},
			OrganizationalUnit: []string{OrgUnitDevice},
			CommonName:         "device-1",
		},
		DNSNames: []string{"gateway.example.com"},
	}, key)
	if err != nil {
		t.Fatalf("csr: %v", err)
	}
	p := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	if _, err := ca.SignCSR(p, time.Hour); err == nil {
		t.Fatal("a CSR carrying a SAN was signed")
	} else if !strings.Contains(err.Error(), "subjectAltName") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSignCSRRejectsGarbage(t *testing.T) {
	ca := testCA(t)
	for name, in := range map[string][]byte{
		"empty":       nil,
		"not pem":     []byte("this is not a certificate request"),
		"wrong type":  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1, 2, 3}}),
		"truncated":   reqTruncated(t),
		"private key": reqPrivateKeyPEM(t),
	} {
		if _, err := ca.SignCSR(in, time.Hour); err == nil {
			t.Errorf("%s: expected refusal", name)
		}
	}
}

// helpers

func parseLeaf(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatalf("leaf is not PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return leaf
}

func csrWithOU(t *testing.T, cn, ou string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{
			Organization:       []string{"ARD"},
			OrganizationalUnit: []string{ou},
			CommonName:         cn,
		},
	}, key)
	if err != nil {
		t.Fatalf("csr: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func reqTruncated(t *testing.T) []byte {
	t.Helper()
	req, err := GenerateRequest("device-1", OrgUnitDevice)
	if err != nil {
		t.Fatalf("GenerateRequest: %v", err)
	}
	block, _ := pem.Decode(req.CSRPEM)
	der := block.Bytes
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der[:len(der)/2]})
}

func reqPrivateKeyPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}
