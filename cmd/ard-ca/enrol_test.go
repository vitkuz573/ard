package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vitkuz573/ard/internal/enrol"
	"github.com/vitkuz573/ard/internal/tlsx"
)

// writePKI builds a server root plus a server leaf, which is all confirmGateway reads.
func writePKI(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	ca, err := tlsx.NewCA("test-server-ca", 24*time.Hour)
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	if err := ca.SaveDir(filepath.Join(dir, "server"), "ca"); err != nil {
		t.Fatalf("SaveDir: %v", err)
	}
	id, err := ca.IssueServer("ard-server", []string{"localhost"}, nil, time.Hour)
	if err != nil {
		t.Fatalf("IssueServer: %v", err)
	}
	if err := id.SaveDir(filepath.Join(dir, "server"), "server"); err != nil {
		t.Fatalf("SaveDir leaf: %v", err)
	}
	return dir
}

// The fingerprint of the real gateway must be accepted, or enrolment would never work.
func TestConfirmGatewayAcceptsTheMatchingCertificate(t *testing.T) {
	dir := writePKI(t)
	serverPEM, err := os.ReadFile(filepath.Join(dir, "server", "server.crt"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	err = confirmGateway(&enrol.Claimed{ObservedGatewayFingerprint: certFingerprint(serverPEM)}, dir)
	if err != nil {
		t.Fatalf("the real gateway's own fingerprint was refused: %v", err)
	}
}

// This is the check the whole first-contact design rests on. A device with no CA
// certificate cannot verify the gateway, so it reports what it was shown and the signing
// side compares it. A machine-in-the-middle can complete the handshake, receive the CSR
// and look entirely convincing; all it cannot do is produce a fingerprint that matches.
//
// If this test ever passes with a wrong fingerprint, the design's only protection against
// interception at enrolment is gone.
func TestConfirmGatewayRefusesADifferentCertificate(t *testing.T) {
	dir := writePKI(t)

	// A second, entirely unrelated PKI: what an interceptor would present.
	other := t.TempDir()
	otherCA, err := tlsx.NewCA("attacker-ca", 24*time.Hour)
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	if err := otherCA.SaveDir(filepath.Join(other, "server"), "ca"); err != nil {
		t.Fatalf("SaveDir: %v", err)
	}
	otherID, err := otherCA.IssueServer("ard-server", []string{"localhost"}, nil, time.Hour)
	if err != nil {
		t.Fatalf("IssueServer: %v", err)
	}
	if err := otherID.SaveDir(filepath.Join(other, "server"), "server"); err != nil {
		t.Fatalf("SaveDir leaf: %v", err)
	}
	attackerPEM, err := os.ReadFile(filepath.Join(other, "server", "server.crt"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	err = confirmGateway(&enrol.Claimed{ObservedGatewayFingerprint: certFingerprint(attackerPEM)}, dir)
	if err == nil {
		t.Fatal("a certificate from a different PKI was accepted: enrolment would sign for whoever is intercepting")
	}
	// The message has to show both values, or the operator cannot tell a misconfigured
	// device from an interception attempt.
	msg := err.Error()
	if !strings.Contains(msg, "different gateway") {
		t.Errorf("error does not explain the mismatch: %v", err)
	}
	if !strings.Contains(msg, "intercepting") {
		t.Errorf("error does not mention interception, so a real attack reads like a typo: %v", err)
	}
}

// A device that reports nothing cannot be checked, and "cannot be checked" must not be
// treated as "checked and fine".
func TestConfirmGatewayRefusesAnUnreportedFingerprint(t *testing.T) {
	dir := writePKI(t)
	if err := confirmGateway(&enrol.Claimed{}, dir); err == nil {
		t.Fatal("an unreported fingerprint was accepted")
	}
}

// Fingerprints get read aloud and retyped, so the two spellings of the same hash must
// compare equal. Getting this wrong would refuse every legitimate enrolment while
// appearing to work.
func TestFingerprintComparisonToleratesFormatting(t *testing.T) {
	dir := writePKI(t)
	serverPEM, err := os.ReadFile(filepath.Join(dir, "server", "server.crt"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	canonical := certFingerprint(serverPEM)

	spaced := ""
	for i := 0; i < len(canonical); i += 2 {
		if i > 0 {
			spaced += ":"
		}
		spaced += canonical[i : i+2]
	}

	for name, spelling := range map[string]string{
		"canonical":         canonical,
		"colon grouped":     spaced,
		"upper case":        strings.ToUpper(canonical),
		"surrounding space": "  " + canonical + "  ",
	} {
		if err := confirmGateway(&enrol.Claimed{ObservedGatewayFingerprint: spelling}, dir); err != nil {
			t.Errorf("%s spelling refused: %v", name, err)
		}
	}
}

// The operator must be shown the request before approving it, and the approval must
// cover this request. A CSR that names a different device than the one submitted is the
// obvious way to get someone to sign the wrong thing.
func TestConfirmIdentityRefusesAMismatch(t *testing.T) {
	ca, err := tlsx.NewCA("test-devices", 24*time.Hour)
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	req, err := tlsx.GenerateRequest("device-7", tlsx.OrgUnitDevice)
	if err != nil {
		t.Fatalf("GenerateRequest: %v", err)
	}
	_ = ca

	// Names agree: accepted.
	if err := confirmIdentity(&enrol.Claimed{DeviceID: "device-7", CSRPEM: req.CSRPEM}); err != nil {
		t.Fatalf("a matching request was refused: %v", err)
	}

	// The device submitted as one thing and asked to be signed as another.
	err = confirmIdentity(&enrol.Claimed{DeviceID: "device-7", CSRPEM: mustCSR(t, "somebody-elses-phone")})
	if err == nil {
		t.Fatal("a CSR naming a different device was accepted")
	}
	if !strings.Contains(err.Error(), "refusing") {
		t.Errorf("unhelpful error: %v", err)
	}
}

// A CSR asking for a role other than device must not be signed by a tool whose whole
// purpose is to sign device certificates.
func TestConfirmIdentityRefusesTheWrongRole(t *testing.T) {
	err := confirmIdentity(&enrol.Claimed{DeviceID: "device-7", CSRPEM: mustCSRRole(t, "device-7", tlsx.OrgUnitOperator)})
	if err == nil {
		t.Fatal("a CSR requesting the operator role was accepted for device enrolment")
	}
	if !strings.Contains(err.Error(), "role") {
		t.Errorf("error does not mention the role: %v", err)
	}
}

func TestConfirmIdentityRefusesGarbage(t *testing.T) {
	for name, csr := range map[string][]byte{
		"empty":     nil,
		"not a csr": []byte("hello"),
		"a cert":    mustCertPEM(t),
	} {
		if err := confirmIdentity(&enrol.Claimed{DeviceID: "device-7", CSRPEM: csr}); err == nil {
			t.Errorf("%s: expected refusal", name)
		}
	}
}

// helpers

func mustCSR(t *testing.T, name string) []byte {
	t.Helper()
	req, err := tlsx.GenerateRequest(name, tlsx.OrgUnitDevice)
	if err != nil {
		t.Fatalf("GenerateRequest: %v", err)
	}
	return req.CSRPEM
}

func mustCSRRole(t *testing.T, name, role string) []byte {
	t.Helper()
	req, err := tlsx.GenerateRequest(name, role)
	if err != nil {
		// GenerateRequest refuses unknown roles, which is itself the first line of
		// defence; build the CSR by hand to test the second.
		return handBuiltCSR(t, name, role)
	}
	return req.CSRPEM
}

func mustCertPEM(t *testing.T) []byte {
	t.Helper()
	ca, err := tlsx.NewCA("t", time.Hour)
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	signed, err := ca.SignCSR(mustCSR(t, "d"), time.Minute)
	if err != nil {
		t.Fatalf("SignCSR: %v", err)
	}
	return signed.CertPEM
}

// handBuiltCSR builds a request for a role GenerateRequest would refuse.
//
// GenerateRequest allowlists roles, so testing that a hand-built request for another role
// is still refused at signing time needs a request that bypassed the first check.
func handBuiltCSR(t *testing.T, cn, role string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{
			Organization:       []string{"ARD"},
			OrganizationalUnit: []string{role},
			CommonName:         cn,
		},
	}, key)
	if err != nil {
		t.Fatalf("csr: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}
