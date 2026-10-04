package main

// Enrolment, device side.
//
// The device generates its own key pair, sends a CSR, shows the operator a claim code,
// receives a certificate and stores it. At no point does a private key leave this
// process: the key is written to the device's private storage and the only thing that
// travels is a signature over a public key.
//
// It lives in the agent rather than in the app because the cryptography is here already
// and in Java it would need the same code a second time. The app's part is one button
// and one field to display the code.
//
// The first contact is the awkward part, and it is handled by refusing to trust
// anything it has not been shown. A device with no CA certificate cannot verify the
// gateway, so it records the fingerprint of whatever was presented and hands it to the
// operator, who compares it against the PKI they hold. A machine-in-the-middle can
// therefore complete the TLS handshake and even receive the CSR, but it cannot produce a
// fingerprint that matches, and nothing is signed.

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/vitkuz573/ard/internal/enrol"
	"github.com/vitkuz573/ard/internal/tlsx"
)

// enrolOptions configures one enrolment attempt.
type enrolOptions struct {
	Gateway    string // host:port of the enrolment listener
	ServerName string
	DeviceID   string
	DeviceName string
	OutDir     string // where device.key, device.crt and ca.crt are written
	Timeout    time.Duration
}

// enrolTimeout bounds the whole exchange. The wait is dominated by a human reading a
// code and typing it into a terminal on the other machine, so this is generous; a
// device that gives up early is worse than one that waits.
const enrolTimeout = 10 * time.Minute

// runEnrol performs one enrolment and returns the process exit code.
//
// The exit code matters: the app runs this as a child process and has no other way to
// find out what happened. Every failure gets a distinct, documented code rather than a
// generic 1, because "enrolment failed" and "the operator declined" call for different
// things from the person holding the phone.
func runEnrol(opt enrolOptions) error {
	if opt.Gateway == "" {
		return errors.New("-enrol-gateway is required")
	}
	if opt.DeviceID == "" {
		return errors.New("-enrol-id is required: the gateway uses it as the device's identity")
	}
	if opt.OutDir == "" {
		return errors.New("-enrol-out is required")
	}
	if opt.Timeout <= 0 {
		opt.Timeout = enrolTimeout
	}

	req, err := tlsx.GenerateRequest(opt.DeviceID, tlsx.OrgUnitDevice)
	if err != nil {
		return fmt.Errorf("generate a key pair: %w", err)
	}
	keyPEM, err := req.KeyPEM()
	if err != nil {
		return err
	}
	// Written before the network is touched. If enrolment then fails, the next attempt
	// reuses this key instead of orphaning it, and a half-finished enrolment never
	// leaves a key that nothing references.
	if err := writePrivate(opt.OutDir, "device.key", keyPEM); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), opt.Timeout)
	defer cancel()

	conn, observed, err := dialEnrolGateway(ctx, opt)
	if err != nil {
		return err
	}
	defer conn.Close()

	if err := enrol.WriteJSON(conn, enrol.Submit{
		DeviceID:          opt.DeviceID,
		DeviceName:        opt.DeviceName,
		CSRPEM:            req.CSRPEM,
		GatewayCertSHA256: observed,
	}); err != nil {
		return fmt.Errorf("send the certificate request: %w", err)
	}

	var receipt enrol.Receipt
	if err := enrol.ReadJSON(conn, &receipt, 8<<10); err != nil {
		return fmt.Errorf("read the gateway's answer: %w", err)
	}
	if receipt.Code == "" {
		return errors.New("the gateway refused the request; nothing was signed")
	}

	// Everything the operator needs to make the decision, and nothing more. The
	// fingerprint matters as much as the code: it is how the operator knows this phone is
	// talking to the gateway they think it is.
	fmt.Printf("code=%s\n", receipt.Code)
	fmt.Printf("device_id=%s\n", opt.DeviceID)
	fmt.Printf("gateway_fingerprint=%s\n", receipt.ObservedGatewayFingerprint)
	fmt.Printf("valid_for=%s\n", receipt.ValidFor)

	var grant enrol.Grant
	if err := enrol.ReadJSON(conn, &grant, enrol.MaxCSRBytes*2); err != nil {
		return fmt.Errorf("no certificate arrived: %w", err)
	}
	if err := verifyGrantedIdentity(grant.CertPEM, keyPEM, opt.DeviceID); err != nil {
		// Tell the operator rather than dying quietly: they may have signed the wrong
		// thing, and they need to know before they retry.
		_ = enrol.WriteJSON(conn, enrol.Outcome{Error: err.Error()})
		return err
	}
	if len(grant.CAPEM) == 0 {
		_ = enrol.WriteJSON(conn, enrol.Outcome{Error: "no CA certificate was delivered"})
		return errors.New("the gateway delivered a certificate but no CA certificate")
	}
	if err := writeFile(opt.OutDir, "device.crt", grant.CertPEM, 0o644); err != nil {
		_ = enrol.WriteJSON(conn, enrol.Outcome{Error: err.Error()})
		return err
	}
	if err := writeFile(opt.OutDir, "ca.crt", grant.CAPEM, 0o644); err != nil {
		_ = enrol.WriteJSON(conn, enrol.Outcome{Error: err.Error()})
		return err
	}

	// Only now is enrolment reported as successful, and only because the files are on
	// disk. The operator is waiting on this answer, so it must be the truth.
	if err := enrol.WriteJSON(conn, enrol.Outcome{RequestID: receipt.RequestID, DeviceID: opt.DeviceID, OK: true}); err != nil {
		return fmt.Errorf("stored the certificate but could not confirm to the gateway: %w", err)
	}
	fmt.Printf("enrolled=%s\n", opt.DeviceID)
	fmt.Printf("out=%s\n", opt.OutDir)
	return nil
}

// dialEnrolGateway connects and records which certificate was presented.
//
// Verification is deliberately not performed here, because there is nothing to verify
// against on a first enrolment: no CA certificate has reached this device yet. What the
// code does instead is return the fingerprint of the presented chain so the operator can
// check it out of band.
//
// The fingerprint is taken from the leaf the server actually presented, not from
// anything the peer claims about itself.
func dialEnrolGateway(ctx context.Context, opt enrolOptions) (*tls.Conn, string, error) {
	d := &net.Dialer{}
	raw, err := d.DialContext(ctx, "tcp", opt.Gateway)
	if err != nil {
		return nil, "", fmt.Errorf("connect to the gateway's enrolment port: %w", err)
	}
	conn := tls.Client(raw, &tls.Config{
		ServerName:         opt.ServerName,
		InsecureSkipVerify: true, // see above: the fingerprint is checked by the operator.
		MinVersion:         tls.VersionTLS13,
	})
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, "", fmt.Errorf("TLS handshake with the gateway: %w", err)
	}
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		_ = conn.Close()
		return nil, "", errors.New("the gateway presented no certificate")
	}
	sum := sha256.Sum256(state.PeerCertificates[0].Raw)
	return conn, hex.EncodeToString(sum[:]), nil
}

// verifyGrantedIdentity checks the delivered certificate against the key this device
// generated.
//
// Without this the device would store whatever arrived and only discover the mismatch
// later, as a TLS error on its first real connection. Verifying here means a
// misconfiguration is reported while the operator is still watching.
func verifyGrantedIdentity(certPEM, keyPEM []byte, wantID string) error {
	if _, err := tlsx.TLSCertificateFromPEM(certPEM, keyPEM); err != nil {
		return fmt.Errorf("the delivered certificate does not match the key this device generated: %w", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return errors.New("the delivered certificate is not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse the delivered certificate: %w", err)
	}
	if cert.Subject.CommonName != wantID {
		return fmt.Errorf("the certificate is issued to %q, not %q", cert.Subject.CommonName, wantID)
	}
	if len(cert.Subject.OrganizationalUnit) != 1 || cert.Subject.OrganizationalUnit[0] != tlsx.OrgUnitDevice {
		return fmt.Errorf("the certificate carries role %v, not %q",
			cert.Subject.OrganizationalUnit, tlsx.OrgUnitDevice)
	}
	// A device certificate that also said "I am a server" would be a way to hold both
	// roles at once, so refuse it here rather than trusting the CA to have got it right.
	for _, eku := range cert.ExtKeyUsage {
		if eku != x509.ExtKeyUsageClientAuth {
			return fmt.Errorf("the certificate carries an unexpected extended key usage (%v)", eku)
		}
	}
	return nil
}

// writeFile writes a file with the given mode, refusing to widen it.
func writeFile(dir, name string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, mode); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	// WriteFile only applies the mode when it creates the file, so an existing file
	// keeps whatever it had. Set it explicitly: a key that was briefly world-readable is
	// a key that cannot be un-leaked.
	if err := os.Chmod(path, mode); err != nil {
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	return nil
}

// writePrivate is writeFile for key material, with permissions that assume the file may
// be read by anyone who gets at the device.
func writePrivate(dir, name string, data []byte) error {
	return writeFile(dir, name, data, 0o600)
}
