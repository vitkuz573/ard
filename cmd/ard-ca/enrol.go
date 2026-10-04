package main

// Enrolment, operator side.
//
// This is where a certificate actually gets signed. It runs on whichever machine holds
// the device CA -- in practice the gateway host, as root, invoked over SSH -- and it is
// the only step in the whole flow that needs the CA key.
//
// Two properties fall out of where the signing happens:
//
//   - The gateway never signs. It forwards CSRs and delivers certificates. So a
//     compromised gateway cannot mint device identities, which is the escalation this
//     PKI layout exists to prevent.
//   - The operator sees the request before approving it: which device, which request id,
//     and the CSR itself. Approving is a decision about a specific request, not a
//     standing grant to whatever turns up next.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vitkuz573/ard/internal/enrol"
	"github.com/vitkuz573/ard/internal/tlsx"
)

// cmdEnrol claims a pending request by code, signs it and delivers it.
//
// -yes exists because the whole point is that a human approves a specific request, and
// a flag that must be typed to bypass that is worth having: it makes "I did not mean to
// do that" a distinguishable event in the audit log rather than an accident.
func cmdEnrol(args []string) error {
	fs := flag.NewFlagSet("enrol", flag.ContinueOnError)
	pkiDir := fs.String("dir", "/etc/ard/pki", "pki directory containing the device CA")
	socket := fs.String("socket", "/run/ard/control.sock", "gateway control socket")
	code := fs.String("code", "", "claim code shown on the device")
	ttl := fs.Duration("ttl", 365*24*time.Hour, "certificate lifetime")
	yes := fs.Bool("yes", false, "approve without printing the request first")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *code == "" {
		return errors.New("-code is required; it is the code shown on the device")
	}

	claimed, err := claimRequest(*socket, *code)
	if err != nil {
		return err
	}

	if !*yes {
		fmt.Printf("device id    %s\n", claimed.DeviceID)
		if claimed.DeviceName != "" {
			fmt.Printf("device name  %s\n", claimed.DeviceName)
		}
		fmt.Printf("request      %s\n", claimed.RequestID)
		fmt.Printf("role         %s\n", roleOf(claimed.CSRPEM))
		sum := sha256.Sum256(claimed.CSRPEM)
		fmt.Printf("csr          %d bytes, SHA-256 %x\n", len(claimed.CSRPEM), sum[:8])
		fmt.Printf("\nApprove signing this certificate for %s? [y/N] ", claimed.DeviceID)
		var answer string
		if _, err := fmt.Scanln(&answer); err != nil {
			return errors.New("no answer: refusing to sign. pass -yes to approve without a prompt")
		}
		switch answer {
		case "y", "Y", "yes", "Yes":
		default:
			return errors.New("declined: nothing was signed")
		}
	}

	// Verify the request matches what was approved, before using it. The operator read
	// a device id off the terminal; the CSR carries the identity that will end up in the
	// certificate. If they disagree, the approval was not of this request.
	if err := confirmIdentity(claimed); err != nil {
		return err
	}
	if err := confirmGateway(claimed, *pkiDir); err != nil {
		return err
	}

	ca, err := tlsx.LoadCA(filepath.Join(*pkiDir, "devices"))
	if err != nil {
		return fmt.Errorf("load the device CA: %w", err)
	}
	signed, err := ca.SignCSR(claimed.CSRPEM, *ttl)
	if err != nil {
		return fmt.Errorf("sign: %w", err)
	}

	// The certificate delivered to the device must be the SERVER root, not the device
	// root that just signed the leaf. The device's -ca is what verifies the gateway's
	// certificate on every subsequent connection, and the gateway presents a server
	// certificate. Handing over the device root here produces an identity that is valid
	// and correctly signed but cannot verify anything -- the first real connection fails
	// with "signed by unknown authority" and no explanation.
	serverCAPEM, err := os.ReadFile(filepath.Join(*pkiDir, "server", "ca.crt"))
	if err != nil {
		return fmt.Errorf("read the server CA certificate to deliver to the device: %w", err)
	}

	outcome, err := deliverCertificate(*socket, *code, signed.CertPEM, serverCAPEM)
	if err != nil {
		// Signed but not delivered. Say exactly that: the certificate exists, the phone
		// does not have it, and the operator can simply run this again with the same
		// code. Blurring it into "failed" would send them back to the phone instead.
		return fmt.Errorf("signed, but delivery to the device did not complete: %w", err)
	}
	if !outcome.OK {
		return fmt.Errorf("the device refused the certificate: %s", outcome.Error)
	}
	fmt.Printf("enrolled %s (request %s): the device confirmed it stored the certificate\n",
		outcome.DeviceID, outcome.RequestID)
	return nil
}

// claimRequest asks the gateway for the request a code refers to.
//
// One request per connection, because that is how the control socket is built: it reads a
// single request, answers it and closes. Reusing the connection for the delivery that
// follows would fail on a broken pipe, which is exactly what happened the first time
// this was written.
func claimRequest(socket, code string) (*enrol.Claimed, error) {
	conn, err := dialControl(socket, 30*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := writeControl(conn, map[string]any{"op": "enrol.claim", "code": code}); err != nil {
		return nil, fmt.Errorf("claim request: %w", err)
	}
	var claimed enrol.Claimed
	if err := json.NewDecoder(conn).Decode(&claimed); err != nil {
		return nil, fmt.Errorf("read claim response: %w", err)
	}
	if claimed.Error != "" {
		return nil, fmt.Errorf("cannot claim %s: %s", code, claimed.Error)
	}
	if len(claimed.CSRPEM) == 0 {
		return nil, errors.New("the gateway returned no certificate request for that code")
	}
	return &claimed, nil
}

// deliverCertificate sends the signed certificate back and waits for the device's answer.
//
// The deadline is longer than the gateway's own wait on purpose. The gateway blocks until
// the device has written its files and answered, and if this side gave up first it would
// report a timeout for a request that was about to succeed -- and the operator would
// reasonably conclude that enrolment had failed.
func deliverCertificate(socket, code string, certPEM, caPEM []byte) (*enrol.Outcome, error) {
	conn, err := dialControl(socket, 3*time.Minute)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := writeControl(conn, map[string]any{
		"op": "enrol.deliver", "code": code,
		"cert_pem": certPEM, "ca_pem": caPEM,
	}); err != nil {
		return nil, fmt.Errorf("deliver certificate: %w", err)
	}
	var outcome enrol.Outcome
	if err := json.NewDecoder(conn).Decode(&outcome); err != nil {
		return nil, fmt.Errorf("read delivery response: %w", err)
	}
	return &outcome, nil
}

// dialControl opens one control-socket connection with a deadline.
func dialControl(socket string, timeout time.Duration) (net.Conn, error) {
	conn, err := net.Dial("unix", socket)
	if err != nil {
		return nil, fmt.Errorf("connect to the gateway control socket: %w", err)
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	return conn, nil
}

func writeControl(conn net.Conn, v any) error {
	enc := json.NewEncoder(conn)
	if err := enc.Encode(v); err != nil {
		return fmt.Errorf("write to the control socket: %w", err)
	}
	return nil
}

// confirmIdentity checks that the CSR's common name is the device the operator approved.
//
// The device proposes its own name, so nothing stops a device asking to be enrolled as
// something else. The code binds the approval to one request, and this check binds that
// request to the name that will be in the certificate, so a mismatch is refused here
// rather than showing up later as a device that cannot connect.
func confirmIdentity(claimed *enrol.Claimed) error {
	name, orgUnit, err := tlsx.PeekCSR(claimed.CSRPEM)
	if err != nil {
		return fmt.Errorf("inspect the certificate request: %w", err)
	}
	if name != claimed.DeviceID {
		return fmt.Errorf("the request asks for identity %q but was submitted as %q; refusing", name, claimed.DeviceID)
	}
	if orgUnit != tlsx.OrgUnitDevice {
		return fmt.Errorf("the request asks for role %q, not %q; refusing", orgUnit, tlsx.OrgUnitDevice)
	}
	return nil
}

// roleOf is only used to print something readable before approval.
func roleOf(csrPEM []byte) string {
	_, orgUnit, err := tlsx.PeekCSR(csrPEM)
	if err != nil {
		return "unreadable"
	}
	return orgUnit
}

// confirmGateway checks that the gateway the device reached is the gateway this PKI
// belongs to.
//
// A device enrolling for the first time has nothing to verify the gateway against, so it
// reports the fingerprint of the certificate it was actually shown. This compares that
// against the server certificate in the PKI directory.
//
// This is where a machine-in-the-middle is caught. The attacker can hand the device
// whatever certificate it likes, and the device will happily talk to it -- but the
// fingerprint that comes back will not match, so nothing gets signed and the operator
// sees why. Checking after the device has already been given a certificate would be too
// late; the certificate would exist and be usable.
func confirmGateway(claimed *enrol.Claimed, pkiDir string) error {
	if claimed.ObservedGatewayFingerprint == "" {
		// Not fatal on its own: an older device may not report it. But it does mean the
		// first-contact trust was never checked, so say so rather than pass silently.
		return errors.New("the device did not report which gateway it reached, so the " +
			"first connection cannot be verified; refusing to sign")
	}
	serverPEM, err := os.ReadFile(filepath.Join(pkiDir, "server", "server.crt"))
	if err != nil {
		return fmt.Errorf("read the gateway certificate to compare against: %w", err)
	}
	expected := certFingerprint(serverPEM)
	got := normalizeFingerprint(claimed.ObservedGatewayFingerprint)
	if got != expected {
		return fmt.Errorf("the device reached a different gateway than this PKI belongs to\n"+
			"  device saw:  %s\n"+
			"  expected:    %s\n"+
			"refusing to sign: either the device is configured for another gateway, or "+
			"something is intercepting the connection", got, expected)
	}
	return nil
}

// certFingerprint is the SHA-256 of a certificate's DER, as colon-separated hex.
//
// Hashing the DER rather than the PEM means the value cannot change just because the
// file was re-wrapped or re-indented.
func certFingerprint(certPEM []byte) string {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return ""
	}
	sum := sha256.Sum256(block.Bytes)
	return normalizeFingerprint(hex.EncodeToString(sum[:]))
}

// normalizeFingerprint makes two spellings of the same value comparable: a device that
// groups hex into pairs and one that does not are reporting the same hash.
func normalizeFingerprint(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, ":", "")
	s = strings.ReplaceAll(s, " ", "")
	return s
}
