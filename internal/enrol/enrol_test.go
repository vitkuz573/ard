package enrol

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// The flow this package exists for, end to end and in-process: a device submits a
// CSR and gets a code, an operator claims it, signs it and delivers, and the device
// confirms. If any step of that breaks, enrolment is a manual procedure again.
func TestMailboxFullEnrolmentFlow(t *testing.T) {
	m := NewMailbox(10 * time.Minute)

	pending, code, err := m.Put(Submit{
		DeviceID:   "pixel-8-abc123",
		DeviceName: "Google Pixel 8",
		CSRPEM:     []byte("-----BEGIN CERTIFICATE REQUEST-----\nfake\n-----END CERTIFICATE REQUEST-----\n"),
	})
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if code == "" {
		t.Fatal("Put returned no claim code")
	}

	// The operator's view: enough context to be sure of what they are approving.
	claimed, err := m.Claim(code)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if claimed.DeviceID != "pixel-8-abc123" {
		t.Fatalf("DeviceID = %q", claimed.DeviceID)
	}
	if string(claimed.CSRPEM) != string(pending.CSRPEM) {
		t.Fatal("claimed CSR differs from the submitted one")
	}

	// Device side, waiting in the background the way a connection handler would.
	type received struct {
		cert, ca []byte
		ack      func(error)
		err      error
	}
	got := make(chan received, 1)
	go func() {
		cert, ca, ack, err := pending.Receive(context.Background())
		got <- received{cert: cert, ca: ca, ack: ack, err: err}
	}()

	cert := []byte("-----BEGIN CERTIFICATE-----\nsigned\n-----END CERTIFICATE-----\n")
	ca := []byte("-----BEGIN CERTIFICATE-----\nroot\n-----END CERTIFICATE-----\n")

	var (
		outcome *Outcome
		derr    error
		wg      sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		outcome, derr = m.Deliver(code, cert, ca, 5*time.Second)
	}()

	r := <-got
	if r.err != nil {
		t.Fatalf("Receive: %v", r.err)
	}
	if string(r.cert) != string(cert) {
		t.Fatalf("device received %q", r.cert)
	}
	if string(r.ca) != string(ca) {
		t.Fatalf("device received CA %q", r.ca)
	}
	r.ack(nil)
	wg.Wait()

	if derr != nil {
		t.Fatalf("Deliver: %v", derr)
	}
	if !outcome.OK || outcome.DeviceID != "pixel-8-abc123" {
		t.Fatalf("outcome = %+v", outcome)
	}
	// A confirmed request is consumed, so the same code cannot enrol a second device.
	if m.Len() != 0 {
		t.Fatalf("mailbox still holds %d requests after a confirmed enrolment", m.Len())
	}
	if _, err := m.Claim(code); !errors.Is(err, ErrNotFound) {
		t.Fatalf("claiming a completed code returned %v, want ErrNotFound", err)
	}
}

// A device that rejects the certificate must not be reported as enrolled. This is the
// case that a "delivered" response would hide.
func TestDeliverReportsDeviceRejection(t *testing.T) {
	m := NewMailbox(time.Minute)
	pending, code, err := m.Put(Submit{DeviceID: "d1", CSRPEM: []byte("csr")})
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _, ack, _ := pending.Receive(context.Background())
		ack(errors.New("certificate does not match the key I generated"))
	}()

	if _, err := m.Deliver(code, []byte("cert"), nil, 5*time.Second); err == nil {
		t.Fatal("a device that rejected the certificate was reported as delivered")
	} else if !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("the device's own reason was lost: %v", err)
	}
	<-done
}

// A code that was never issued must say so, not look like a successful enrolment.
func TestDeliverUnknownCodeIsNotSuccess(t *testing.T) {
	m := NewMailbox(time.Minute)
	if _, err := m.Deliver("ZZZZ-ZZZZ", []byte("cert"), nil, time.Second); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Deliver of an unknown code = %v, want ErrNotFound", err)
	}
	if _, err := m.Claim("ZZZZ-ZZZZ"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Claim of an unknown code = %v, want ErrNotFound", err)
	}
}

// A device that has gone away must not make the operator hang forever. The request is
// deliberately kept so a retry is possible, but the operator has to get an answer.
func TestDeliverTimesOutWhenDeviceIsSilent(t *testing.T) {
	m := NewMailbox(time.Minute)
	pending, code, err := m.Put(Submit{DeviceID: "d1", CSRPEM: []byte("csr")})
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	_ = pending
	go func() {
		// Receive, then never acknowledge: exactly a device that froze mid-write.
		_, _, ack, rerr := pending.Receive(ctx)
		if rerr != nil {
			return
		}
		select {
		case <-ctx.Done():
		}
		_ = ack
	}()

	start := time.Now()
	_, err = m.Deliver(code, []byte("cert"), nil, 200*time.Millisecond)
	if err == nil {
		t.Fatal("Deliver waited successfully for a device that never answered")
	}
	if elapsed := time.Since(start); elapsed < 150*time.Millisecond {
		t.Fatalf("Deliver gave up after %s, before its own timeout", elapsed)
	}
	cancel()
}

// An expired request must be gone, and its device must be told rather than left
// hanging until its own deadline.
func TestExpiredRequestIsDroppedAndDeviceWoken(t *testing.T) {
	m := NewMailbox(time.Minute)
	m.now = func() time.Time { return time.Unix(1_700_000_000, 0) }
	pending, code, err := m.Put(Submit{DeviceID: "d1", CSRPEM: []byte("csr")})
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	// Move past the deadline.
	m.now = func() time.Time { return time.Unix(1_700_000_000, 0).Add(2 * time.Minute) }

	if _, err := m.Claim(code); !errors.Is(err, ErrNotFound) {
		t.Fatalf("claiming an expired request = %v, want ErrNotFound", err)
	}
	if m.Len() != 0 {
		t.Fatalf("%d expired requests survived", m.Len())
	}
	// The waiting device gets released rather than left blocked.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, _, _, rerr := pending.Receive(ctx); rerr == nil {
		t.Fatal("Receive returned a certificate for an expired request")
	}
}

// The port this mailbox sits behind is reachable by anyone who can open a TCP
// connection, so the bounds are the security-relevant part.
func TestMailboxBoundsUntrustedInput(t *testing.T) {
	m := NewMailbox(time.Minute)

	if _, _, err := m.Put(Submit{CSRPEM: []byte("csr")}); err == nil {
		t.Fatal("a request with no device id was accepted")
	}
	if _, _, err := m.Put(Submit{DeviceID: "d", CSRPEM: nil}); err == nil {
		t.Fatal("a request with no CSR was accepted")
	}
	if _, _, err := m.Put(Submit{DeviceID: strings.Repeat("x", MaxDeviceIDLen+1), CSRPEM: []byte("csr")}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversized device id = %v, want ErrTooLarge", err)
	}
	if _, _, err := m.Put(Submit{DeviceID: "d", DeviceName: strings.Repeat("n", MaxDeviceNameLn+1), CSRPEM: []byte("csr")}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversized device name = %v, want ErrTooLarge", err)
	}
	big := make([]byte, MaxCSRBytes+1)
	if _, _, err := m.Put(Submit{DeviceID: "d", CSRPEM: big}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversized CSR = %v, want ErrTooLarge", err)
	}

	// Flooding must hit the cap rather than growing without bound.
	for i := 0; i < MaxPending; i++ {
		if _, _, err := m.Put(Submit{DeviceID: "d", CSRPEM: []byte("csr")}); err != nil {
			t.Fatalf("request %d of %d refused early: %v", i, MaxPending, err)
		}
	}
	if _, _, err := m.Put(Submit{DeviceID: "d", CSRPEM: []byte("csr")}); !errors.Is(err, ErrFull) {
		t.Fatalf("request past the cap = %v, want ErrFull", err)
	}
	if m.Len() != MaxPending {
		t.Fatalf("mailbox holds %d, want %d", m.Len(), MaxPending)
	}
}

// The code is read off a screen and typed by hand, so both steps have to tolerate the
// ways people actually type it.
func TestClaimCodeIsForgivingAboutHowItWasTyped(t *testing.T) {
	m := NewMailbox(time.Minute)
	_, code, err := m.Put(Submit{DeviceID: "d1", CSRPEM: []byte("csr")})
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	for _, typed := range []string{
		code,
		strings.ToLower(code),
		strings.ReplaceAll(code, "-", ""),
		strings.ReplaceAll(code, "-", " "),
		"  " + code + "  ",
	} {
		if _, err := m.Claim(typed); err != nil {
			t.Errorf("Claim(%q) = %v, want success", typed, err)
		}
	}
}

// A code must not contain the characters people confuse when reading a phone screen.
func TestClaimCodeAvoidsAmbiguousCharacters(t *testing.T) {
	m := NewMailbox(time.Minute)
	for i := 0; i < 50; i++ {
		_, code, err := m.Put(Submit{DeviceID: "d", CSRPEM: []byte("csr")})
		if err != nil {
			t.Fatalf("Put: %v", err)
		}
		bare := strings.ReplaceAll(code, "-", "")
		if len(bare) != 8 {
			t.Fatalf("code %q is not 8 characters", code)
		}
		if strings.ContainsAny(bare, "IO01") {
			t.Fatalf("code %q contains an easily misread character", code)
		}
		m.Complete(code)
	}
}

// Concurrently claiming and completing must not corrupt the map or double-deliver.
func TestConcurrentClaimsAreSafe(t *testing.T) {
	m := NewMailbox(time.Minute)
	_, code, err := m.Put(Submit{DeviceID: "d1", CSRPEM: []byte("csr")})
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if i%2 == 0 {
				_, _ = m.Claim(code)
				return
			}
			m.Complete(code)
		}(i)
	}
	wg.Wait()
	if _, err := m.Claim(code); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after concurrent completes the request survived: %v", err)
	}
}

// A request must not be mutated through the struct a caller received, or through the
// slice the caller submitted.
func TestClaimReturnsACopy(t *testing.T) {
	m := NewMailbox(time.Minute)
	csr := []byte("original")
	_, code, err := m.Put(Submit{DeviceID: "d1", CSRPEM: csr})
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	first, err := m.Claim(code)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	first.DeviceID = "tampered"
	first.CSRPEM[0] = 'X'

	second, err := m.Claim(code)
	if err != nil {
		t.Fatalf("second Claim: %v", err)
	}
	if second.DeviceID != "d1" {
		t.Fatalf("stored request was mutated: %q", second.DeviceID)
	}
	if string(second.CSRPEM) != "original" {
		t.Fatalf("stored CSR was mutated: %q", second.CSRPEM)
	}
	// And the caller's own slice must not have been aliased into storage.
	csr[0] = 'Y'
	third, err := m.Claim(code)
	if err != nil {
		t.Fatalf("third Claim: %v", err)
	}
	if string(third.CSRPEM) != "original" {
		t.Fatalf("stored CSR aliases the caller's slice: %q", third.CSRPEM)
	}
}
