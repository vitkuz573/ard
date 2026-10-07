// Package enrol carries certificate requests from a device to whoever holds the CA.
//
// The problem it solves: a device private key on a server, in a terminal, in an adb push
// and in shell history is a device private key in four places it should never be.
//
// So the device generates its own key and sends a CSR, and the private key never
// moves. What still needs to happen is a decision by a human: a CA must not sign
// requests that arrive on their own. The gateway cannot sign anything -- it holds no
// CA key -- so it cannot be the decision point either.
//
// Which leaves a mailbox. A device submits a CSR and receives a short claim code. The
// operator types that code into a tool holding the CA, which fetches the CSR, signs it
// on the operator's side of the trust boundary, and sends the certificate back. The
// gateway stores and forwards; it never signs.
//
// The code is what makes the operator's approval specific. Without it, an approval for
// "device-7" would sign whatever CSR happened to be sitting under that name, and
// anyone on the internet can submit one of those.
package enrol

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

// Sizes are bounded because this port is reachable by anyone who can open a TCP
// connection to the gateway. A request that is mostly padding costs memory and CPU to
// hold, and nothing legitimate is large.
const (
	MaxCSRBytes     = 8 << 10
	MaxDeviceIDLen  = 128
	MaxDeviceNameLn = 128
	// MaxPending caps how many unenrolled devices can wait at once. Enrolment is a
	// rare, human-paced operation, so a handful is generous; anything approaching
	// this limit is abuse rather than a backlog.
	MaxPending = 16
)

// Errors a caller can distinguish. Both the device and the operator tool show these to
// a human, and "not found" versus "expired" is the difference between retyping a code
// and starting over.
var (
	ErrNotFound = errors.New("enrol: no such request")
	ErrExpired  = errors.New("enrol: request expired")
	ErrFull     = errors.New("enrol: too many pending requests")
	ErrTooLarge = errors.New("enrol: request too large")
)

// Submit is what a device sends first. CSRPEM is a byte slice so it survives the JSON
// round trip as base64 rather than as something a parser might reformat.
type Submit struct {
	DeviceID   string `json:"device_id"`
	DeviceName string `json:"device_name,omitempty"`
	CSRPEM     []byte `json:"csr_pem"`

	// GatewayCertSHA256 is the fingerprint of the certificate the gateway actually
	// presented, taken from the TLS handshake.
	//
	// It exists because a device enrolling for the first time has no CA certificate and
	// therefore nothing to verify the gateway against. Rather than trust it blindly, the
	// device reports what it saw and the operator's tool compares it against the CA it
	// holds. A machine-in-the-middle can feed the device its own certificate, but it
	// cannot make the observed fingerprint match, so the attempt fails before anything
	// is signed.
	//
	// It is an observation, not a claim: the gateway does not compute it, and a
	// compromised gateway could put anything here. What makes it meaningful is that the
	// operator checks it against a value held outside this system.
	GatewayCertSHA256 string `json:"gateway_cert_sha256,omitempty"`

	// Error is set instead of a CSR when the request is refused. Without it a rejection
	// arrives as a dropped connection, which tells the device nothing about whether to
	// retry.
	Error string `json:"error,omitempty"`
}

// Receipt is the device's answer: the code to show the operator, and how long it stays
// valid.
type Receipt struct {
	Code      string `json:"code"`
	RequestID string `json:"request_id"`
	ValidFor  string `json:"valid_for"`

	// ObservedGatewayFingerprint echoes back what the device reported, so the device can
	// show the operator exactly which certificate it is about to trust.
	ObservedGatewayFingerprint string `json:"observed_gateway_fingerprint,omitempty"`
}

// Claim is what the operator-side tool sends to fetch a pending request.
type Claim struct {
	Code string `json:"code"`
}

// Claimed is the CSR the operator is about to sign, with enough context to be sure they
// are approving what they think they are approving.
type Claimed struct {
	RequestID  string `json:"request_id"`
	DeviceID   string `json:"device_id"`
	DeviceName string `json:"device_name,omitempty"`
	CSRPEM     []byte `json:"csr_pem"`

	// ObservedGatewayFingerprint is what the device saw when it connected, carried here
	// so the party that signs can check it against the CA it holds. See
	// Submit.GatewayCertSHA256 for why this is worth doing.
	ObservedGatewayFingerprint string `json:"observed_gateway_fingerprint,omitempty"`

	// Error is set instead of a CSR when the code is unknown or expired. Without it a
	// failed claim is indistinguishable from an empty one, and an operator tool would
	// report it as "nothing to sign" rather than "that code is wrong".
	Error string `json:"error,omitempty"`
}

// Grant carries a signed certificate back to a waiting device.
type Grant struct {
	Code    string `json:"code"`
	CertPEM []byte `json:"cert_pem"`
	CAPEM   []byte `json:"ca_pem"`
}

// Outcome is the device's own confirmation. It exists because "the gateway accepted
// this certificate" and "the device stored it" are different claims, and only the
// second one means the device is enrolled.
type Outcome struct {
	RequestID string `json:"request_id"`
	DeviceID  string `json:"device_id,omitempty"`
	OK        bool   `json:"ok"`
	Error     string `json:"error,omitempty"`
}

type grant struct {
	certPEM []byte
	caPEM   []byte
}

// Pending is one device's request, held until it is signed, delivered or expires.
//
// Delivery is a rendezvous between two goroutines in one process: the device
// connection waiting to be enrolled, and the control-socket request holding the CA.
//
// Every channel is buffered, so neither side can block the other and neither has to
// know whether the other has arrived yet. That matters because the operator learns the
// code the instant the device submits, and could deliver in the gap before the device
// goroutine reaches Receive. Without a buffer, that race would show up as an
// intermittent enrolment failure in the field.
type Pending struct {
	RequestID         string
	DeviceID          string
	DeviceName        string
	CSRPEM            []byte
	GatewayCertSHA256 string
	Created           time.Time
	Expires           time.Time

	grants    chan grant
	acks      chan error
	cancelled chan struct{}
	once      sync.Once
}

// Receive waits for the operator to deliver a certificate.
//
// It is the device's half. The returned ack must be called exactly once, with nil if the
// files were written and an error otherwise: the operator's command is waiting on that
// answer, and reporting success it never observed is worse than reporting nothing.
func (p *Pending) Receive(ctx context.Context) (certPEM, caPEM []byte, ack func(error), err error) {
	select {
	case g := <-p.grants:
		var once sync.Once
		return g.certPEM, g.caPEM, func(e error) {
			once.Do(func() {
				// Never blocks: acks is buffered, and a second call is dropped rather
				// than deadlocking a goroutine that is already shutting down.
				select {
				case p.acks <- e:
				default:
				}
			})
		}, nil
	case <-p.cancelled:
		return nil, nil, nil, errors.New("enrol: request withdrawn")
	case <-ctx.Done():
		return nil, nil, nil, ctx.Err()
	}
}

// WaitAck waits for the device's answer. It is the operator-side half.
func (p *Pending) WaitAck(timeout time.Duration) error {
	select {
	case err := <-p.acks:
		return err
	case <-time.After(timeout):
		return fmt.Errorf("enrol: device did not confirm within %s", timeout)
	}
}

// Mailbox holds pending enrolment requests.
//
// Every operation is short: map access and a copy. Nothing blocks under the lock, so a
// device that has gone away cannot stall enrolment for anybody else.
type Mailbox struct {
	mu    sync.Mutex
	items map[string]*Pending
	ttl   time.Duration

	// now is injectable so expiry can be tested without sleeping.
	now func() time.Time
}

// NewMailbox returns a mailbox holding requests for ttl.
func NewMailbox(ttl time.Duration) *Mailbox {
	return &Mailbox{items: map[string]*Pending{}, ttl: ttl, now: time.Now}
}

// TTL reports how long a request stays valid.
func (m *Mailbox) TTL() time.Duration { return m.ttl }

// Put stores a request and returns it with its claim code.
//
// The code is 8 characters of an alphabet with no I, O, 0 or 1, because it gets read
// off a phone screen and typed into a terminal by a person. That is 40 bits, and
// together with a short lifetime and single use it is a confirmation token rather than
// a guessable credential.
func (m *Mailbox) Put(sub Submit) (*Pending, string, error) {
	if strings.TrimSpace(sub.DeviceID) == "" {
		return nil, "", errors.New("enrol: device id is required")
	}
	if len(sub.DeviceID) > MaxDeviceIDLen {
		return nil, "", ErrTooLarge
	}
	if len(sub.DeviceName) > MaxDeviceNameLn {
		return nil, "", ErrTooLarge
	}
	if len(sub.CSRPEM) == 0 {
		return nil, "", errors.New("enrol: empty csr")
	}
	if len(sub.CSRPEM) > MaxCSRBytes {
		return nil, "", ErrTooLarge
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.sweepLocked()

	if len(m.items) >= MaxPending {
		return nil, "", ErrFull
	}
	code, err := m.uniqueCodeLocked()
	if err != nil {
		return nil, "", err
	}
	id, err := randomToken(16)
	if err != nil {
		return nil, "", err
	}
	now := m.now()
	p := &Pending{
		RequestID:         hex.EncodeToString(id),
		DeviceID:          sub.DeviceID,
		DeviceName:        sub.DeviceName,
		CSRPEM:            append([]byte(nil), sub.CSRPEM...),
		GatewayCertSHA256: sub.GatewayCertSHA256,
		Created:           now,
		Expires:           now.Add(m.ttl),
		grants:            make(chan grant, 1),
		acks:              make(chan error, 1),
		cancelled:         make(chan struct{}),
	}
	// Stored under the normalised form, because every lookup normalises what it is
	// given. Storing the pretty form here would mean a code typed without its dash
	// never matches, which is the one way an operator is most likely to type it.
	m.items[normalizeCode(code)] = p
	return p, code, nil
}

// Claim returns a pending request for signing without consuming it.
//
// Non-destructive on purpose: the operator may sign successfully and then fail to
// deliver, and discarding the CSR to a network error would mean restarting enrolment on
// the phone. The request is consumed by Complete, after the device confirms.
func (m *Mailbox) Claim(code string) (*Pending, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sweepLocked()
	p, ok := m.items[normalizeCode(code)]
	if !ok {
		return nil, ErrNotFound
	}
	// Copy rather than hand out the live struct: the caller must not be able to mutate
	// what is stored, and must not reach the delivery channels. The CSR gets its own
	// backing array, because a caller that edits the bytes it was handed must not be
	// editing the pending request everybody else is about to sign.
	return &Pending{
		RequestID:         p.RequestID,
		DeviceID:          p.DeviceID,
		DeviceName:        p.DeviceName,
		CSRPEM:            append([]byte(nil), p.CSRPEM...),
		GatewayCertSHA256: p.GatewayCertSHA256,
		Created:           p.Created,
		Expires:           p.Expires,
		grants:            make(chan grant, 1),
		acks:              make(chan error, 1),
		cancelled:         make(chan struct{}),
	}, nil
}

// Deliver hands a signed certificate to the waiting device and waits for it to confirm
// that it stored it.
//
// It returns an error for a request that is absent rather than reporting success, so
// "delivered" can never be claimed for something that was never there.
func (m *Mailbox) Deliver(code string, certPEM, caPEM []byte, timeout time.Duration) (*Outcome, error) {
	if len(certPEM) == 0 {
		return nil, errors.New("enrol: no certificate to deliver")
	}
	key := normalizeCode(code)
	m.mu.Lock()
	p, ok := m.items[key]
	m.mu.Unlock()
	if !ok {
		return nil, ErrNotFound
	}

	select {
	case p.grants <- grant{certPEM: certPEM, caPEM: caPEM}:
	case <-p.cancelled:
		return nil, errors.New("enrol: request withdrawn")
	}

	if err := p.WaitAck(timeout); err != nil {
		// The request stays in place on purpose. The device may still be writing the
		// files, and an operator retry is far cheaper than restarting on the phone.
		return nil, err
	}
	m.Complete(code)
	return &Outcome{RequestID: p.RequestID, DeviceID: p.DeviceID, OK: true}, nil
}

// Complete removes a request. Called once the device has confirmed.
func (m *Mailbox) Complete(code string) {
	key := normalizeCode(code)
	m.mu.Lock()
	p, ok := m.items[key]
	delete(m.items, key)
	m.mu.Unlock()
	if ok {
		// Wake a device that is still waiting, so it reports failure instead of sitting
		// until its own deadline.
		p.once.Do(func() { close(p.cancelled) })
	}
}

// Cancel is Complete under a name that says what it is for.
func (m *Mailbox) Cancel(code string) { m.Complete(code) }

// Len reports how many requests are pending, for diagnostics and tests.
func (m *Mailbox) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.items)
}

// sweepLocked drops expired requests. A background sweep would be tidier, but expiry is
// also checked on every operation, so correctness never depends on a timer firing.
func (m *Mailbox) sweepLocked() {
	now := m.now()
	for code, p := range m.items {
		if now.After(p.Expires) {
			delete(m.items, code)
			p.once.Do(func() { close(p.cancelled) })
		}
	}
}

// uniqueCodeLocked draws a code not already in use.
func (m *Mailbox) uniqueCodeLocked() (string, error) {
	for attempt := 0; attempt < 8; attempt++ {
		raw, err := randomToken(8)
		if err != nil {
			return "", err
		}
		code := formatCode(raw)
		if _, taken := m.items[code]; !taken {
			return code, nil
		}
	}
	return "", errors.New("enrol: could not allocate a unique code")
}

// codeAlphabet omits I, O, 0 and 1: those are the characters people misread between a
// phone screen and a keyboard.
const codeAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

func formatCode(raw []byte) string {
	var b strings.Builder
	for i, c := range raw {
		if i == 4 {
			b.WriteByte('-')
		}
		b.WriteByte(codeAlphabet[int(c)%len(codeAlphabet)])
	}
	return b.String()
}

// normalizeCode accepts a code as typed, with the dash missing, lowercase, or replaced
// by a space, and returns the canonical form. The operator types it by hand, so being
// forgiving here is worth more than being strict.
func normalizeCode(in string) string {
	up := strings.ToUpper(strings.TrimSpace(in))
	up = strings.ReplaceAll(up, "-", "")
	up = strings.ReplaceAll(up, " ", "")
	return up
}

// randomToken returns n bytes of entropy. Used for both codes and request ids; neither
// is a secret, but both must be unguessable enough that a caller cannot enumerate
// somebody else's request.
func randomToken(n int) ([]byte, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("enrol: entropy: %w", err)
	}
	return buf, nil
}

// WriteJSON writes one JSON value.
//
// Enrolment messages are small and few, so a single value per connection is the whole
// framing. There is no stream to multiplex and no reason to invent a length prefix.
func WriteJSON(w io.Writer, v any) error {
	return json.NewEncoder(w).Encode(v)
}

// ReadJSON reads one JSON value, refusing to buffer more than limit bytes.
//
// The limit is the important part: this port is reachable by anyone who can open a TCP
// connection, so an unbounded read is a way to make the gateway allocate whatever the
// sender claims it wants.
func ReadJSON(r io.Reader, v any, limit int64) error {
	return json.NewDecoder(io.LimitReader(r, limit)).Decode(v)
}
