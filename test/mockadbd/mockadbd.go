// Package mockadbd implements enough of adbd's wire protocol to stand in for a real
// Android device.
//
// This exists so the whole relay stack can be tested deterministically: transport
// framing, multiplexing, reconnection, authorization and byte-for-byte integrity
// are all exercised without an emulator in the loop. The emulator is still used
// later for the final acceptance pass, because it is the only thing that proves
// the implementation matches real adbd rather than this model of it.
//
// Protocol reference: AOSP packages/modules/adb/daemon/ and
// packages/modules/adb/adb_auth_host.cpp.
package mockadbd

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// Commands as they appear on the wire, little-endian.
const (
	CmdCNXN uint32 = 0x4e584e43 // "CNXN"
	CmdAUTH uint32 = 0x48545541 // "AUTH"
	CmdOPEN uint32 = 0x4e45504f // "OPEN"
	CmdOKAY uint32 = 0x59414b4f // "OKAY"
	CmdCLSE uint32 = 0x45534c43 // "CLSE"
	CmdWRTE uint32 = 0x45545257 // "WRTE"
)

// AUTH subtypes.
const (
	authToken        uint32 = 1
	authSignature    uint32 = 2
	authRSAPublicKey uint32 = 3
)

// connVersion is AOSP's CNXN version: 0x01000000.
// connVersionLegacy is the pre-checksum CNXN version, kept only as documentation of
// what older hosts send. The reply mirrors the host rather than assuming one.
const connVersionLegacy = 0x01000000

// maxPayload is the largest data payload we will accept. adbd uses 4096 or
// 1MB depending on the transport; a hostile peer must not be able to make us
// allocate on a size it chose.
const maxPayload = 1 << 20

// headerLen is the fixed size of an ADB message header.
const headerLen = 24

// Message is a decoded ADB packet.
type Message struct {
	Cmd  uint32
	Arg0 uint32
	Arg1 uint32
	Data []byte
	// DataCheck is the header's integrity field. It is retained because whether
	// it must be verified depends on the negotiated protocol version, which is
	// only known after the CNXN exchange.
	DataCheck uint32
}

// Config configures a mock device.
type Config struct {
	// FS is the filesystem the device presents. Nil means "build a seeded default",
	// because a simulator with no storage can only answer eight commands and is not
	// worth much as a test fixture.
	FS *VFS

	// Banner is sent in CNXN. The real format is
	// "device::ro.product.name=...;ro.product.model=...;features=...".
	Banner string

	// TrustedHostKeyPath points at an adbkey.pub file. When set, the device
	// demands RSA authentication and accepts only a signature made by the
	// matching private key.
	//
	// Note which key this is. adb signs with the HOST's key from
	// ~/.android/adbkey, so a device verifying the host must know the HOST's
	// public key, not one of its own. A real phone populates its authorised-host
	// list out of band, via a consent prompt or an MDM profile; the mock is handed
	// the same list explicitly, which is what makes an auth test meaningful rather
	// than a comparison against a key the peer never had.
	TrustedHostKeyPath string

	// Shell handles a "shell:" service request. When nil a default handler
	// answers a small set of commands so tests can assert on real behaviour.
	Shell func(argv []string, stdin io.Reader, stdout, stderr io.Writer) int

	// Debug, when set, receives a line per protocol event. Interoperating with a
	// real adb is the only way to validate this implementation, and when it goes
	// wrong the packet trace is the only useful diagnostic.
	Debug func(format string, args ...any)
}

func (c Config) debug(format string, args ...any) {
	if c.Debug != nil {
		c.Debug(format, args...)
	}
}

// hookWrites routes outbound packet tracing through the listener's Debug hook.
func (c Config) hookWrites() {
	if c.Debug != nil {
		debugWrites = c.Debug
	}
}

// cmdName renders a command id for logs.
func cmdName(c uint32) string {
	switch c {
	case CmdCNXN:
		return "CNXN"
	case CmdAUTH:
		return "AUTH"
	case CmdOPEN:
		return "OPEN"
	case CmdOKAY:
		return "OKAY"
	case CmdWRTE:
		return "WRTE"
	case CmdCLSE:
		return "CLSE"
	default:
		return fmt.Sprintf("0x%08x", c)
	}
}

// shortData renders payload bytes for logs without flooding them.
func shortData(b []byte) string {
	const limit = 96
	s := string(b)
	for i, r := range s {
		if r < 32 || r > 126 {
			return fmt.Sprintf("%q+%d", s[:i], len(b)-i)
		}
	}
	if len(s) > limit {
		return fmt.Sprintf("%q+%d", s[:limit], len(b)-limit)
	}
	return fmt.Sprintf("%q", s)
}

func (c *Config) withDefaults() Config {
	out := *c
	if out.Banner == "" {
		out.Banner = "device::ro.product.name=ard_mock;ro.product.model=Mock;ro.build.version.release=14;" +
			"ro.build.type=user;features=cmd,stat_v2,shell_v2"
	}
	if out.Shell == nil {
		out.Shell = defaultShell
	}
	return out
}

// Listener is a mock adbd listening for host connections.
type Listener struct {
	ln  net.Listener
	cfg Config

	mu     sync.Mutex
	closed bool
	conns  map[net.Conn]struct{}

	// The trusted host key is parsed once rather than on every connection.
	pubOnce sync.Once
	pub     *rsa.PublicKey
	pubErr  error
}

// Listen starts a mock adbd on addr.
func Listen(addr string, cfg Config) (*Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("mockadbd: listen: %w", err)
	}
	cf := cfg.withDefaults()
	cf.hookWrites()
	l := &Listener{ln: ln, cfg: cf, conns: make(map[net.Conn]struct{})}
	go l.acceptLoop()
	return l, nil
}

// Addr reports the bound address.
func (l *Listener) Addr() net.Addr { return l.ln.Addr() }

// Close stops accepting and tears down live connections.
func (l *Listener) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	for c := range l.conns {
		_ = c.Close()
	}
	l.mu.Unlock()
	return l.ln.Close()
}

func (l *Listener) acceptLoop() {
	for {
		c, err := l.ln.Accept()
		if err != nil {
			return
		}
		l.mu.Lock()
		if l.closed {
			l.mu.Unlock()
			_ = c.Close()
			return
		}
		l.conns[c] = struct{}{}
		l.mu.Unlock()
		l.cfg.debug("accepted connection from %s", c.RemoteAddr())

		go func() {
			defer func() {
				l.mu.Lock()
				delete(l.conns, c)
				l.mu.Unlock()
				_ = c.Close()
			}()
			if err := l.serve(c); err != nil {
				// A connection dying mid-session is normal when a relay
				// reconnects, so this is traced rather than surfaced as a failure.
				l.cfg.debug("connection ended: %v", err)
			} else {
				l.cfg.debug("connection ended: clean")
			}
		}()
	}
}

// conn is one host connection with its stream table.
type conn struct {
	w      io.Writer
	nextID uint32
	// version mirrors the host's CNXN arg0. Replying with the host's own version
	// keeps a legacy host from being pushed onto the checksummed path it cannot
	// read, and keeps a modern host on the fast one.
	version uint32
	mu      sync.Mutex
	streams map[uint32]*stream
	writeMu sync.Mutex
}

func (l *Listener) serve(nc net.Conn) error {
	br := bufio.NewReaderSize(nc, 64<<10)
	c := &conn{w: nc, streams: make(map[uint32]*stream)}

	first, err := readMessage(br)
	if err != nil {
		return err
	}
	l.cfg.debug("recv %s arg0=%d arg1=%d len=%d %s", cmdName(first.Cmd), first.Arg0, first.Arg1, len(first.Data), shortData(first.Data))
	if first.Cmd != CmdCNXN {
		return fmt.Errorf("mockadbd: expected CNXN, got 0x%08x", first.Cmd)
	}
	c.version = first.Arg0

	if l.cfg.TrustedHostKeyPath != "" {
		if err := l.authenticate(c, br, first); err != nil {
			return err
		}
	}
	l.cfg.debug("auth done, sending CNXN banner=%q", l.cfg.Banner)
	if err := c.write(Message{Cmd: CmdCNXN, Arg0: c.version, Arg1: maxPayload,
		Data: []byte(l.cfg.Banner)}); err != nil {
		return err
	}

	for {
		m, err := readMessage(br)
		if err != nil {
			c.closeAll(io.EOF)
			return err
		}
		l.cfg.debug("recv %s arg0=%d arg1=%d len=%d %s", cmdName(m.Cmd), m.Arg0, m.Arg1, len(m.Data), shortData(m.Data))
		if m.Cmd == CmdWRTE {
			// Data packets get a hex dump: the first byte is a frame id, so the
			// textual preview hides exactly the byte that reveals the layout.
			l.cfg.debug("     hex[0:48]=%x", m.Data[:min(48, len(m.Data))])
		}
		if err := verifyPayload(c.version, m); err != nil {
			return err
		}
		// Incoming data packets name our stream in arg1. Looking it up in arg0
		// silently drops the payload, which presents as a command that never
		// sees its input.
		switch m.Cmd {
		case CmdOPEN:
			if err := c.handleOpen(l.cfg, m); err != nil {
				return err
			}
		case CmdOKAY:
			c.deliver(m.Arg1, m.Data)
		case CmdWRTE:
			c.deliver(m.Arg1, m.Data)
		case CmdCLSE:
			// The host closing its side ends input but must not tear the stream
			// down: the command goroutine may still be reading, and closing here
			// races it, losing whatever was already delivered. Let the command
			// finish on its own and close the stream when it returns.
			if s := c.lookup(m.Arg1); s != nil {
				s.setEOF()
			}
		case CmdCNXN:
			// A second CNXN on the same connection is not legal.
			return errors.New("mockadbd: duplicate CNXN")
		default:
			return fmt.Errorf("mockadbd: unexpected command 0x%08x", m.Cmd)
		}
	}
}

// authenticate runs the AUTH_TOKEN / RSAPUBLICKEY / SIGNATURE exchange.
//
// The signature is RSA PKCS#1 v1.5 over SHA-1 of the token, which is what
// adb_auth_host.cpp produces. Verification is exact, so a relay that corrupted
// a byte would be rejected here rather than silently passing tests.
func (l *Listener) authenticate(c *conn, br *bufio.Reader, cnxn Message) error {
	pub, err := l.hostPublicKey()
	if err != nil {
		return err
	}

	token := make([]byte, 20)
	if _, err := rand.Read(token); err != nil {
		return fmt.Errorf("mockadbd: token: %w", err)
	}
	l.cfg.debug("sending AUTH TOKEN")
	if err := c.write(Message{Cmd: CmdAUTH, Arg0: authToken, Data: token}); err != nil {
		return err
	}

	for {
		reply, err := readMessage(br)
		if err != nil {
			return err
		}
		switch reply.Cmd {
		case CmdCNXN:
			// The host declined to authenticate. A secure device must refuse:
			// accepting here would let anyone in with no key at all.
			return errors.New("mockadbd: host skipped authentication")

		case CmdAUTH:
			switch reply.Arg0 {
			case authRSAPublicKey:
				// The host is offering its own key for us to authorise. A mock has
				// nothing to approve, so acknowledge and wait for the signature.
				l.cfg.debug("host offered its public key; waiting for AUTH SIGNATURE")
				if err := c.write(Message{Cmd: CmdAUTH, Arg0: authSignature, Data: token}); err != nil {
					return err
				}

			case authSignature:
				// The payload is the bare signature. The token is NOT echoed back:
				// the device issued it and already holds it, so it signs the token
				// it issued. Treating the first bytes as a token prefix shifts the
				// signature by 20 bytes and every verification fails.
				sig := reply.Data
				if len(sig) < 64 {
					return fmt.Errorf("mockadbd: AUTH SIGNATURE implausibly short (%d bytes)", len(sig))
				}
				// adb signs SHA-1 of the token with RSA PKCS#1 v1.5.
				sum := sha1.Sum(token)
				if err := rsa.VerifyPKCS1v15(pub, cryptoSHA1, sum[:], sig); err != nil {
					return fmt.Errorf("mockadbd: host signature rejected: %w", err)
				}
				l.cfg.debug("host signature verified")
				return nil

			default:
				return fmt.Errorf("mockadbd: unexpected AUTH subtype %d", reply.Arg0)
			}

		default:
			return fmt.Errorf("mockadbd: unexpected reply to AUTH TOKEN: 0x%08x", reply.Cmd)
		}
	}
}

// hostPublicKey loads the trusted host key once per listener.
func (l *Listener) hostPublicKey() (*rsa.PublicKey, error) {
	l.pubOnce.Do(func() {
		l.pub, l.pubErr = loadADBPublicKey(l.cfg.TrustedHostKeyPath)
	})
	return l.pub, l.pubErr
}

// loadADBPublicKey reads an adbkey.pub file.
//
// adb's public key files have no PEM armour: the file is one long line of base64
// decoding to AndroidPublicKey, which is a 4-byte version, a 4-byte length, and
// then that many bytes of DER SubjectPublicKeyInfo. Attempting a PEM decode
// first fails, and the resulting "no PEM block" error looks like a corrupt file
// rather than a format assumption.
func loadADBPublicKey(path string) (*rsa.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("mockadbd: read host key: %w", err)
	}
	// The file is "<base64> <comment>", where the comment is "user@host". Decoding
	// the whole line fails on the comment, and the resulting "illegal base64 data
	// at input byte N" error points into the middle of what looks like valid data,
	// which is a misleading way to learn the file has a trailing field.
	fields := strings.Fields(string(raw))
	if len(fields) == 0 {
		return nil, fmt.Errorf("mockadbd: %s: file is empty", path)
	}
	decoded, err := base64.StdEncoding.DecodeString(fields[0])
	if err != nil {
		return nil, fmt.Errorf("mockadbd: %s: base64: %w", path, err)
	}
	if len(decoded) < 8 {
		return nil, fmt.Errorf("mockadbd: %s: key too short (%d bytes)", path, len(decoded))
	}
	keyLen := int(binary.BigEndian.Uint32(decoded[4:8]))
	if keyLen <= 0 || 8+keyLen > len(decoded) {
		return nil, fmt.Errorf("mockadbd: %s: declared key length %d does not fit in %d bytes",
			path, keyLen, len(decoded))
	}
	parsed, err := x509.ParsePKIXPublicKey(decoded[8 : 8+keyLen])
	if err != nil {
		return nil, fmt.Errorf("mockadbd: %s: parse public key: %w", path, err)
	}
	rsaPub, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("mockadbd: %s: key is %T, want RSA", path, parsed)
	}
	return rsaPub, nil
}

// handleOpen services an OPEN request. arg0 is the host-assigned local id.
func (c *conn) handleOpen(cfg Config, m Message) error {
	service, arg, v2, err := parseServiceSpec(string(m.Data))
	if err != nil {
		return err
	}

	c.mu.Lock()
	c.nextID++
	id := c.nextID
	s := &stream{
		conn:   c,
		id:     id,
		hostID: m.Arg0,
		v2:     v2,
		in:     make(chan []byte, 64),
		done:   make(chan struct{}),
		eofCh:  make(chan struct{}),
		buf:    new(bytes.Buffer),
	}
	c.streams[id] = s
	c.mu.Unlock()

	// OKAY(local-id, remote-id): our stream id first, the host's second. The host
	// resolves this reply by looking up the stream named in arg1, so passing our
	// own id there instead makes it answer with CLSE and abandon the request.
	if err := c.write(Message{Cmd: CmdOKAY, Arg0: s.id, Arg1: s.hostID}); err != nil {
		return err
	}

	cfg.debug("open service=%q arg=%q -> stream id=%d", service, arg, id)
	if cfg.FS == nil {
		cfg.FS = NewVFS()
	}
	tracef("OPEN service=%q arg=%q", service, arg)
	switch service {
	case "shell", "shell,v2", "shell,raw":
		go runShell(cfg, arg, s)
	// "sync", not "sync:" -- the trailing colon is not what adb sends, and guessing it
	// from the documentation rather than from a trace cost a debugging round.
	case "sync", "sync:", "sync:v1", "sync:,version=1":
		go runSync2(cfg, s)
	case "host:version", "host:devices", "host:transport":
		// Answer with a plausible line so a host that probes these sees
		// something sane rather than a hang.
		go func() {
			s.Write([]byte("0029host::version=41\n"))
			s.close(nil)
		}()
	default:
		// Unknown service: close rather than hang, mirroring adbd's rejection.
		go s.close(fmt.Errorf("mockadbd: unknown service %q", service))
	}
	return nil
}

func (c *conn) deliver(id uint32, data []byte) {
	c.mu.Lock()
	s := c.streams[id]
	c.mu.Unlock()
	if s == nil {
		return
	}
	// An empty WRTE means the host closed its side of the stream.
	if len(data) == 0 {
		s.setEOF()
		return
	}
	if !s.v2 {
		s.in <- data
		return
	}
	// Under shell v2 the host frames stdin exactly as it frames output, so the
	// header must be decoded and only the payload handed to the command.
	// Accumulate across packets, because one frame can span several WRTE packets.
	if len(s.partial)+len(data) > maxPayload+v2HeaderSize {
		s.partial = nil // desynchronised; drop the buffer rather than grow it
	}
	s.partial = append(s.partial, data...)

	// One WRTE can carry several frames: the host routinely packs the final stdin
	// chunk together with kIdCloseStdin. Decoding a single frame per packet leaves
	// the rest buffered, and a command reading stdin then never observes EOF and
	// blocks until the client is killed. Drain every complete frame instead.
	for {
		payload, frameID, n, ok := decodeV2Frame(s.partial)
		if !ok {
			return // incomplete: the remainder arrives in a later packet
		}
		s.partial = s.partial[n:]
		if len(s.partial) == 0 {
			s.partial = nil
		}
		switch frameID {
		case v2Stdin:
			tracef("stdin frame id=%d len=%d", frameID, len(payload))
			if len(payload) > 0 {
				s.in <- payload
			}
			// Top the stdin window back up as data is consumed.
			//
			// Flow control has to be acknowledged in step: a window granted once up
			// front is not what the peer expects, and in this mock it made adb stop
			// sending stdin entirely. Replenishing per frame is both closer to a real
			// adbd and, unlike the up-front grant, does not confuse the client.
			if len(payload) > 0 {
				grant := make([]byte, 4)
				binary.LittleEndian.PutUint32(grant, mockStdinWindow)
				_ = s.writeFrame(v2WindowSizeChg, grant)
			}
		case v2CloseStdin:
			// The host signals end of stdin with this frame, not an empty WRTE.
			tracef("closeStdin id=%d len=%d", frameID, len(payload))
			s.setEOF()
			return
		case v2WindowSizeChg:
			// Advisory only: the mock has no PTY to resize.
		}
	}
}

// decodeV2Frame parses a shell v2 frame. ok is false when more bytes are needed.
// n is the number of bytes consumed, so the caller can keep any trailing frame.
func decodeV2Frame(data []byte) (payload []byte, id byte, n int, ok bool) {
	if len(data) < v2HeaderSize {
		return nil, 0, 0, false
	}
	length := int(binary.LittleEndian.Uint32(data[1:v2HeaderSize]))
	if length < 0 || length > maxPayload {
		// A nonsensical length means desynchronisation. Report it as unusable so
		// the caller stops accumulating rather than growing without bound.
		return nil, 0, len(data), true
	}
	if len(data) < v2HeaderSize+length {
		return nil, 0, 0, false
	}
	return data[v2HeaderSize : v2HeaderSize+length], data[0], v2HeaderSize + length, true
}

func (c *conn) lookup(id uint32) *stream {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.streams[id]
}

func (c *conn) take(id uint32) *stream {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.streams[id]
	delete(c.streams, id)
	return s
}

func (c *conn) closeAll(cause error) {
	c.mu.Lock()
	streams := c.streams
	c.streams = make(map[uint32]*stream)
	c.mu.Unlock()
	for _, s := range streams {
		s.close(cause)
	}
}

func (c *conn) write(m Message) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	err := writeMessage(c.w, m, c.version)
	if debugWrites != nil {
		debugWrites("send %s arg0=%d arg1=%d len=%d %s err=%v",
			cmdName(m.Cmd), m.Arg0, m.Arg1, len(m.Data), shortData(m.Data), err)
	}
	return err
}

// debugWrites traces outbound packets when set, which is how a mock that receives
// correctly but replies wrongly gets diagnosed.
var debugWrites func(format string, args ...any)

// stream is one adbd service stream.
type stream struct {
	conn *conn
	// id is the stream id we assigned; hostID is the one the host assigned in
	// its OPEN. Every packet we send addresses the host's id in arg0 and ours in
	// arg1, because arg0 is the destination and arg1 the source in ADB.
	id     uint32
	hostID uint32
	// v2 records that the host requested shell,v2. The v2 protocol frames every
	// byte of output and reports the exit status as a leading ID byte, so raw
	// bytes are simply ignored by such a host.
	v2 bool

	in   chan []byte
	done chan struct{}
	// eofCh fires when the host closes the input side, so a blocked reader such as
	// "cat" terminates instead of waiting forever.
	eofCh chan struct{}
	// partial holds an incomplete shell v2 frame. A frame can be split across
	// several WRTE packets, and discarding the remainder loses stdin silently.
	partial []byte
	bufMu   sync.Mutex
	buf     *bytes.Buffer
	eof     bool
	closed  sync.Once
	err     error
}

func (s *stream) Read(p []byte) (int, error) {
	for {
		// Order matters here, twice over.
		//
		// First, buffered bytes and queued chunks must both be drained before any
		// termination signal is honoured. A select over the data channel and a
		// closed channel picks uniformly at random among ready cases, so once the
		// host closes stdin, delivered data is lost whenever the closed case wins.
		// The symptom is a command that silently sees none of its input.
		//
		// Second, the queued-chunk check must come before the end-of-input check,
		// for the same reason: chunks sit in the channel, not in the buffer, until
		// they are moved across.
		s.bufMu.Lock()
		if s.buf.Len() > 0 {
			n, _ := s.buf.Read(p)
			s.bufMu.Unlock()
			return n, nil
		}
		s.bufMu.Unlock()

		select {
		case chunk := <-s.in:
			s.bufMu.Lock()
			s.buf.Write(chunk)
			s.bufMu.Unlock()
			continue
		default:
		}

		s.bufMu.Lock()
		eof := s.eof
		s.bufMu.Unlock()
		if eof {
			return 0, io.EOF
		}

		select {
		case chunk := <-s.in:
			s.bufMu.Lock()
			s.buf.Write(chunk)
			s.bufMu.Unlock()
		case <-s.eofCh:
			// Loop back so anything queued is drained before EOF is reported.
		case <-s.done:
			// The peer closed the stream, which also ends input.
		}
	}
}

func (s *stream) Write(p []byte) (int, error) {
	if err := s.writeFrame(v2Stdout, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Frame identifiers from AOSP shell_protocol.h, ShellProtocol::Id. They are
// unscoped and non-contiguous — stdin is 0, stdout is 1, exit is 3 — so deriving
// them by incrementing is wrong. Getting them wrong yields a shell that connects,
// accepts bytes, and produces nothing at all.
const (
	v2Stdin         byte = 0
	v2Stdout        byte = 1
	v2Stderr        byte = 2
	v2Exit          byte = 3
	v2CloseStdin    byte = 4
	v2WindowSizeChg byte = 5

	// mockStdinWindow is the amount of stdin the mock grants the host at once. Large
	// enough that no test has to care about windowing, small enough to be a real number
	// rather than an obvious "unlimited" sentinel.
	mockStdinWindow uint32 = 256 * 1024
)

// v2HeaderSize is 1 byte identifier plus a 4-byte length (AOSP
// ShellProtocol::kHeaderSize).
const v2HeaderSize = 5

// writeFrame sends one chunk.
//
// Under shell v2 every chunk carries a 5-byte header: a one byte identifier
// followed by a 4-byte little-endian payload length. The length field is
// mandatory. A frame with only an identifier byte makes the host wait forever
// for a payload that never arrives, which presents as a shell that connects,
// produces no output, and never exits.
//
// Under the original protocol there is no framing and bytes are sent as they are.
func (s *stream) writeFrame(id byte, p []byte) error {
	payload := p
	if s.v2 {
		payload = make([]byte, v2HeaderSize+len(p))
		payload[0] = id
		binary.LittleEndian.PutUint32(payload[1:v2HeaderSize], uint32(len(p)))
		copy(payload[v2HeaderSize:], p)
	}
	return s.writeChunked(payload)
}

// writeChunked sends payload as a sequence of WRTE packets no larger than maxPayload.
func (s *stream) writeChunked(payload []byte) error {
	const chunk = maxPayload - 16
	if len(payload) <= chunk {
		return s.conn.write(Message{Cmd: CmdWRTE, Arg0: s.id, Arg1: s.hostID, Data: payload})
	}
	for off := 0; off < len(payload); off += chunk {
		end := off + chunk
		if end > len(payload) {
			end = len(payload)
		}
		if err := s.conn.write(Message{Cmd: CmdWRTE, Arg0: s.id, Arg1: s.hostID, Data: payload[off:end]}); err != nil {
			return err
		}
	}
	return nil
}

// setEOF marks the input side closed and wakes any reader waiting on it.
// A separate method because the host closes stdin with an empty WRTE and, in the
// v2 protocol, with an explicit kIdCloseStdin frame; both must unblock a command
// that is reading, and a command that is never unblocked is an indefinite hang.
func (s *stream) setEOF() {
	s.bufMu.Lock()
	if s.eof {
		s.bufMu.Unlock()
		return
	}
	s.eof = true
	s.bufMu.Unlock()
	select {
	case <-s.eofCh:
	default:
		close(s.eofCh)
	}
	// No packet is sent to the host here. EOF on stdin is a local condition for
	// the command; echoing it as an empty WRTE would instead look like the device
	// sending an empty chunk to the host.
}

func (s *stream) close(cause error) {
	s.closed.Do(func() {
		if cause != nil {
			s.err = cause
		}
		close(s.done)
		_ = s.conn.write(Message{Cmd: CmdCLSE, Arg0: s.id, Arg1: s.hostID})
		s.conn.mu.Lock()
		delete(s.conn.streams, s.id)
		s.conn.mu.Unlock()
	})
}

// runShell executes a shell service request. Real adbd spawns /system/bin/sh;
// the mock interprets a few commands so tests can assert on observable behaviour
// rather than only on transport framing.
func runShell(cfg Config, arg string, s *stream) {
	argv := splitArgv(arg)

	pr, pw := io.Pipe()
	go func() {
		_, _ = io.Copy(pw, s)
		_ = pw.Close()
	}()

	var out strings.Builder
	code := cfg.Shell(argv, pr, &out, &out)
	if out.Len() > 0 {
		_ = s.writeFrame(v2Stdout, []byte(out.String()))
	}
	// The exit status only exists in the v2 protocol. Under the original shell
	// protocol the host infers success from CLSE, so sending an exit frame there
	// would put a stray byte on the client's stdout.
	if s.v2 {
		_ = s.writeFrame(v2Exit, []byte{byte(code)})
	}
	s.close(nil)
}

// defaultShell answers a small, fixed command set.
func defaultShell(argv []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(argv) == 0 {
		fmt.Fprintln(stderr, "mockadbd: empty command")
		return 1
	}
	switch argv[0] {
	case "echo":
		fmt.Fprintln(stdout, strings.Join(argv[1:], " "))
	case "get-state":
		fmt.Fprintln(stdout, "device")
	case "pwd":
		fmt.Fprintln(stdout, "/")
	case "whoami":
		fmt.Fprintln(stdout, "shell")
	case "cat":
		data, err := io.ReadAll(stdin)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		stdout.Write(data)
	case "exit":
		return 0
	case "true":
		return 0
	case "false", "fail":
		return 1
	default:
		// A real shell reports "command not found" with status 127. Matching that
		// lets tests assert on failure without special-casing the mock.
		fmt.Fprintf(stderr, "mockadbd: %s: command not found\n", argv[0])
		return 127
	}
	return 0
}

// parseServiceSpec splits an OPEN payload into a bare service type and its
// argument.
//
// The wire format is "service[,key=value...]:argument". The options matter: a
// modern host asks for "shell,v2,TERM=xterm-256color,raw", so splitting on the
// comma is not optional. Getting this wrong means every shell request looks like
// an unknown service and the device appears to accept connections but never
// answers, which is exactly the failure this avoids.
func parseServiceSpec(raw string) (service, arg string, v2 bool, err error) {
	spec := strings.TrimRight(raw, "\x00")
	colon := strings.IndexByte(spec, ':')
	if colon < 0 {
		return "", "", false, fmt.Errorf("mockadbd: malformed service spec %q", raw)
	}
	head, arg := spec[:colon], spec[colon+1:]
	opts := ""
	if comma := strings.IndexByte(head, ','); comma >= 0 {
		opts, head = head[comma+1:], head[:comma]
	}
	if head == "" {
		return "", "", false, fmt.Errorf("mockadbd: empty service in %q", raw)
	}
	// The bare service type must be the first option, e.g. "shell,v2,TERM=...".
	for _, opt := range strings.Split(opts, ",") {
		if opt == "v2" {
			v2 = true
		}
	}
	return head, arg, v2, nil
}

// splitArgv parses the quoting in a shell service argument. adbd passes the
// command as a single string that the device's shell then parses.
func splitArgv(s string) []string {
	var out []string
	var cur strings.Builder
	inWord := false
	var quote byte
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case quote != 0:
			if ch == quote {
				quote = 0
			} else {
				cur.WriteByte(ch)
			}
		case ch == '\'' || ch == '"':
			quote = ch
			inWord = true
		case ch == ' ' || ch == '\t':
			if inWord {
				out = append(out, cur.String())
				cur.Reset()
				inWord = false
			}
		default:
			cur.WriteByte(ch)
			inWord = true
		}
	}
	if inWord {
		out = append(out, cur.String())
	}
	return out
}

// readMessage reads one packet, validating the magic and the payload CRC.
func readMessage(r io.Reader) (Message, error) {
	var hdr [headerLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Message{}, err
	}
	m := Message{
		Cmd:  binary.LittleEndian.Uint32(hdr[0:4]),
		Arg0: binary.LittleEndian.Uint32(hdr[4:8]),
		Arg1: binary.LittleEndian.Uint32(hdr[8:12]),
	}
	length := binary.LittleEndian.Uint32(hdr[12:16])
	m.DataCheck = binary.LittleEndian.Uint32(hdr[16:20])
	gotMagic := binary.LittleEndian.Uint32(hdr[20:24])

	// The magic field is derived from the command word, so a mismatch means the
	// stream is desynchronised: resynchronising on the magic is what a real adbd
	// does, and it is what recovers a relay from a truncated packet.
	if !validMagic(m.Cmd, gotMagic) {
		return Message{}, fmt.Errorf("mockadbd: magic 0x%08x does not match command %s",
			gotMagic, cmdName(m.Cmd))
	}
	if length > maxPayload {
		return Message{}, fmt.Errorf("mockadbd: payload length %d exceeds cap %d", length, maxPayload)
	}
	if length > 0 {
		m.Data = make([]byte, length)
		if _, err := io.ReadFull(r, m.Data); err != nil {
			return Message{}, err
		}
	}
	return m, nil
}

// verifyPayload checks a payload once the connection has negotiated a version.
// The CNXN handshake itself predates negotiation, so it is validated separately.
func verifyPayload(version uint32, m Message) error {
	if !payloadIntact(m.Data, version, m.DataCheck) {
		return fmt.Errorf("mockadbd: payload integrity check failed for %s", cmdName(m.Cmd))
	}
	return nil
}

func writeMessage(w io.Writer, m Message, version uint32) error {
	if len(m.Data) > maxPayload {
		return fmt.Errorf("mockadbd: payload length %d exceeds cap %d", len(m.Data), maxPayload)
	}
	hdr := make([]byte, headerLen)
	binary.LittleEndian.PutUint32(hdr[0:4], m.Cmd)
	binary.LittleEndian.PutUint32(hdr[4:8], m.Arg0)
	binary.LittleEndian.PutUint32(hdr[8:12], m.Arg1)
	binary.LittleEndian.PutUint32(hdr[12:16], uint32(len(m.Data)))
	binary.LittleEndian.PutUint32(hdr[16:20], dataCheckFor(m.Data, version))
	binary.LittleEndian.PutUint32(hdr[20:24], magicFor(m.Cmd))
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	if len(m.Data) > 0 {
		if _, err := w.Write(m.Data); err != nil {
			return err
		}
	}
	return nil
}

// tracef writes a diagnostic line when MOCKADBD_TRACE names a file.
//
// This exists because a hang has no other evidence: the symptom is that nothing happens,
// so without a record of which frames actually arrived the only honest options are to
// guess or to add tracing. Gate it behind an environment variable so it costs nothing
// when nobody is debugging.
func tracef(format string, args ...any) {
	path := os.Getenv("MOCKADBD_TRACE")
	if path == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s %s\n", time.Now().Format("15:04:05.000"), fmt.Sprintf(format, args...))
}
