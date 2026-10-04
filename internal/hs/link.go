package hs

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

// Link is the gateway side of the inner multiplexer that sits on top of a single
// adbd connection. See the comment above writeFrame for why that connection is
// held open for the whole session rather than opened per stream.
//
// Lifecycle: NewLink starts a read loop. The loop terminates on read error or
// Close, and every open stream is closed with the link's error, so no stream can
// be left waiting forever on a dead link.
type Link struct {
	r io.Reader
	w io.Writer

	writeMu sync.Mutex

	mu        sync.Mutex
	streams   map[string]*Stream
	opens     chan openFrame
	closed    chan struct{}
	err       error
	finishOnce sync.Once
}

// Stream is one multiplexed byte pipe. Inbound data arrives on Data; Write sends
// upstream. A Stream belongs to exactly one operator session and is never shared.
type Stream struct {
	id     string
	kind   string
	link   *Link
	data   chan []byte
	done   chan struct{}
	endMu  sync.Mutex
	endErr error
}

// NewLink starts multiplexing over an established adbd connection.
func NewLink(rw io.ReadWriter) *Link {
	l := &Link{
		r:       rw,
		w:       rw,
		streams: make(map[string]*Stream),
		opens:   make(chan openFrame, 16),
		closed:  make(chan struct{}),
	}
	go l.readLoop()
	return l
}

// Open creates a local stream and announces it to the device.
func (l *Link) Open(streamID, kind string, meta json.RawMessage) (*Stream, error) {
	body, err := json.Marshal(openFrame{Stream: streamID, Kind: kind, Meta: meta})
	if err != nil {
		return nil, fmt.Errorf("hs: encode open: %w", err)
	}
	if err := l.write(frameOpen, body); err != nil {
		return nil, fmt.Errorf("hs: send open: %w", err)
	}
	s := newStream(l, streamID, kind)
	l.mu.Lock()
	if _, dup := l.streams[streamID]; dup {
		l.mu.Unlock()
		return nil, fmt.Errorf("hs: stream %q already open", streamID)
	}
	l.streams[streamID] = s
	l.mu.Unlock()
	return s, nil
}

// AcceptStream blocks until the device opens a stream.
func (l *Link) AcceptStream() (*Stream, error) {
	select {
	case f := <-l.opens:
		s := newStream(l, f.Stream, f.Kind)
		l.mu.Lock()
		l.streams[f.Stream] = s
		l.mu.Unlock()
		return s, nil
	case <-l.closed:
		return nil, l.Err()
	}
}

// Err reports why the link stopped, or nil if it is healthy.
func (l *Link) Err() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.err
}

// Closed is closed when the link terminates.
func (l *Link) Closed() <-chan struct{} { return l.closed }

// Close shuts the link down and ends every open stream.
func (l *Link) Close() {
	l.finish(io.EOF)
}

// finish terminates the link exactly once. Both Close and the read loop can reach
// it, typically at the same moment when a device drops mid-traffic, so the guard
// has to live here rather than on Close.
func (l *Link) finish(err error) {
	l.finishOnce.Do(func() {
		l.mu.Lock()
		if l.err == nil {
			l.err = err
		}
		final := l.err
		streams := make([]*Stream, 0, len(l.streams))
		for _, s := range l.streams {
			streams = append(streams, s)
		}
		l.streams = map[string]*Stream{}
		l.mu.Unlock()

		for _, s := range streams {
			s.end(final)
		}
		close(l.closed)
	})
}

func (l *Link) write(typ byte, payload []byte) error {
	l.writeMu.Lock()
	defer l.writeMu.Unlock()
	return writeFrame(l.w, typ, payload)
}

func (l *Link) readLoop() {
	for {
		typ, payload, err := readFrame(l.r)
		if err != nil {
			if errors.Is(err, io.EOF) {
				err = io.ErrUnexpectedEOF
			}
			l.finish(err)
			return
		}
		if err := l.dispatch(typ, payload); err != nil {
			l.finish(err)
			return
		}
	}
}

func (l *Link) dispatch(typ byte, payload []byte) error {
	switch typ {
	case frameOpen:
		var f openFrame
		if err := json.Unmarshal(payload, &f); err != nil {
			return fmt.Errorf("hs: decode open: %w", err)
		}
		select {
		case l.opens <- f:
		case <-l.closed:
			return io.ErrClosedPipe
		case <-time.After(openBackpressure):
			// Refusing is correct here: an unclaimed stream would otherwise be
			// silently dropped while the device believes it is live.
			return fmt.Errorf("hs: device opened stream %q that nobody claimed", f.Stream)
		}
	case frameData:
		if len(payload) == 0 {
			return errors.New("hs: empty data frame")
		}
		sid, data, err := decodeData(payload)
		if err != nil {
			return err
		}
		s := l.lookup(sid)
		if s == nil {
			return nil // stream already closed locally; drop silently
		}
		select {
		case s.data <- data:
		case <-s.done:
		case <-time.After(dataBackpressure):
			return fmt.Errorf("hs: stream %q is not draining", sid)
		}
	case frameClose:
		if len(payload) == 0 {
			return nil
		}
		var ref struct {
			Stream string `json:"s"`
		}
		if err := json.Unmarshal(payload, &ref); err != nil {
			return fmt.Errorf("hs: decode close: %w", err)
		}
		if s := l.lookup(ref.Stream); s != nil {
			s.end(io.EOF)
		}
	default:
		return fmt.Errorf("hs: unknown frame type 0x%02x", typ)
	}
	return nil
}

func (l *Link) lookup(id string) *Stream {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.streams[id]
}

func (l *Link) remove(id string) {
	l.mu.Lock()
	delete(l.streams, id)
	l.mu.Unlock()
}

func newStream(l *Link, id, kind string) *Stream {
	return &Stream{
		id:   id,
		kind: kind,
		link: l,
		data: make(chan []byte, 64),
		done: make(chan struct{}),
	}
}

// ID returns the stream identifier, for audit correlation.
func (s *Stream) ID() string { return s.id }

// Kind returns the stream kind.
func (s *Stream) Kind() string { return s.kind }

// Read yields the next inbound chunk, or io.EOF when the device closes the stream.
func (s *Stream) Read() ([]byte, error) {
	select {
	case chunk := <-s.data:
		return chunk, nil
	case <-s.done:
		s.endMu.Lock()
		defer s.endMu.Unlock()
		if s.endErr != nil && !errors.Is(s.endErr, io.EOF) {
			return nil, s.endErr
		}
		// Drain anything already buffered before reporting EOF.
		select {
		case chunk := <-s.data:
			return chunk, nil
		default:
			return nil, io.EOF
		}
	}
}

// Write sends a chunk upstream to the device.
func (s *Stream) Write(p []byte) (int, error) {
	body, err := encodeData(s.id, p)
	if err != nil {
		return 0, err
	}
	if err := s.link.write(frameData, body); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close ends the stream on both sides.
func (s *Stream) Close() error {
	s.end(io.EOF)
	s.link.remove(s.id)
	body, err := json.Marshal(struct {
		Stream string `json:"s"`
	}{s.id})
	if err != nil {
		return err
	}
	return s.link.write(frameClose, body)
}

// Done is closed when the stream terminates.
func (s *Stream) Done() <-chan struct{} { return s.done }

func (s *Stream) end(err error) {
	s.endMu.Lock()
	if s.endErr == nil {
		s.endErr = err
	}
	s.endMu.Unlock()
	select {
	case <-s.done:
	default:
		close(s.done)
	}
}

// dataHeader is the JSON prefix on a data frame carrying the target stream id.
// Encoding the id in the frame rather than a fixed header keeps the frame format
// self-describing, which matters because both ends are versioned independently
// during a rolling upgrade.
func encodeData(id string, payload []byte) ([]byte, error) {
	prefix, err := json.Marshal(struct {
		S string `json:"s"`
	}{id})
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(prefix)+1+len(payload))
	out = append(out, prefix...)
	out = append(out, ' ') // separator; payload is arbitrary bytes and may not be JSON
	out = append(out, payload...)
	return out, nil
}

func decodeData(payload []byte) (string, []byte, error) {
	i := indexByte(payload, ' ')
	if i < 0 {
		return "", nil, errors.New("hs: data frame without separator")
	}
	var ref struct {
		S string `json:"s"`
	}
	if err := json.Unmarshal(payload[:i], &ref); err != nil {
		return "", nil, fmt.Errorf("hs: decode data header: %w", err)
	}
	if ref.S == "" {
		return "", nil, errors.New("hs: data frame without stream id")
	}
	return ref.S, payload[i+1:], nil
}

func indexByte(b []byte, c byte) int {
	for i := range b {
		if b[i] == c {
			return i
		}
	}
	return -1
}

// Backpressure bounds. A slow consumer must not grow memory without limit, and a
// device that opens streams nobody claims must be told, not ignored.
const (
	openBackpressure = 30 * time.Second
	dataBackpressure = 60 * time.Second
)
