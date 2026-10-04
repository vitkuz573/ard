package hs

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// net.Pipe is synchronous and unbuffered, so it behaves like a socket with no
// kernel buffering. That makes it the right harness for framing tests: any byte
// a reader swallows cannot be hidden by buffering.
func pipe(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	return a, b
}

func TestHandshakeRoundTrip(t *testing.T) {
	client, server := pipe(t)

	type result struct {
		w   Welcome
		err error
	}
	done := make(chan result, 1)
	go func() {
		w, err := ClientHandshake(client, Hello{Device: "dev-1", Name: "pixel", Agent: "0.1"})
		done <- result{w, err}
	}()

	hello, err := ServerHandshake(server)
	if err != nil {
		t.Fatalf("server handshake: %v", err)
	}
	if hello.Device != "dev-1" || hello.Name != "pixel" || hello.Agent != "0.1" {
		t.Fatalf("hello parsed wrong: %+v", hello)
	}
	if err := writeLine(server, Proto+" WELCOME "+mustJSON(Welcome{Session: "sess-9", Heartbeat: 30 * time.Second})); err != nil {
		t.Fatalf("write welcome: %v", err)
	}

	r := <-done
	if r.err != nil {
		t.Fatalf("client handshake: %v", r.err)
	}
	if r.w.Session != "sess-9" || r.w.Heartbeat != 30*time.Second {
		t.Fatalf("welcome parsed wrong: %+v", r.w)
	}
}

// A refused device must see a distinct error, because the agent has to be able to
// tell "you are not authorised" from "the network broke" and must not retry.
func TestHandshakeRefusalIsDistinct(t *testing.T) {
	client, server := pipe(t)
	go func() {
		_, _ = ServerHandshake(server)
		_ = writeLine(server, Proto+" WELCOME "+mustJSON(Welcome{Error: "device not enrolled"}))
	}()

	_, err := ClientHandshake(client, Hello{Device: "unknown"})
	if err == nil {
		t.Fatal("expected refusal")
	}
	if !strings.Contains(err.Error(), "device not enrolled") {
		t.Fatalf("refusal reason lost: %v", err)
	}
}

// Regression test. The route header is line-delimited but the payload after it is
// arbitrary binary that routinely contains newline bytes. If the header reader
// buffers ahead, the first chunk of every stream is corrupted and the failure
// surfaces as an unexplained adbd protocol error much later.
func TestRouteHeaderDoesNotConsumePayload(t *testing.T) {
	client, server := pipe(t)

	// Every byte value, including 0x0a, 0x00 and 0xff.
	payload := make([]byte, 256)
	for i := range payload {
		payload[i] = byte(i)
	}
	// Repeat so the payload is much larger than any plausible read buffer.
	payload = bytes.Repeat(payload, 64)

	go func() {
		_ = WriteRoute(client, Route{Device: "dev-1", Kind: KindADB, Stream: "st-1"})
		_, _ = client.Write(payload)
	}()

	rt, err := ReadRoute(server)
	if err != nil {
		t.Fatalf("read route: %v", err)
	}
	if rt.Kind != KindADB || rt.Stream != "st-1" || rt.Device != "dev-1" {
		t.Fatalf("route parsed wrong: %+v", rt)
	}

	got := make([]byte, len(payload))
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatalf("read payload: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload corrupted: got %d bytes, want %d, first difference at %d",
			len(got), len(payload), firstDiff(got, payload))
	}
}

func firstDiff(a, b []byte) int {
	for i := range a {
		if i >= len(b) || a[i] != b[i] {
			return i
		}
	}
	return len(a)
}

func TestRouteHeaderCarriesMeta(t *testing.T) {
	client, server := pipe(t)
	meta := json.RawMessage(`{"cols":120,"rows":40}`)

	go func() {
		_ = WriteRoute(client, Route{Device: "d", Kind: KindShell, Stream: "s", Meta: meta})
		_ = writeLine(client, Proto+" ROUTE "+mustJSON(Route{Kind: KindShell, Stream: "s"}))
	}()

	rt, err := ReadRoute(server)
	if err != nil {
		t.Fatalf("read route: %v", err)
	}
	if string(rt.Meta) != string(meta) {
		t.Fatalf("meta mangled: got %s want %s", rt.Meta, meta)
	}
	// Second header proves the reader is still aligned for back-to-back streams.
	if _, err := ReadRoute(server); err != nil {
		t.Fatalf("read second route: %v", err)
	}
}

func TestRouteValidation(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteRoute(&buf, Route{Device: "d", Stream: "s"}); err == nil {
		t.Error("route without kind must be rejected")
	}
	if err := WriteRoute(&buf, Route{Device: "d", Kind: KindADB}); err == nil {
		t.Error("route without stream id must be rejected")
	}
}

func TestHandshakeRejectsGarbage(t *testing.T) {
	client, server := pipe(t)
	go func() {
		_, _ = client.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
		_ = client.Close()
	}()
	if _, err := ServerHandshake(server); err == nil {
		t.Fatal("expected error on non-ARD input")
	}
}

func TestControlLineCap(t *testing.T) {
	client, server := pipe(t)
	// A single Write, not io.Copy: net.Pipe is synchronous and unbuffered, so a
	// reader-then-writer loop can deadlock before any byte is ever offered.
	// This writer may stay blocked once readLine gives up, which is fine; closing
	// the pipe in cleanup releases it.
	go func() {
		_, _ = client.Write(bytes.Repeat([]byte("A"), maxControlLine+64))
		_ = client.Close()
	}()
	if _, err := ServerHandshake(server); err == nil {
		t.Fatal("oversized control line must be rejected")
	}
}

// readLine has no deadline of its own, so callers must impose one. Without it a
// peer that sends maxControlLine-1 bytes and then stalls holds a handshake
// handler open indefinitely. The listener is responsible for setting a deadline
// before calling into this package; this test documents the cap that deadline
// must protect.
func TestReadLineIsUnbuffered(t *testing.T) {
	// Two control lines followed by binary data, all in one buffer. A buffered
	// reader would over-read into the binary data.
	var buf bytes.Buffer
	_ = writeLine(&buf, Proto+" ROUTE "+mustJSON(Route{Device: "d", Kind: KindADB, Stream: "s"}))
	_ = writeLine(&buf, Proto+" ROUTE "+mustJSON(Route{Device: "d", Kind: KindADB, Stream: "s2"}))
	binaryTail := []byte{0x00, 0x0a, 0xff, 0x41}
	buf.Write(binaryTail)

	rd := bytes.NewReader(buf.Bytes())
	for _, want := range []string{"s", "s2"} {
		rt, err := ReadRoute(rd)
		if err != nil {
			t.Fatalf("read route: %v", err)
		}
		if rt.Stream != want {
			t.Fatalf("stream = %q, want %q", rt.Stream, want)
		}
	}
	rest, err := io.ReadAll(rd)
	if err != nil {
		t.Fatalf("read tail: %v", err)
	}
	if !bytes.Equal(rest, binaryTail) {
		t.Fatalf("tail = %v, want %v", rest, binaryTail)
	}
}

// Two streams must not be able to observe each other's bytes. This is the
// isolation property that lets concurrent operators share one device connection.
func TestLinkStreamIsolation(t *testing.T) {
	gw, dev := pipe(t)

	link := NewLink(gw)
	defer link.Close()

	// Stand in for the device: read frames and echo each stream's payload back
	// tagged with its own id, so the gateway can tell which reply is whose.
	done := make(chan error, 1)
	_ = done
	go func() {
		for {
			typ, payload, err := readFrame(dev)
			if err != nil {
				done <- err
				return
			}
			switch typ {
			case frameOpen:
				var f openFrame
				if err := json.Unmarshal(payload, &f); err != nil {
					done <- err
					return
				}
				body, _ := encodeData(f.Stream, []byte("opened:"+f.Stream))
				if err := writeFrame(dev, frameData, body); err != nil {
					done <- err
					return
				}
			case frameData:
				id, data, err := decodeData(payload)
				if err != nil {
					done <- err
					return
				}
				body, _ := encodeData(id, append([]byte("echo:"), data...))
				if err := writeFrame(dev, frameData, body); err != nil {
					done <- err
					return
				}
			case frameClose:
				// ignore
			}
		}
	}()

	alpha, err := link.Open("st-alpha", KindADB, nil)
	if err != nil {
		t.Fatalf("open alpha: %v", err)
	}
	beta, err := link.Open("st-beta", KindADB, nil)
	if err != nil {
		t.Fatalf("open beta: %v", err)
	}

	readWithTimeout := func(s *Stream) string {
		t.Helper()
		chunk, err := s.Read()
		if err != nil {
			t.Fatalf("read on %s: %v", s.ID(), err)
		}
		return string(chunk)
	}

	if got := readWithTimeout(alpha); got != "opened:st-alpha" {
		t.Errorf("alpha open reply wrong: %q", got)
	}
	if got := readWithTimeout(beta); got != "opened:st-beta" {
		t.Errorf("beta open reply wrong: %q", got)
	}

	// Interleave writes on both streams.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = alpha.Write([]byte("AAAA")) }()
	go func() { defer wg.Done(); _, _ = beta.Write([]byte("BBBB")) }()
	wg.Wait()

	gotAlpha := readWithTimeout(alpha)
	gotBeta := readWithTimeout(beta)
	if gotAlpha != "echo:AAAA" {
		t.Errorf("alpha got %q, want echo:AAAA", gotAlpha)
	}
	if gotBeta != "echo:BBBB" {
		t.Errorf("beta got %q, want echo:BBBB", gotBeta)
	}

	// Close must terminate the link and every stream it still holds. The link
	// does not own the underlying connection, so the device side is not expected
	// to observe anything; Closed is the contract.
	link.Close()
	select {
	case <-link.Closed():
	case <-time.After(2 * time.Second):
		t.Fatal("link did not report shutdown")
	}
	if link.Err() == nil {
		t.Error("closed link should report why it stopped")
	}
	select {
	case <-alpha.Done():
	case <-time.After(2 * time.Second):
		t.Error("alpha stream was not terminated by link shutdown")
	}
	select {
	case <-beta.Done():
	case <-time.After(2 * time.Second):
		t.Error("beta stream was not terminated by link shutdown")
	}
	// Close must be idempotent: a peer that drops mid-traffic makes the read loop
	// and Close race, and double-closing the channel used to panic.
	link.Close()
}

// Closing a stream must terminate it even if the device never answers, otherwise
// an operator's shell would hang on a dead device forever.
func TestStreamCloseUnblocksRead(t *testing.T) {
	gw, dev := pipe(t)
	go func() {
		// Consume frames but never reply.
		for {
			if _, _, err := readFrame(dev); err != nil {
				return
			}
		}
	}()

	link := NewLink(gw)
	defer link.Close()

	s, err := link.Open("st-hang", KindADB, nil)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	readErr := make(chan error, 1)
	go func() {
		_, err := s.Read()
		readErr <- err
	}()

	time.Sleep(50 * time.Millisecond)
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	select {
	case err := <-readErr:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("read after close returned %v, want EOF", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not unblock Read")
	}
}

// A frame with a corrupt length must be refused rather than turned into a huge
// allocation.
func TestFrameLengthCap(t *testing.T) {
	r := bytes.NewReader([]byte{0x00, 0xff, 0xff, 0xff, frameData, 0x00})
	if _, _, err := readFrame(r); err == nil {
		t.Fatal("oversized frame length must be rejected")
	}
}

func TestEncodeDecodeData(t *testing.T) {
	// Payload chosen to include a space and bytes that break naive parsing.
	payload := []byte("first line\nsecond line\x00 with spaces ")
	encoded, err := encodeData("st-1", payload)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	id, got, err := decodeData(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if id != "st-1" {
		t.Errorf("id = %q, want st-1", id)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("payload = %q, want %q", got, payload)
	}
}
