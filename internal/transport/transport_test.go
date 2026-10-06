package transport

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/vitkuz573/ard/internal/hs"
)

// pair returns two Sessions on opposite ends of one connection, which is what a gateway and
// an agent have.
func pair(t *testing.T) (a, b *Session) {
	t.Helper()
	c1, c2 := net.Pipe()
	t.Cleanup(func() { _ = c1.Close(); _ = c2.Close() })

	type made struct {
		s   *Session
		err error
	}
	// Both ends are constructed concurrently: yamux writes its header as it starts, and a
	// pipe is unbuffered, so building them one after the other would wait forever.
	done := make(chan made, 2)
	go func() {
		s, err := New(c1, "dev-1", "device", "shell_v2,cmd", Acceptor)
		done <- made{s, err}
	}()
	go func() {
		s, err := New(c2, "dev-1", "device", "shell_v2,cmd", Dialer)
		done <- made{s, err}
	}()
	first, second := <-done, <-done
	if first.err != nil || second.err != nil {
		t.Fatalf("building the session pair: %v, %v", first.err, second.err)
	}
	return first.s, second.s
}

// accepted is one stream as the accepting end classified it.
type accepted struct {
	kind    string
	service string
	payload []byte
}

// serve accepts on one end until both expected streams have arrived, and reports how each was
// classified along with the payload that followed it.
//
// Both classifications are checked on one session, because the thing being tested is that the
// two are told apart: a device's own service name and a gateway's route header arrive on the
// same session and differ only in their first bytes.
func serve(t *testing.T, s *Session, want int) []accepted {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	got := make(chan accepted, want)
	go func() {
		_ = s.Accept(ctx,
			func(route hs.Route, conn net.Conn) error {
				return readAccepted(got, accepted{kind: route.Kind}, conn)
			},
			func(service string, conn net.Conn) error {
				return readAccepted(got, accepted{service: service}, conn)
			})
	}()

	out := make([]accepted, 0, want)
	for len(out) < want {
		select {
		case a := <-got:
			out = append(out, a)
		case <-ctx.Done():
			t.Fatalf("only %d of %d streams were classified", len(out), want)
		}
	}
	return out
}

// readAccepted takes whatever the stream carries after its header. One read rather than a
// full-length one: a stream that has more to say later is not the subject here, and waiting
// for bytes that may never come would turn a classification failure into a timeout.
func readAccepted(out chan<- accepted, a accepted, conn net.Conn) error {
	defer conn.Close()
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if n > 0 {
		a.payload = buf[:n]
	}
	out <- a
	return err
}

// A stream the gateway opened carries a route header; a stream the device opened carries a
// bare service name. Both reach the same Accept, and each has to reach its own handler with
// the bytes that followed the header intact -- the prefix taken to classify a stream belongs
// to nobody unless the reader it was buffered by stays in front of the socket.
func TestAcceptTellsARouteFromADeviceServiceAndKeepsBothPayloads(t *testing.T) {
	accepting, opening := pair(t)
	ctx := context.Background()

	// The routed stream is opened by the peer: a stream arrives at the end that did not
	// open it.
	gatewaySide, err := opening.Open(ctx, hs.KindADB, "st-1", nil)
	if err != nil {
		t.Fatalf("open a routed stream: %v", err)
	}
	if _, err := gatewaySide.Write([]byte("routed payload")); err != nil {
		t.Fatalf("write the routed payload: %v", err)
	}

	// The device's own request is a bare NUL-terminated name on a stream it opened itself.
	// Going through Open would put a route header onto it, which is the very thing being
	// told apart, so the mux stream is reserved directly and the name written onto it.
	deviceStream, err := opening.mux.OpenStream()
	if err != nil {
		t.Fatalf("open a device stream: %v", err)
	}
	if err := deviceStream.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set the deadline: %v", err)
	}
	if _, err := deviceStream.Write(append([]byte("tcp:9911"), 0)); err != nil {
		t.Fatalf("write the service name: %v", err)
	}
	if _, err := deviceStream.Write([]byte("device payload")); err != nil {
		t.Fatalf("write the device payload: %v", err)
	}

	got := serve(t, accepting, 2)
	byKind := map[string]accepted{}
	for _, a := range got {
		switch {
		case a.kind != "":
			byKind[a.kind] = a
		case a.service != "":
			byKind["service:"+a.service] = a
		default:
			t.Errorf("a stream arrived classified as neither a route nor a service: %+v", a)
		}
	}

	routed, ok := byKind[hs.KindADB]
	if !ok {
		t.Fatalf("the routed stream was not delivered as a route; got %+v", got)
	}
	if !bytes.Equal(routed.payload, []byte("routed payload")) {
		t.Errorf("the routed stream carried %q, want %q", routed.payload, "routed payload")
	}

	dev, ok := byKind["service:tcp:9911"]
	if !ok {
		t.Fatalf("the device's own stream was not delivered as a service; got %+v", got)
	}
	if !bytes.Equal(dev.payload, []byte("device payload")) {
		t.Errorf("the device's stream carried %q, want %q", dev.payload, "device payload")
	}
}

// A device open travels upstream as a named route rather than as a bare service name, because
// the gateway that receives it owns the ports and the policy. The name has to arrive as
// metadata, intact, or the gateway does not know which port the bytes are for.
func TestDeviceOpenCarriesItsServiceAsRouteMetadata(t *testing.T) {
	accepting, opening := pair(t)

	// What the agent sends: a routed stream whose metadata names the service.
	upstream, err := opening.Open(context.Background(), hs.KindDeviceOpen, "st-9",
		[]byte(`{"service":"tcp:9911"}`))
	if err != nil {
		t.Fatalf("open the relayed stream: %v", err)
	}
	if _, err := upstream.Write([]byte("relayed")); err != nil {
		t.Fatalf("write through the relayed stream: %v", err)
	}

	got := serve(t, accepting, 1)
	if len(got) != 1 || got[0].kind != hs.KindDeviceOpen {
		t.Fatalf("the relayed ask was not delivered as a device open; got %+v", got)
	}
	if !bytes.Equal(got[0].payload, []byte("relayed")) {
		t.Errorf("the relayed ask carried %q, want %q", got[0].payload, "relayed")
	}
	_ = upstream.Close()
}
