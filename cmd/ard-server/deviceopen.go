package main

// A stream a device opened for itself, relayed to the gateway.
//
// A device needs one of these when a reverse forward is in play: the forward binds a port on
// the device, and whatever connects to that port has to land on a port on this gateway. The
// device cannot ask the gateway directly -- the gateway opens streams in response to an
// operator, and a device that could open one would be able to reach any operator's device --
// so it asks the agent, and the agent relays the ask.
//
// The relay is a splice of two streams and nothing more. The service name travels as the
// route's metadata and the bytes after it travel as the stream's payload, which is the same
// arrangement every other stream here uses.

import (
	"context"
	"encoding/json"
	"fmt"
	"net"

	"github.com/vitkuz573/ard/internal/hs"
	"github.com/vitkuz573/ard/internal/transport"
)

// relayDeviceOpen carries a device's own stream request to the gateway as a named stream.
func relayDeviceOpen(ctx context.Context, to *transport.Session, device, service string, stream net.Conn) error {
	meta, err := json.Marshal(hs.DeviceOpen{Service: service})
	if err != nil {
		_ = stream.Close()
		return err
	}
	upstream, err := to.Open(ctx, hs.KindDeviceOpen, newStreamID(), json.RawMessage(meta))
	if err != nil {
		_ = stream.Close()
		return fmt.Errorf("relay %s for device %s: %w", service, device, err)
	}
	defer upstream.Close()
	relay(&namedStream{Conn: upstream, name: device}, stream)
	return nil
}

// namedStream is a stream with a name in its log lines.
//
// Without one, a stream that misbehaves is identified by a pointer, and the one thing an
// operator has to correlate is which device it belonged to.
type namedStream struct {
	net.Conn
	name string
}

func (n namedStream) String() string { return "stream to " + n.name }
