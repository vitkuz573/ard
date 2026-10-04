// Package registry tracks which devices are connected to the gateway.
//
// Keying is by device UUID, never by connection: a UUID survives reboot,
// reinstall and address change, and the registry is what authorization is checked
// against. A socket is not an identity.
package registry

import (
	"fmt"
	"io"
	"sort"
	"sync"
	"time"
)

// State is a device's presence.
type State string

const (
	// StateOnline means streams may be opened.
	StateOnline State = "online"
	// StateDraining means the device is disconnecting but existing streams are
	// still being served. New streams are refused, which is what makes a graceful
	// shutdown possible instead of cutting live sessions.
	StateDraining State = "draining"
	// StateOffline means no session is present.
	StateOffline State = "offline"
)

// Device is a registry entry.
type Device struct {
	UUID        string    `json:"uuid"`
	Name        string    `json:"name"`
	State       State     `json:"state"`
	Agent       string    `json:"agent"`
	ConnectedAt time.Time `json:"connected_at"`
	LastSeen    time.Time `json:"last_seen"`
	// RemoteAddr is recorded for the audit log. It is not an identifier.
	RemoteAddr string `json:"remote_addr"`
	// LoopbackPort is the local TCP port that represents this device to the stock
	// adb server. It is assigned from the allowlist order rather than from
	// connection order, so a serial stays the same across reconnects and reboots;
	// a port that shifted on every reconnect would invalidate every operator's
	// saved device identifier.
	LoopbackPort int `json:"loopback_port"`
	Streams      int `json:"streams"`
}

// Registry is the gateway's device table.
type Registry struct {
	mu      sync.RWMutex
	devices map[string]*entry
	// allowed is the set of device UUIDs permitted to connect at all. A device not
	// in it is refused during the handshake, so it never becomes present.
	allowed map[string]bool
	// onChange is called after every state transition, for audit and logging.
	onChange func(*Device, string)
	// now is injectable so tests do not depend on wall-clock time.
	now func() time.Time
	// ports maps device UUID to its stable loopback port.
	ports map[string]int
}

type entry struct {
	mu    sync.Mutex
	uuid  string
	name  string
	agent string
	state State
	open  func(streamID, kind string) (io.ReadWriteCloser, error)
	port  int
	conn  func() error
	// streams counts live streams, so the registry can report load and refuse
	// work for a device that is already saturated.
	streams     int
	connectedAt time.Time
	lastSeen    time.Time
	remoteAddr  string
}

// New creates a registry allowing only the given device UUIDs.
//
// An empty allowlist is a configuration error rather than "allow everything":
// defaulting open would turn a missing config file into full access.
func New(allowed []string, basePort int, onChange func(*Device, string)) (*Registry, error) {
	if len(allowed) == 0 {
		return nil, fmt.Errorf("registry: no devices allowed; refusing to start with an empty allowlist")
	}
	if basePort <= 0 || basePort > 60000 {
		return nil, fmt.Errorf("registry: loopback base port %d is out of range", basePort)
	}
	if basePort+len(allowed) > 65535 {
		return nil, fmt.Errorf("registry: %d devices from port %d overflow the port range",
			len(allowed), basePort)
	}
	set := make(map[string]bool, len(allowed))
	ports := make(map[string]int, len(allowed))
	for i, id := range allowed {
		if id == "" {
			return nil, fmt.Errorf("registry: empty device UUID in allowlist")
		}
		if set[id] {
			// Two entries for one device would assign two ports and make the serial
			// ambiguous.
			return nil, fmt.Errorf("registry: device %q appears twice in the allowlist", id)
		}
		set[id] = true
		ports[id] = basePort + i
	}
	return &Registry{
		devices:  map[string]*entry{},
		allowed:  set,
		ports:    ports,
		onChange: onChange,
		now:      time.Now,
	}, nil
}

// LoopbackPort reports the stable local port for a device.
func (r *Registry) LoopbackPort(uuid string) (int, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.ports[uuid]
	return p, ok
}

// Allowed reports whether a device may connect.
func (r *Registry) Allowed(uuid string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.allowed[uuid]
}

// Add registers a connected device. It returns an error if the device is already
// connected, which would mean two agents claiming one identity.
func (r *Registry) Add(uuid, name, agent, remoteAddr string,
	open func(streamID, kind string) (io.ReadWriteCloser, error),
	conn func() error) error {
	if !r.Allowed(uuid) {
		return fmt.Errorf("registry: device %q is not enrolled", uuid)
	}
	r.mu.Lock()
	if _, exists := r.devices[uuid]; exists {
		r.mu.Unlock()
		return fmt.Errorf("registry: device %q is already connected", uuid)
	}
	now := r.now()
	e := &entry{
		uuid: uuid, name: name, agent: agent, state: StateOnline,
		open: open, conn: conn, connectedAt: now, lastSeen: now,
		remoteAddr: remoteAddr,
		// Carry the assigned port onto the entry: the snapshot the gateway serves
		// is built from entries, not from the allowlist, so a device that forgot
		// this would be reported with no port and the proxy would never bind.
		port: r.ports[uuid],
	}
	r.devices[uuid] = e
	r.mu.Unlock()

	r.notify(e, "connected")
	return nil
}

// Remove drops a device and returns its connection closer so the caller can shut
// the socket down.
func (r *Registry) Remove(uuid string) (func() error, *Device) {
	r.mu.Lock()
	e, ok := r.devices[uuid]
	if ok {
		delete(r.devices, uuid)
	}
	r.mu.Unlock()
	if !ok {
		return nil, nil
	}
	dev := snapshot(e)
	r.notifySnapshot(dev, "disconnected")
	return e.conn, dev
}

// Drain marks a device as leaving: existing streams continue, new ones are refused.
func (r *Registry) Drain(uuid string) {
	r.mu.RLock()
	e, ok := r.devices[uuid]
	r.mu.RUnlock()
	if !ok {
		return
	}
	e.mu.Lock()
	e.state = StateDraining
	e.mu.Unlock()
	r.notify(e, "draining")
}

// Open reserves a stream to a device.
//
// Authorization is not decided here: this function is reached only after the
// caller has checked the operator's grants. What it does enforce is that the
// device is present and not draining.
func (r *Registry) Open(uuid, streamID, kind string) (io.ReadWriteCloser, error) {
	r.mu.RLock()
	e, ok := r.devices[uuid]
	r.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("registry: device %q is not connected", uuid)
	}
	e.mu.Lock()
	switch e.state {
	case StateOffline:
		e.mu.Unlock()
		return nil, fmt.Errorf("registry: device %q is offline", uuid)
	case StateDraining:
		e.mu.Unlock()
		return nil, fmt.Errorf("registry: device %q is shutting down and will not accept new streams", uuid)
	}
	e.streams++
	opener := e.open
	e.mu.Unlock()

	stream, err := opener(streamID, kind)

	e.mu.Lock()
	e.streams--
	e.lastSeen = r.now()
	e.mu.Unlock()

	if err != nil {
		return nil, err
	}
	return stream, nil
}

// Get2 returns a device snapshot pointer, for callers that need a possibly-absent
// device in a single expression.
func (r *Registry) Get2(uuid string) *Device {
	d, _ := r.Get(uuid)
	return d
}

// Get returns a device snapshot.
func (r *Registry) Get(uuid string) (*Device, bool) {
	r.mu.RLock()
	e, ok := r.devices[uuid]
	r.mu.RUnlock()
	if !ok {
		return nil, false
	}
	return snapshot(e), true
}

// List returns every known device, allowlisted or not, so operators can see that
// a device is enrolled but not currently connected.
func (r *Registry) List() []Device {
	r.mu.RLock()
	out := make([]Device, 0, len(r.devices))
	for _, e := range r.devices {
		out = append(out, *snapshot(e))
	}
	r.mu.RUnlock()

	// Present enrolled-but-absent devices too.
	r.mu.RLock()
	for uuid := range r.allowed {
		if _, online := r.devices[uuid]; !online {
			out = append(out, Device{UUID: uuid, State: StateOffline, LoopbackPort: r.ports[uuid]})
		}
	}
	r.mu.RUnlock()

	sort.Slice(out, func(i, j int) bool { return out[i].UUID < out[j].UUID })
	return out
}

func snapshot(e *entry) *Device {
	e.mu.Lock()
	defer e.mu.Unlock()
	return &Device{
		UUID:         e.uuid,
		Name:         e.name,
		State:        e.state,
		Agent:        e.agent,
		ConnectedAt:  e.connectedAt,
		LastSeen:     e.lastSeen,
		RemoteAddr:   e.remoteAddr,
		LoopbackPort: e.port,
		Streams:      e.streams,
	}
}

func (r *Registry) notify(e *entry, event string) {
	if r.onChange == nil {
		return
	}
	r.onChange(snapshot(e), event)
}

func (r *Registry) notifySnapshot(d *Device, event string) {
	if r.onChange == nil {
		return
	}
	r.onChange(d, event)
}
