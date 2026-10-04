// Package audit records what operators did.
//
// The log is append-only and written before an action is granted rather than
// after it completes. That ordering is the point: if the gateway dies mid-session
// the record still exists, and a log written afterwards would be exactly the log
// that goes missing when something goes wrong.
package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Event is one audited action.
type Event struct {
	Time time.Time `json:"time"`
	// Kind is a dotted event name such as "stream.open" or "device.connected".
	Kind string `json:"kind"`
	// Actor identifies the human or device responsible. Never "an operator": an
	// action that cannot be attributed is not auditable in any useful sense.
	Actor string `json:"actor"`
	// Device is the device UUID acted upon.
	Device string `json:"device,omitempty"`
	// Stream correlates the action with a stream across the gateway, the
	// transport and the device's own logs.
	Stream string `json:"stream,omitempty"`
	// Remote is the source address of the connection.
	Remote string `json:"remote,omitempty"`
	// Detail is free text, but must never contain secrets or command output.
	Detail string `json:"detail,omitempty"`
}

// Config configures an Auditor.
type Config struct {
	// Path is the append-only log file. Empty means stdout only.
	Path string
	// AlsoTo receives a copy of every event, for stderr visibility during an
	// incident. It is not authoritative; the file is.
	AlsoTo io.Writer
	// Clock is injectable so tests get deterministic output.
	Clock func() time.Time
}

// Auditor writes events.
type Auditor struct {
	mu   sync.Mutex
	w    io.Writer
	file *os.File
	clk  func() time.Time
}

// New opens the audit log for appending.
//
// The file is created with owner-only permissions: an audit log that any local
// account can truncate is not evidence of anything.
func New(cfg Config) (*Auditor, error) {
	a := &Auditor{w: cfg.AlsoTo, clk: cfg.Clock}
	if a.clk == nil {
		a.clk = time.Now
	}
	if cfg.Path == "" {
		return a, nil
	}
	if err := os.MkdirAll(filepath.Dir(cfg.Path), 0o750); err != nil {
		return nil, fmt.Errorf("audit: mkdir: %w", err)
	}
	f, err := os.OpenFile(cfg.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit: open %s: %w", cfg.Path, err)
	}
	a.file = f
	a.w = f
	return a, nil
}

// Record appends an event.
func (a *Auditor) Record(e Event) {
	if e.Time.IsZero() {
		e.Time = a.clk().UTC()
	}
	line, err := json.Marshal(e)
	if err != nil {
		// A marshal failure means a field type is wrong, which is a programming
		// error. Report it rather than silently dropping the record.
		fmt.Fprintf(os.Stderr, "audit: marshal event: %v\n", err)
		return
	}
	line = append(line, '\n')

	a.mu.Lock()
	defer a.mu.Unlock()
	if a.file != nil {
		if _, err := a.file.Write(line); err != nil {
			fmt.Fprintf(os.Stderr, "audit: write: %v\n", err)
		}
	}
	if a.file != nil && a.w != nil && a.w != io.Writer(a.file) {
		_, _ = a.w.Write(line)
	} else if a.file == nil && a.w != nil {
		_, _ = a.w.Write(line)
	}
}

// Close releases the log file.
func (a *Auditor) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.file != nil {
		return a.file.Close()
	}
	return nil
}
