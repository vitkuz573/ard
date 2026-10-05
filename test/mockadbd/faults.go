package mockadbd

// Fault injection.
//
// A mock that only ever behaves perfectly is a mock that cannot answer the question a relay
// test actually has. "Does the path work when a packet is lost, a stream is truncated
// mid-file, or the device stops responding halfway through a transfer?" cannot be answered
// by a device that never misbehaves, and answering it against real hardware means draining
// somebody's phone.
//
// So the faults live here, are configured per listener, and are deterministic when seeded.
// Deterministic matters more than it sounds: a relay test that fails one run in five is a
// relay test that gets ignored, and a coin flip is the worst possible thing to add to a
// suite that was flaky-hard to diagnose once already.

import (
	"hash/fnv"
	"math/rand"
	"sync"
	"time"
)

// Faults describes what the device should do wrong.
//
// The zero value is a device that behaves, which is what every other test wants.
type Faults struct {
	// Latency is added to every device-to-host write. Use it to find code that assumes a
	// reply arrives promptly.
	Latency time.Duration

	// LatencyJitter randomises the delay by up to this much, so a test can exercise
	// reordering rather than a fixed delay.
	LatencyJitter time.Duration

	// TruncateStream closes the connection after this many device-to-host bytes. It models
	// the most unpleasant real failure: a transfer that stops without an error, halfway.
	//
	// Zero means never. Negative means close immediately on the first write.
	TruncateStream int64

	// DropEveryNthWrite drops every Nth device-to-host write outright. Zero means never.
	DropEveryNthWrite int

	// CorruptEveryNthWrite flips a byte in every Nth write, which models a transport that
	// corrupts rather than drops. Checksums upstream should catch it; a relay that
	// forwards it blindly will not.
	CorruptEveryNthWrite int

	// StallAfterBytes stops responding after this many device-to-host bytes, leaving the
	// connection open and silent. This is the one that produces a hang rather than an
	// error, and it is the case a watchdog exists for.
	StallAfterBytes int64

	// RefuseOpen makes the device reject a service request with FAIL, as a locked-down
	// device would.
	RefuseOpen bool

	// Seed makes the randomness reproducible. Zero picks one, so a run is still repeatable
	// within itself even when the caller does not care.
	Seed int64

	mu       sync.Mutex
	written  int64
	writes   int
	rng      *rand.Rand
	truncate bool
	stalled  bool
}

func (f *Faults) init() {
	if f == nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.rng == nil {
		seed := f.Seed
		if seed == 0 {
			// A fixed default rather than time-based: repeatable by accident, which is
			// what a test suite needs.
			seed = 0x5EED
		}
		f.rng = rand.New(rand.NewSource(seed))
	}
}

// decision is what the fault layer decided to do with one write.
type decision int

// Decision is the exported form of the internal decision, for tests from outside the package.
type Decision = decision

// Exported decision values, mirroring the internal ones.
const (
	Deliver      = deliver
	Drop         = drop
	CorruptWrite = corruptWrite
	Stall        = stall
	Truncate     = truncate
)

const (
	deliver decision = iota
	drop
	corruptWrite
	stall
	truncate
)

// beforeWrite is called before a device-to-host write and reports what to do.
//
// The counters live here so TruncateStream, StallAfterBytes and the every-Nth rules compose
// instead of fighting: each write is accounted once, then every rule gets a say, and the
// first one that objects wins.
func (f *Faults) beforeWrite(n int) decision {
	if f == nil {
		return deliver
	}
	f.init()
	f.mu.Lock()
	defer f.mu.Unlock()

	f.writes++
	f.written += int64(n)

	if f.StallAfterBytes > 0 && f.written > f.StallAfterBytes {
		f.stalled = true
		return stall
	}
	if f.TruncateStream != 0 &&
		(f.TruncateStream < 0 || f.written > f.TruncateStream) {
		f.truncate = true
		return truncate
	}
	if f.DropEveryNthWrite > 0 && f.writes%f.DropEveryNthWrite == 0 {
		return drop
	}
	if f.CorruptEveryNthWrite > 0 && f.writes%f.CorruptEveryNthWrite == 0 {
		return corruptWrite
	}
	return deliver
}

// afterWrite applies the latency, outside the lock so a slow write does not serialise
// unrelated streams.
func (f *Faults) afterWrite() {
	if f == nil || f.Latency == 0 {
		return
	}
	d := f.Latency
	if f.LatencyJitter > 0 {
		f.mu.Lock()
		j := time.Duration(f.rng.Int63n(int64(f.LatencyJitter) + 1))
		f.mu.Unlock()
		d += j
	}
	time.Sleep(d)
}

// corruptBytes returns a copy of p with one byte changed.
//
// A copy rather than in-place, so a test that asks for corruption does not silently damage
// the payload every later layer sees.
func corruptBytes(p []byte, rng *rand.Rand) []byte {
	out := append([]byte(nil), p...)
	if len(out) == 0 {
		return out
	}
	i := rng.Intn(len(out))
	// Flip the high bit, so a byte is always changed and never accidentally becomes equal.
	out[i] ^= 0x80
	return out
}

// seedFrom derives a stable seed from a string, for tests that want reproducibility without
// carrying a number around.
func seedFrom(s string) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(s))
	return int64(h.Sum64() & 0x7fffffffffffffff)
}

// Test-only shims.
//
// The fault layer is unexported inside the package's own tests, but the behaviour has to be
// assertable from outside it: a relay test configures Faults through Config and needs to be
// able to state what it expects without reaching into internals. These expose the decision
// and the helpers without making the whole type public.

// BeforeWriteForTest reports what the fault layer decided for a write of n bytes.
func (f *Faults) BeforeWriteForTest(n int) Decision {
	if f == nil {
		return Deliver
	}
	return Decision(f.beforeWrite(n))
}

// AfterWriteForTest applies the configured latency.
func (f *Faults) AfterWriteForTest() { f.afterWrite() }

// CorruptBytesForTest returns a corrupted copy, for asserting that corruption changes bytes
// and leaves the caller's slice alone.
func CorruptBytesForTest(p []byte, rng *rand.Rand) []byte { return corruptBytes(p, rng) }

// RngForTest exposes the deterministic source so the shim above can use it.
func RngForTest(f *Faults) *rand.Rand {
	f.init()
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.rng
}
