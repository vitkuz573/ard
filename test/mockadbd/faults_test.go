package mockadbd_test

import (
	"strings"
	"testing"
	"time"

	mockadbd "github.com/vitkuz573/ard/test/mockadbd"
)

// listenMock starts a device with an explicit configuration, which the fault tests need
// because the faults are the configuration.
func listenMock(t *testing.T, cfg *mockadbd.Config) (*mockadbd.Listener, error) {
	t.Helper()
	return mockadbd.Listen("127.0.0.1:0", *cfg)
}

// A device that never misbehaves cannot answer the questions a relay test actually has.
// These tests assert that each fault is reachable and does what it claims, because a fault
// injection layer that silently does nothing is worse than not having one: the test that
// depends on it passes for the wrong reason.

func TestFaultsDefaultToBehaving(t *testing.T) {
	var f *mockadbd.Faults
	if got := f.BeforeWriteForTest(10); got != mockadbd.Deliver {
		t.Fatalf("a nil Faults changed a write: %v", got)
	}
	empty := &mockadbd.Faults{}
	for i := 0; i < 20; i++ {
		if got := empty.BeforeWriteForTest(10); got != mockadbd.Deliver {
			t.Fatalf("the zero Faults changed write %d: %v", i, got)
		}
	}
}

func TestFaultDropsEveryNthWrite(t *testing.T) {
	f := &mockadbd.Faults{DropEveryNthWrite: 3}
	var drops, delivered int
	for i := 1; i <= 9; i++ {
		if f.BeforeWriteForTest(10) == mockadbd.Drop {
			drops++
		} else {
			delivered++
		}
	}
	if drops != 3 {
		t.Fatalf("dropped %d of 9 writes, want 3", drops)
	}
	if delivered != 6 {
		t.Fatalf("delivered %d of 9, want 6", delivered)
	}
}

func TestFaultCorruptsEveryNthWrite(t *testing.T) {
	f := &mockadbd.Faults{CorruptEveryNthWrite: 2}
	corrupt := 0
	for i := 1; i <= 6; i++ {
		if f.BeforeWriteForTest(8) == mockadbd.CorruptWrite {
			corrupt++
		}
	}
	if corrupt != 3 {
		t.Fatalf("corrupted %d of 6 writes, want 3", corrupt)
	}
	// Corruption has to change the bytes and must not damage the caller's buffer.
	orig := []byte("payload")
	got := mockadbd.CorruptBytesForTest(orig, mockadbd.RngForTest(f))
	if string(orig) != "payload" {
		t.Fatalf("corruption damaged the caller's slice: %q", orig)
	}
	if string(got) == "payload" {
		t.Fatal("corruption returned the input unchanged")
	}
}

// Truncation is the unpleasant one: the transfer stops with no error, which is what a
// watchdog on the far side exists to survive.
func TestFaultTruncatesAfterAByteCount(t *testing.T) {
	f := &mockadbd.Faults{TruncateStream: 100}
	var truncated bool
	for i := 0; i < 20; i++ {
		if f.BeforeWriteForTest(20) == mockadbd.Truncate {
			truncated = true
			break
		}
	}
	if !truncated {
		t.Fatal("truncation never triggered")
	}
	// Negative means close immediately, which is a different failure worth being able to
	// ask for.
	immediate := &mockadbd.Faults{TruncateStream: -1}
	if got := immediate.BeforeWriteForTest(1); got != mockadbd.Truncate {
		t.Fatalf("a negative TruncateStream did not fire on the first write: %v", got)
	}
}

// A stall produces a hang rather than an error, so it has to be distinguishable from
// truncation and from a drop.
func TestFaultStallsAfterAByteCount(t *testing.T) {
	f := &mockadbd.Faults{StallAfterBytes: 50}
	var sawStall bool
	for i := 0; i < 20; i++ {
		if f.BeforeWriteForTest(10) == mockadbd.Stall {
			sawStall = true
			break
		}
	}
	if !sawStall {
		t.Fatal("stall never triggered")
	}
}

// Rules have to compose rather than fight: whichever objects first wins, and the counters
// advance once per write so "every third" stays every third.
func TestFaultRulesComposeDeterministically(t *testing.T) {
	build := func() *mockadbd.Faults {
		return &mockadbd.Faults{DropEveryNthWrite: 2, Seed: 42}
	}
	first := build()
	second := build()
	for i := 0; i < 20; i++ {
		a := first.BeforeWriteForTest(16)
		b := second.BeforeWriteForTest(16)
		if a != b {
			t.Fatalf("write %d diverged: %v vs %v with the same seed", i, a, b)
		}
	}
}

// Latency is applied outside the lock so a slow write cannot serialise other streams, and
// it must actually be observable or a test that asks for it is not testing anything.
func TestFaultLatencyIsObservable(t *testing.T) {
	f := &mockadbd.Faults{Latency: 60 * time.Millisecond}
	start := time.Now()
	f.AfterWriteForTest()
	elapsed := time.Since(start)
	if elapsed < 50*time.Millisecond {
		t.Fatalf("a 60ms latency took %s", elapsed)
	}
}

// The point of the whole layer: a truncated transfer must actually look truncated to a
// client, not complete quietly. This is the assertion a relay test would otherwise make by
// hand against real hardware.
func TestTruncatedTransferIsVisibleToAClient(t *testing.T) {
	adb := requireAdb(t)
	// A budget small enough that the shell's greeting and first output cannot fit.
	cfg := mockadbd.Config{Faults: &mockadbd.Faults{TruncateStream: 8}}
	l, err := listenMock(t, &cfg)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()
	startPrivateServer(t, adb)
	serial := l.Addr().String()
	_ = adbCmd(t, adb, "connect", serial).Run()
	waitForState(t, adb, serial, "device")

	// Whatever adb manages to do, it must not report a complete, coherent command it did
	// not receive. Either it errors, or it hangs, or it returns something partial.
	// The assertion is not "it failed" but "it did not deliver output it never received".
	// Accepting either outcome, as an earlier version of this test did, means it passes
	// whether or not the fault layer works -- which is the failure mode a fault test must
	// not have.
	var out string
	done := make(chan struct{})
	go func() {
		b, _ := adbCmd(t, adb, "-s", serial, "shell", "echo truncate-canary").CombinedOutput()
		out = string(b)
		close(done)
	}()
	select {
	case <-done:
		if strings.TrimSpace(out) == "truncate-canary" {
			t.Fatal("a truncated device delivered the complete command output")
		}
	case <-time.After(20 * time.Second):
		// The realistic outcome of a stream cut mid-response.
	}
}

// A stalled device must not be distinguishable from a dead one to a client that has a
// watchdog, and it must not be distinguishable from a healthy one either -- which is
// exactly why the stall case needs a timeout in the first place.
func TestStalledDeviceProducesNoFurtherOutput(t *testing.T) {
	adb := requireAdb(t)
	cfg := mockadbd.Config{Faults: &mockadbd.Faults{StallAfterBytes: 1}}
	l, err := listenMock(t, &cfg)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()
	startPrivateServer(t, adb)
	serial := l.Addr().String()
	_ = adbCmd(t, adb, "connect", serial).Run()
	waitForState(t, adb, serial, "device")

	done := make(chan struct{})
	var out string
	go func() {
		b, _ := adbCmd(t, adb, "-s", serial, "shell", "echo should-not-arrive").CombinedOutput()
		out = string(b)
		close(done)
	}()
	select {
	case <-done:
		if strings.TrimSpace(out) == "should-not-arrive" {
			t.Fatal("a stalled device delivered the command output anyway")
		}
	case <-time.After(20 * time.Second):
		// The expected outcome: silence.
	}
}
