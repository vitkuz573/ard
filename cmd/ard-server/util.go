package main

import (
	"strconv"
	"sync/atomic"
	"time"
)

// streamIDs hands out short, unique stream IDs.
//
// They exist to correlate one action across the gateway, the transport and the
// device's own logs. Uniqueness matters more than readability here: two streams
// sharing an ID would make an audit trail ambiguous, which defeats its purpose.
type streamIDs struct {
	n   atomic.Uint64
	seq atomic.Uint64
}

var ids = &streamIDs{}

func newStreamID() string {
	// The sequence guarantees uniqueness within a process even when several IDs
	// are minted in the same nanosecond, which happens under load.
	return "st-" + strconv.FormatUint(ids.seq.Add(1), 36) + "-" +
		strconv.FormatInt(time.Now().UnixMilli(), 36)
}
