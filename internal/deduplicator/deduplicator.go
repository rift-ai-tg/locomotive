package deduplicator

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"

	cache "github.com/Code-Hex/go-generics-cache"
)

// Deduplicator suppresses repeated events with the same signature within a time window.
// Used for Sentry log forwarding to prevent tick-cycle spam.
type Deduplicator struct {
	cache  *cache.Cache[string, sentinel]
	window time.Duration
	mu     sync.Mutex
}

type sentinel struct{}

// New creates a Deduplicator that suppresses repeats within the given window.
func New(window time.Duration) *Deduplicator {
	if window <= 0 {
		window = time.Minute
	}
	return &Deduplicator{
		cache:  cache.New[string, sentinel](),
		window: window,
	}
}

// RecordAndShouldSend records the signature and returns true if the event should be sent.
// First occurrence: returns true (send). Subsequent occurrences within window: returns false (suppress).
// After window expires, the next occurrence is treated as first again.
func (d *Deduplicator) RecordAndShouldSend(signature string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, exists := d.cache.Get(signature)
	if exists {
		return false
	}

	d.cache.Set(signature, sentinel{}, cache.WithExpiration(d.window))
	return true
}

// SignatureForDeployLog builds a stable signature from log message and source metadata.
// Collapses identical errors from the same service/deployment.
func SignatureForDeployLog(message string, serviceID, deploymentID, severity string) string {
	h := sha256.New()
	h.Write([]byte(message))
	h.Write([]byte("|"))
	h.Write([]byte(serviceID))
	h.Write([]byte("|"))
	h.Write([]byte(deploymentID))
	h.Write([]byte("|"))
	h.Write([]byte(severity))
	return hex.EncodeToString(h.Sum(nil))
}
