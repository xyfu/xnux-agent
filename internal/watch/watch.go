// Package watch holds what the event watchers share: the supervisor that
// restarts a failed watcher with backoff (spec A3: 1 s → 5 min) and the
// per-watcher error counters reported in diag.collector_errors.
package watch

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

const (
	backoffMin = time.Second
	backoffMax = 5 * time.Minute
	// A run that lasted this long counts as healthy and resets the backoff.
	healthyAfter = time.Minute
)

// Errors counts watcher failures by name. It is safe for concurrent use.
type Errors struct {
	mu sync.Mutex
	m  map[string]int
}

func (e *Errors) Add(name string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.m == nil {
		e.m = map[string]int{}
	}
	e.m[name]++
}

// Snapshot returns a copy of the counters.
func (e *Errors) Snapshot() map[string]int {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make(map[string]int, len(e.m))
	for k, v := range e.m {
		out[k] = v
	}
	return out
}

// Supervise runs fn until ctx ends, restarting it after an error. A watcher
// failing affects only itself.
func Supervise(ctx context.Context, name string, log *slog.Logger, errs *Errors, fn func(context.Context) error) {
	backoff := backoffMin
	for ctx.Err() == nil {
		start := time.Now()
		err := fn(ctx)
		if ctx.Err() != nil {
			return
		}
		if time.Since(start) >= healthyAfter {
			backoff = backoffMin
		}
		errs.Add(name)
		log.Warn("watcher stopped, restarting", "watcher", name, "err", err, "in", backoff)
		t := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		backoff = min(backoff*2, backoffMax)
	}
}
