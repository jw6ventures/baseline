package agent

import (
	"sync/atomic"
	"testing"
	"time"
)

// The margins are wide so a loaded machine can't make this flaky.
func TestSettler(t *testing.T) {
	var fired atomic.Int32
	waitFor := func(n int32) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for fired.Load() < n && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		if got := fired.Load(); got < n {
			t.Fatalf("fired %d times, want %d", got, n)
		}
	}

	// A burst is one collection, once it pauses.
	s := &settler{quiet: 300 * time.Millisecond, max: time.Minute, fire: func() { fired.Add(1) }}
	for range 5 {
		s.poke()
	}
	waitFor(1)
	time.Sleep(400 * time.Millisecond)
	if n := fired.Load(); n != 1 {
		t.Fatalf("a burst fired %d times", n)
	}

	// Events that never pause still collect, max after the first.
	fired.Store(0)
	s = &settler{quiet: time.Minute, max: 100 * time.Millisecond, fire: func() { fired.Add(1) }}
	s.poke()
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-done:
				return
			default:
				s.poke()
				time.Sleep(10 * time.Millisecond)
			}
		}
	}()
	waitFor(1)
	close(done)
	s.stop()

	// Stopping drops a pending collection.
	fired.Store(0)
	s = &settler{quiet: 300 * time.Millisecond, max: time.Minute, fire: func() { fired.Add(1) }}
	s.poke()
	s.stop()
	time.Sleep(500 * time.Millisecond)
	if n := fired.Load(); n != 0 {
		t.Fatalf("fired %d times after stop", n)
	}
}
