package path

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRelayManager_DoubleStop verifies that calling Stop() multiple times is safe (idempotent).
// This test addresses BUG-H02 from the audit report.
func TestRelayManager_DoubleStop(t *testing.T) {
	listener := &mockListener{}
	rm := NewRelayManager(listener)
	require.NotNil(t, rm)

	// First stop should succeed
	rm.Stop()

	// Second stop should not panic (idempotent)
	assert.NotPanics(t, func() {
		rm.Stop()
	})

	// Third stop should also not panic
	assert.NotPanics(t, func() {
		rm.Stop()
	})
}

// TestRelayManager_ConcurrentStop verifies that concurrent calls to Stop() are safe.
func TestRelayManager_ConcurrentStop(t *testing.T) {
	listener := &mockListener{}
	rm := NewRelayManager(listener)
	require.NotNil(t, rm)

	// Call Stop() concurrently from multiple goroutines
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rm.Stop()
		}()
	}

	// Wait for all goroutines to complete
	assert.NotPanics(t, func() {
		wg.Wait()
	})
}

// mockListener is a minimal implementation of ListenerRef for testing.
type mockListener struct{}

func (m *mockListener) GetAddr() string {
	return "127.0.0.1:9001"
}
