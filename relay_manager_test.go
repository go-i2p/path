package ssu2path

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/go-i2p/common/data"
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

// TestRelayManager_IntroducerExpiryTracksRelayTag verifies the S-16 fix: an
// introducer's ExpiresAt must reflect the real relay-tag lifetime, not a
// hardcoded 1h, so the published iexp matches the tag's actual expiry.
func TestRelayManager_IntroducerExpiryTracksRelayTag(t *testing.T) {
	listener := &mockListener{}
	rm := NewRelayManager(listener)
	require.NotNil(t, rm)
	defer rm.Stop()

	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:5000")
	require.NoError(t, err)

	// Allocate a real relay tag so it exists in the manager's map.
	relayTag, err := rm.AllocateRelayTag(addr)
	require.NoError(t, err)
	require.NotZero(t, relayTag)

	// Give the tag a distinctive, non-default expiry so we can prove the
	// introducer picks it up rather than the hardcoded 1h fallback.
	tagExpiry := time.Now().Add(45 * time.Minute)
	rm.SetRelayTagExpiry(relayTag, tagExpiry)

	routerHash := data.Hash{0x01, 0x02, 0x03, 0x04}
	require.NoError(t, rm.RegisterIntroducer(addr, routerHash, relayTag))

	intros := rm.GetAllIntroducers()
	require.Len(t, intros, 1)
	assert.True(t, intros[0].ExpiresAt.Equal(tagExpiry),
		"introducer ExpiresAt (%s) should equal the relay tag's expiry (%s)",
		intros[0].ExpiresAt, tagExpiry)
}

// TestRelayManager_IntroducerExpiryUpdateTracksRelayTag verifies the S-16 fix
// on the update-existing path: re-registering an introducer for the same
// address must refresh its ExpiresAt to the relay tag's real lifetime.
func TestRelayManager_IntroducerExpiryUpdateTracksRelayTag(t *testing.T) {
	listener := &mockListener{}
	rm := NewRelayManager(listener)
	require.NotNil(t, rm)
	defer rm.Stop()

	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:5001")
	require.NoError(t, err)

	relayTag, err := rm.AllocateRelayTag(addr)
	require.NoError(t, err)

	routerHash := data.Hash{0x0a, 0x0b, 0x0c, 0x0d}
	require.NoError(t, rm.RegisterIntroducer(addr, routerHash, relayTag))

	// Simulate the tag's lifetime changing, then re-register the same
	// introducer. The update-existing path must pick up the new expiry.
	newExpiry := time.Now().Add(30 * time.Minute)
	rm.SetRelayTagExpiry(relayTag, newExpiry)
	require.NoError(t, rm.RegisterIntroducer(addr, routerHash, relayTag))

	intros := rm.GetAllIntroducers()
	require.Len(t, intros, 1)
	assert.True(t, intros[0].ExpiresAt.Equal(newExpiry),
		"updated introducer ExpiresAt (%s) should equal the relay tag's new expiry (%s)",
		intros[0].ExpiresAt, newExpiry)
}

// TestRelayManager_IntroducerExpiryFallback verifies the S-16 fallback: when
// the relay tag is not present in the manager's map, the introducer still
// gets a sensible default expiry (now + 1h) rather than a zero time.
func TestRelayManager_IntroducerExpiryFallback(t *testing.T) {
	listener := &mockListener{}
	rm := NewRelayManager(listener)
	require.NotNil(t, rm)
	defer rm.Stop()

	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:5002")
	require.NoError(t, err)

	// Use a tag value that was never allocated, so it is absent from the map.
	const unknownTag = 0xdeadbeef
	routerHash := data.Hash{0x11, 0x22, 0x33, 0x44}
	require.NoError(t, rm.RegisterIntroducer(addr, routerHash, unknownTag))

	intros := rm.GetAllIntroducers()
	require.Len(t, intros, 1)
	// The fallback is now + 1h; just assert it is in the future and non-zero.
	assert.True(t, intros[0].ExpiresAt.After(time.Now()),
		"fallback introducer ExpiresAt should be in the future, got %s", intros[0].ExpiresAt)
}
