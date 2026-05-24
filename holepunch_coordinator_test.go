package ssu2path

import (
	"crypto/ed25519"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/samber/oops"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestHolePunchCoordinator creates a HolePunchCoordinator for testing.
// BUG-M02 fix: Now provides a default no-op signature verifier since it's
// mandatory at construction.
func createTestHolePunchCoordinator(t *testing.T) *HolePunchCoordinator {
	t.Helper()

	// Create relay manager (nil listener is sufficient for path package tests)
	manager := NewRelayManager(nil)

	// Provide a default verifier that accepts all signatures (for testing)
	verifyFn := func(block *RelayIntroBlock, signerKey ed25519.PublicKey) error {
		return nil
	}

	// Create coordinator with mandatory verifier
	hpc, err := NewHolePunchCoordinator(manager, verifyFn)
	require.NoError(t, err)
	return hpc
}

func TestNewHolePunchCoordinator(t *testing.T) {
	manager := NewRelayManager(nil)

	verifyFn := func(block *RelayIntroBlock, signerKey ed25519.PublicKey) error {
		return nil
	}

	hpc, err := NewHolePunchCoordinator(manager, verifyFn)
	require.NoError(t, err)

	assert.NotNil(t, hpc)
	assert.Equal(t, manager, hpc.manager)
	assert.NotNil(t, hpc.attempts)
	assert.Equal(t, 0, len(hpc.attempts))
}

func TestNewHolePunchCoordinator_NilVerifierReturnsError(t *testing.T) {
	manager := NewRelayManager(nil)

	// L-3 fix: Verify that nil verifier returns an error instead of panicking
	hpc, err := NewHolePunchCoordinator(manager, nil)
	assert.Error(t, err, "Expected error when verifier is nil")
	assert.Nil(t, hpc)
}

func TestHolePunchCoordinator_InitiateHolePunch(t *testing.T) {
	hpc := createTestHolePunchCoordinator(t)

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 8887}
	introducerAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.2"), Port: 8888}
	relayTag := uint32(0x12345678)

	sessionID, err := hpc.InitiateHolePunch(remoteAddr, introducerAddr, relayTag)

	require.NoError(t, err)
	assert.NotEqual(t, uint64(0), sessionID)

	// Verify attempt was created
	attempt := hpc.GetAttempt(sessionID)
	require.NotNil(t, attempt)
	assert.Equal(t, sessionID, attempt.SessionID)
	assert.Equal(t, remoteAddr.String(), attempt.RemoteAddr.String())
	assert.Equal(t, introducerAddr.String(), attempt.Introducer.String())
	assert.Equal(t, HolePunchRequested, attempt.State)
	assert.Equal(t, 0, attempt.Retries)
	assert.Equal(t, relayTag, attempt.RelayTag)
}

func TestHolePunchCoordinator_InitiateHolePunch_NilRemoteAddr(t *testing.T) {
	hpc := createTestHolePunchCoordinator(t)

	introducerAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.2"), Port: 8888}
	relayTag := uint32(0x12345678)

	_, err := hpc.InitiateHolePunch(nil, introducerAddr, relayTag)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "remote address cannot be nil")
}

func TestHolePunchCoordinator_InitiateHolePunch_NilIntroducerAddr(t *testing.T) {
	hpc := createTestHolePunchCoordinator(t)

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 8887}
	relayTag := uint32(0x12345678)

	_, err := hpc.InitiateHolePunch(remoteAddr, nil, relayTag)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "introducer address cannot be nil")
}

func TestHolePunchCoordinator_InitiateHolePunch_ZeroRelayTag(t *testing.T) {
	hpc := createTestHolePunchCoordinator(t)

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 8887}
	introducerAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.2"), Port: 8888}

	_, err := hpc.InitiateHolePunch(remoteAddr, introducerAddr, 0)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "relay tag cannot be zero")
}

func TestHolePunchCoordinator_InitiateHolePunch_MultipleAttempts(t *testing.T) {
	hpc := createTestHolePunchCoordinator(t)

	remoteAddr1 := &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 8887}
	remoteAddr2 := &net.UDPAddr{IP: net.ParseIP("203.0.113.3"), Port: 8889}
	introducerAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.2"), Port: 8888}

	sessionID1, err := hpc.InitiateHolePunch(remoteAddr1, introducerAddr, uint32(0x12345678))
	require.NoError(t, err)

	sessionID2, err := hpc.InitiateHolePunch(remoteAddr2, introducerAddr, uint32(0x87654321))
	require.NoError(t, err)

	// Session IDs should be different (derived from different relay tags)
	assert.NotEqual(t, sessionID1, sessionID2)

	// Both attempts should exist
	assert.NotNil(t, hpc.GetAttempt(sessionID1))
	assert.NotNil(t, hpc.GetAttempt(sessionID2))
}

func TestHolePunchCoordinator_SendHolePunch(t *testing.T) {
	hpc := createTestHolePunchCoordinator(t)

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 8887}
	introducerAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.2"), Port: 8888}
	relayTag := uint32(0x12345678)

	sessionID, err := hpc.InitiateHolePunch(remoteAddr, introducerAddr, relayTag)
	require.NoError(t, err)

	targetAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 8887}
	err = hpc.SendHolePunch(sessionID, targetAddr)

	require.NoError(t, err)

	// Verify state changed to Sent
	attempt := hpc.GetAttempt(sessionID)
	require.NotNil(t, attempt)
	assert.Equal(t, HolePunchSent, attempt.State)
}

func TestHolePunchCoordinator_SendHolePunch_ZeroSessionID(t *testing.T) {
	hpc := createTestHolePunchCoordinator(t)

	targetAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 8887}
	err := hpc.SendHolePunch(0, targetAddr)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "session ID cannot be zero")
}

func TestHolePunchCoordinator_SendHolePunch_NilAddress(t *testing.T) {
	hpc := createTestHolePunchCoordinator(t)

	err := hpc.SendHolePunch(12345, nil)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "target address cannot be nil")
}

func TestHolePunchCoordinator_SendHolePunch_SessionNotFound(t *testing.T) {
	hpc := createTestHolePunchCoordinator(t)

	targetAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 8887}
	err := hpc.SendHolePunch(99999, targetAddr)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "hole punch session not found")
}

func TestHolePunchCoordinator_HandleHolePunch(t *testing.T) {
	hpc := createTestHolePunchCoordinator(t)

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 8887}
	introducerAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.2"), Port: 8888}
	relayTag := uint32(0x12345678)

	sessionID, err := hpc.InitiateHolePunch(remoteAddr, introducerAddr, relayTag)
	require.NoError(t, err)

	fromAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.3"), Port: 8889}

	// Per BUG-001 fix: nil block must be rejected per SSU2 spec
	err = hpc.HandleHolePunch(sessionID, fromAddr, nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "block cannot be nil")
}

func TestHolePunchCoordinator_HandleHolePunch_ZeroSessionID(t *testing.T) {
	hpc := createTestHolePunchCoordinator(t)

	fromAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 8887}
	err := hpc.HandleHolePunch(0, fromAddr, nil, nil)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "session ID cannot be zero")
}

func TestHolePunchCoordinator_HandleHolePunch_NilAddress(t *testing.T) {
	hpc := createTestHolePunchCoordinator(t)

	err := hpc.HandleHolePunch(12345, nil, nil, nil)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "from address cannot be nil")
}

func TestHolePunchCoordinator_HandleHolePunch_SessionNotFound(t *testing.T) {
	hpc := createTestHolePunchCoordinator(t)

	fromAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 8887}
	err := hpc.HandleHolePunch(99999, fromAddr, nil, nil)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "hole punch session not found")
}

func TestHolePunchCoordinator_ProcessHolePunchResponse(t *testing.T) {
	hpc := createTestHolePunchCoordinator(t)

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 8887}
	introducerAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.2"), Port: 8888}
	relayTag := uint32(0x12345678)

	sessionID, err := hpc.InitiateHolePunch(remoteAddr, introducerAddr, relayTag)
	require.NoError(t, err)

	// Per BUG-001 fix: nil block must be rejected per SSU2 spec
	err = hpc.ProcessHolePunchResponse(sessionID, remoteAddr, nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "block cannot be nil")
}

func TestHolePunchCoordinator_ProcessHolePunchResponse_ZeroSessionID(t *testing.T) {
	hpc := createTestHolePunchCoordinator(t)

	addr := &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 8887}
	err := hpc.ProcessHolePunchResponse(0, addr, nil, nil)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "session ID cannot be zero")
}

func TestHolePunchCoordinator_ProcessHolePunchResponse_NilAddress(t *testing.T) {
	hpc := createTestHolePunchCoordinator(t)

	err := hpc.ProcessHolePunchResponse(12345, nil, nil, nil)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "address cannot be nil")
}

func TestHolePunchCoordinator_ProcessHolePunchResponse_SessionNotFound(t *testing.T) {
	hpc := createTestHolePunchCoordinator(t)

	addr := &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 8887}
	err := hpc.ProcessHolePunchResponse(99999, addr, nil, nil)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "hole punch session not found")
}

func TestHolePunchCoordinator_ProcessHolePunchResponse_AddressMismatch(t *testing.T) {
	hpc := createTestHolePunchCoordinator(t)

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 8887}
	introducerAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.2"), Port: 8888}
	relayTag := uint32(0x12345678)

	sessionID, err := hpc.InitiateHolePunch(remoteAddr, introducerAddr, relayTag)
	require.NoError(t, err)

	// Different address
	wrongAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.99"), Port: 9999}
	// Per BUG-001 fix: nil block is rejected before address check
	err = hpc.ProcessHolePunchResponse(sessionID, wrongAddr, nil, nil)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "block cannot be nil")
}

func TestHolePunchCoordinator_RetryHolePunch(t *testing.T) {
	hpc := createTestHolePunchCoordinator(t)

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 8887}
	introducerAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.2"), Port: 8888}
	relayTag := uint32(0x12345678)

	sessionID, err := hpc.InitiateHolePunch(remoteAddr, introducerAddr, relayTag)
	require.NoError(t, err)

	// First retry
	err = hpc.RetryHolePunch(sessionID)
	require.NoError(t, err)

	attempt := hpc.GetAttempt(sessionID)
	require.NotNil(t, attempt)
	assert.Equal(t, 1, attempt.Retries)
	assert.Equal(t, HolePunchRequested, attempt.State)

	// Second retry
	err = hpc.RetryHolePunch(sessionID)
	require.NoError(t, err)

	attempt = hpc.GetAttempt(sessionID)
	require.NotNil(t, attempt)
	assert.Equal(t, 2, attempt.Retries)

	// Third retry
	err = hpc.RetryHolePunch(sessionID)
	require.NoError(t, err)

	attempt = hpc.GetAttempt(sessionID)
	require.NotNil(t, attempt)
	assert.Equal(t, 3, attempt.Retries)
}

func TestHolePunchCoordinator_RetryHolePunch_MaxRetriesExceeded(t *testing.T) {
	hpc := createTestHolePunchCoordinator(t)

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 8887}
	introducerAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.2"), Port: 8888}
	relayTag := uint32(0x12345678)

	sessionID, err := hpc.InitiateHolePunch(remoteAddr, introducerAddr, relayTag)
	require.NoError(t, err)

	// Exhaust retries
	for i := 0; i < 3; i++ {
		err = hpc.RetryHolePunch(sessionID)
		require.NoError(t, err)
	}

	// Fourth retry should fail
	err = hpc.RetryHolePunch(sessionID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "maximum retry attempts exceeded")

	// Verify state is Failed
	attempt := hpc.GetAttempt(sessionID)
	require.NotNil(t, attempt)
	assert.Equal(t, HolePunchFailed, attempt.State)
}

func TestHolePunchCoordinator_RetryHolePunch_ZeroSessionID(t *testing.T) {
	hpc := createTestHolePunchCoordinator(t)

	err := hpc.RetryHolePunch(0)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "session ID cannot be zero")
}

func TestHolePunchCoordinator_RetryHolePunch_SessionNotFound(t *testing.T) {
	hpc := createTestHolePunchCoordinator(t)

	err := hpc.RetryHolePunch(99999)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "hole punch session not found")
}

func TestHolePunchCoordinator_CompleteHolePunch(t *testing.T) {
	hpc := createTestHolePunchCoordinator(t)

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 8887}
	introducerAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.2"), Port: 8888}
	relayTag := uint32(0x12345678)

	sessionID, err := hpc.InitiateHolePunch(remoteAddr, introducerAddr, relayTag)
	require.NoError(t, err)

	err = hpc.CompleteHolePunch(sessionID)
	require.NoError(t, err)

	// Verify state is Success
	attempt := hpc.GetAttempt(sessionID)
	require.NotNil(t, attempt)
	assert.Equal(t, HolePunchSuccess, attempt.State)
}

func TestHolePunchCoordinator_CompleteHolePunch_ZeroSessionID(t *testing.T) {
	hpc := createTestHolePunchCoordinator(t)

	err := hpc.CompleteHolePunch(0)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "session ID cannot be zero")
}

func TestHolePunchCoordinator_CompleteHolePunch_SessionNotFound(t *testing.T) {
	hpc := createTestHolePunchCoordinator(t)

	err := hpc.CompleteHolePunch(99999)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "hole punch session not found")
}

func TestHolePunchCoordinator_FailHolePunch(t *testing.T) {
	hpc := createTestHolePunchCoordinator(t)

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 8887}
	introducerAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.2"), Port: 8888}
	relayTag := uint32(0x12345678)

	sessionID, err := hpc.InitiateHolePunch(remoteAddr, introducerAddr, relayTag)
	require.NoError(t, err)

	// Fail the hole punch
	err = hpc.FailHolePunch(sessionID, assert.AnError)
	require.NoError(t, err)

	// Verify state is Failed
	attempt := hpc.GetAttempt(sessionID)
	require.NotNil(t, attempt)
	assert.Equal(t, HolePunchFailed, attempt.State)
}

func TestHolePunchCoordinator_FailHolePunch_ZeroSessionID(t *testing.T) {
	hpc := createTestHolePunchCoordinator(t)

	err := hpc.FailHolePunch(0, assert.AnError)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "session ID cannot be zero")
}

func TestHolePunchCoordinator_FailHolePunch_SessionNotFound(t *testing.T) {
	hpc := createTestHolePunchCoordinator(t)

	err := hpc.FailHolePunch(99999, assert.AnError)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "hole punch session not found")
}

func TestHolePunchCoordinator_GetAttempt(t *testing.T) {
	hpc := createTestHolePunchCoordinator(t)

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 8887}
	introducerAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.2"), Port: 8888}
	relayTag := uint32(0x12345678)

	sessionID, err := hpc.InitiateHolePunch(remoteAddr, introducerAddr, relayTag)
	require.NoError(t, err)

	attempt := hpc.GetAttempt(sessionID)

	require.NotNil(t, attempt)
	assert.Equal(t, sessionID, attempt.SessionID)
	assert.Equal(t, remoteAddr.String(), attempt.RemoteAddr.String())
	assert.Equal(t, introducerAddr.String(), attempt.Introducer.String())
	assert.Equal(t, HolePunchRequested, attempt.State)
}

func TestHolePunchCoordinator_GetAttempt_ZeroSessionID(t *testing.T) {
	hpc := createTestHolePunchCoordinator(t)

	attempt := hpc.GetAttempt(0)

	assert.Nil(t, attempt)
}

func TestHolePunchCoordinator_GetAttempt_SessionNotFound(t *testing.T) {
	hpc := createTestHolePunchCoordinator(t)

	attempt := hpc.GetAttempt(99999)

	assert.Nil(t, attempt)
}

func TestHolePunchCoordinator_GetAttempt_DefensiveCopy(t *testing.T) {
	hpc := createTestHolePunchCoordinator(t)

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 8887}
	introducerAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.2"), Port: 8888}
	relayTag := uint32(0x12345678)

	sessionID, err := hpc.InitiateHolePunch(remoteAddr, introducerAddr, relayTag)
	require.NoError(t, err)

	attempt1 := hpc.GetAttempt(sessionID)
	require.NotNil(t, attempt1)

	// Modify returned value
	attempt1.State = HolePunchFailed
	attempt1.Retries = 999

	// Get again
	attempt2 := hpc.GetAttempt(sessionID)
	require.NotNil(t, attempt2)

	// Should be unchanged
	assert.Equal(t, HolePunchRequested, attempt2.State)
	assert.Equal(t, 0, attempt2.Retries)
}

func TestHolePunchCoordinator_RemoveAttempt(t *testing.T) {
	hpc := createTestHolePunchCoordinator(t)

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 8887}
	introducerAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.2"), Port: 8888}
	relayTag := uint32(0x12345678)

	sessionID, err := hpc.InitiateHolePunch(remoteAddr, introducerAddr, relayTag)
	require.NoError(t, err)

	// Verify exists
	assert.NotNil(t, hpc.GetAttempt(sessionID))

	// Remove
	hpc.RemoveAttempt(sessionID)

	// Verify removed
	assert.Nil(t, hpc.GetAttempt(sessionID))
}

func TestHolePunchCoordinator_RemoveAttempt_ZeroSessionID(t *testing.T) {
	hpc := createTestHolePunchCoordinator(t)

	// Should not panic
	hpc.RemoveAttempt(0)
}

func TestHolePunchCoordinator_RemoveAttempt_SessionNotFound(t *testing.T) {
	hpc := createTestHolePunchCoordinator(t)

	// Should not panic
	hpc.RemoveAttempt(99999)
}

func TestHolePunchCoordinator_CleanupExpired(t *testing.T) {
	hpc := createTestHolePunchCoordinator(t)

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 8887}
	introducerAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.2"), Port: 8888}
	relayTag := uint32(0x12345678)

	// Create attempt
	sessionID, err := hpc.InitiateHolePunch(remoteAddr, introducerAddr, relayTag)
	require.NoError(t, err)

	// Manually set start time to past (31 seconds ago)
	hpc.mutex.Lock()
	hpc.attempts[sessionID].StartTime = time.Now().Add(-31 * time.Second)
	hpc.mutex.Unlock()

	// Cleanup
	hpc.CleanupExpired()

	// Verify removed
	assert.Nil(t, hpc.GetAttempt(sessionID))
}

func TestHolePunchCoordinator_CleanupExpired_NotExpired(t *testing.T) {
	hpc := createTestHolePunchCoordinator(t)

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 8887}
	introducerAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.2"), Port: 8888}
	relayTag := uint32(0x12345678)

	// Create attempt
	sessionID, err := hpc.InitiateHolePunch(remoteAddr, introducerAddr, relayTag)
	require.NoError(t, err)

	// Cleanup (should not remove recent attempt)
	hpc.CleanupExpired()

	// Verify still exists
	assert.NotNil(t, hpc.GetAttempt(sessionID))
}

func TestHolePunchCoordinator_GetStats(t *testing.T) {
	hpc := createTestHolePunchCoordinator(t)

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 8887}
	introducerAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.2"), Port: 8888}

	// Create multiple attempts in different states
	_, err := hpc.InitiateHolePunch(remoteAddr, introducerAddr, uint32(0x12345671))
	require.NoError(t, err)

	sessionID2, err := hpc.InitiateHolePunch(remoteAddr, introducerAddr, uint32(0x12345672))
	require.NoError(t, err)
	err = hpc.SendHolePunch(sessionID2, remoteAddr)
	require.NoError(t, err)

	sessionID3, err := hpc.InitiateHolePunch(remoteAddr, introducerAddr, uint32(0x12345673))
	require.NoError(t, err)
	// Per BUG-001 fix: nil block must be rejected
	err = hpc.HandleHolePunch(sessionID3, remoteAddr, nil, nil)
	require.Error(t, err)
	// sessionID3 remains in requested state due to rejected nil block

	sessionID4, err := hpc.InitiateHolePunch(remoteAddr, introducerAddr, uint32(0x12345674))
	require.NoError(t, err)
	err = hpc.CompleteHolePunch(sessionID4)
	require.NoError(t, err)

	sessionID5, err := hpc.InitiateHolePunch(remoteAddr, introducerAddr, uint32(0x12345675))
	require.NoError(t, err)
	err = hpc.FailHolePunch(sessionID5, assert.AnError)
	require.NoError(t, err)

	// Get stats
	stats := hpc.GetStats()

	assert.Equal(t, 5, stats["total"])
	assert.Equal(t, 2, stats["requested"]) // sessionID1 and sessionID3 (rejected nil block)
	assert.Equal(t, 1, stats["sent"])      // sessionID2
	assert.Equal(t, 0, stats["waiting"])   // none (sessionID3 failed to reach waiting)
	assert.Equal(t, 1, stats["success"])   // sessionID4
	assert.Equal(t, 1, stats["failed"])    // sessionID5
}

func TestHolePunchCoordinator_GetStats_Empty(t *testing.T) {
	hpc := createTestHolePunchCoordinator(t)

	stats := hpc.GetStats()

	assert.Equal(t, 0, stats["total"])
	assert.Equal(t, 0, stats["requested"])
	assert.Equal(t, 0, stats["sent"])
	assert.Equal(t, 0, stats["waiting"])
	assert.Equal(t, 0, stats["success"])
	assert.Equal(t, 0, stats["failed"])
}

func TestHolePunchState_String(t *testing.T) {
	tests := []struct {
		state    HolePunchState
		expected string
	}{
		{HolePunchRequested, "Requested"},
		{HolePunchSent, "Sent"},
		{HolePunchWaiting, "Waiting"},
		{HolePunchSuccess, "Success"},
		{HolePunchFailed, "Failed"},
		{HolePunchState(999), "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.state.String())
		})
	}
}

func TestHolePunchCoordinator_ConcurrentOperations(t *testing.T) {
	hpc := createTestHolePunchCoordinator(t)

	const numGoroutines = 50

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	sessionIDs := make(chan uint64, numGoroutines)

	// Concurrent initiations
	for i := 0; i < numGoroutines; i++ {
		go func(index int) {
			defer wg.Done()

			remoteAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 8887 + index}
			introducerAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.2"), Port: 8888}
			relayTag := uint32(index + 1) // unique relay tag per goroutine

			sessionID, err := hpc.InitiateHolePunch(remoteAddr, introducerAddr, relayTag)
			if err == nil {
				sessionIDs <- sessionID
			}
		}(i)
	}

	wg.Wait()
	close(sessionIDs)

	// Verify all sessions were created
	count := 0
	for sessionID := range sessionIDs {
		assert.NotNil(t, hpc.GetAttempt(sessionID))
		count++
	}

	assert.Equal(t, numGoroutines, count)

	// Verify stats
	stats := hpc.GetStats()
	assert.Equal(t, numGoroutines, stats["total"])
}

func TestHolePunchCoordinator_HandleHolePunch_WithSignatureVerification(t *testing.T) {
	hpc := createTestHolePunchCoordinator(t)
	// BUG-M02 fix: Verifier is now set at construction via createTestHolePunchCoordinator

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 8887}
	introducerAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.2"), Port: 8888}
	relayTag := uint32(0xABCD1234)

	sessionID, err := hpc.InitiateHolePunch(remoteAddr, introducerAddr, relayTag)
	require.NoError(t, err)

	block := &RelayIntroBlock{
		AliceRouterHash: make([]byte, 32),
		Nonce:           relayTag,
		Signature:       make([]byte, 64),
	}
	fromAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.3"), Port: 8889}
	err = hpc.HandleHolePunch(sessionID, fromAddr, block, nil)
	require.NoError(t, err)

	attempt := hpc.GetAttempt(sessionID)
	require.NotNil(t, attempt)
	assert.Equal(t, HolePunchWaiting, attempt.State)
}

func TestHolePunchCoordinator_HandleHolePunch_SignatureVerificationFails(t *testing.T) {
	manager := NewRelayManager(nil)

	// BUG-M02 fix: Create coordinator with a verifier that rejects all signatures
	verifyFn := func(block *RelayIntroBlock, signerKey ed25519.PublicKey) error {
		return oops.
			Code("BAD_SIGNATURE").
			Errorf("invalid signature")
	}
	hpc, err := NewHolePunchCoordinator(manager, verifyFn)
	require.NoError(t, err)
	defer hpc.Stop()

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 8887}
	introducerAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.2"), Port: 8888}
	relayTag := uint32(0xABCD1234)

	sessionID, err := hpc.InitiateHolePunch(remoteAddr, introducerAddr, relayTag)
	require.NoError(t, err)

	block := &RelayIntroBlock{
		AliceRouterHash: make([]byte, 32),
		Nonce:           relayTag,
		Signature:       make([]byte, 64),
	}
	fromAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.3"), Port: 8889}
	err = hpc.HandleHolePunch(sessionID, fromAddr, block, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signature verification failed")
}

// BUG-M02 fix: TestHolePunchCoordinator_HandleHolePunch_VerifierNotConfigured removed
// because verifier is now mandatory at construction - this error case is impossible.
