package path

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockPathValidationConn implements PathValidationConn for testing.
type mockPathValidationConn struct {
	sendToAddressCalled int
	sendToAddressError  error
	sentBlocks          []*SSU2Block
	sentAddrs           []*net.UDPAddr
	remoteAddr          *net.UDPAddr
	setRemoteAddrError  error
	mutex               sync.Mutex
}

func (m *mockPathValidationConn) SendToAddress(block *SSU2Block, addr *net.UDPAddr) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.sendToAddressCalled++
	m.sentBlocks = append(m.sentBlocks, block)
	m.sentAddrs = append(m.sentAddrs, addr)
	return m.sendToAddressError
}

func (m *mockPathValidationConn) GetRemoteAddr() *net.UDPAddr {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	return m.remoteAddr
}

func (m *mockPathValidationConn) SetRemoteAddr(addr *net.UDPAddr) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	if m.setRemoteAddrError != nil {
		return m.setRemoteAddrError
	}
	m.remoteAddr = addr
	return nil
}

func (m *mockPathValidationConn) getLastSentBlock() *SSU2Block {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	if len(m.sentBlocks) == 0 {
		return nil
	}
	return m.sentBlocks[len(m.sentBlocks)-1]
}

func (m *mockPathValidationConn) getLastSentAddr() *net.UDPAddr {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	if len(m.sentAddrs) == 0 {
		return nil
	}
	return m.sentAddrs[len(m.sentAddrs)-1]
}

func (m *mockPathValidationConn) resetCalls() {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.sendToAddressCalled = 0
	m.sentBlocks = nil
	m.sentAddrs = nil
}

// TestNewPathValidator tests validator creation.
func TestNewPathValidator(t *testing.T) {
	conn := &mockPathValidationConn{}
	pv := NewPathValidator(conn)

	require.NotNil(t, pv)
	assert.NotNil(t, pv.conn)
	assert.NotNil(t, pv.challenges)
	assert.Equal(t, 0, len(pv.challenges))
}

// TestPathValidator_InitiatePathValidation tests initiating validation.
func TestPathValidator_InitiatePathValidation(t *testing.T) {
	conn := &mockPathValidationConn{}
	pv := NewPathValidator(conn)

	newAddr := &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 8080}

	// Initiate validation
	challengeID, err := pv.InitiatePathValidation(newAddr)
	require.NoError(t, err)
	assert.NotEqual(t, uint64(0), challengeID)

	// Verify challenge was recorded
	challenge, exists := pv.GetChallenge(challengeID)
	require.True(t, exists)
	assert.Equal(t, challengeID, challenge.ChallengeID)
	assert.Equal(t, newAddr.String(), challenge.NewAddr.String())
	assert.Equal(t, ChallengeSent, challenge.State)

	// Verify Path Challenge was sent
	assert.Equal(t, 1, conn.sendToAddressCalled)
	sentBlock := conn.getLastSentBlock()
	require.NotNil(t, sentBlock)
	assert.Equal(t, BlockTypePathChallenge, sentBlock.Type)
	assert.Equal(t, newAddr.String(), conn.getLastSentAddr().String())
}

// TestPathValidator_InitiatePathValidation_NilAddress tests nil address handling.
func TestPathValidator_InitiatePathValidation_NilAddress(t *testing.T) {
	conn := &mockPathValidationConn{}
	pv := NewPathValidator(conn)

	challengeID, err := pv.InitiatePathValidation(nil)
	assert.Error(t, err)
	assert.Equal(t, uint64(0), challengeID)
	assert.Contains(t, err.Error(), "new address is nil")
}

// TestPathValidator_InitiatePathValidation_SendError tests send failure handling.
func TestPathValidator_InitiatePathValidation_SendError(t *testing.T) {
	conn := &mockPathValidationConn{
		sendToAddressError: assert.AnError,
	}
	pv := NewPathValidator(conn)

	newAddr := &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 8080}

	challengeID, err := pv.InitiatePathValidation(newAddr)
	assert.Error(t, err)
	assert.Equal(t, uint64(0), challengeID)

	// Challenge should be cleaned up on failure
	_, exists := pv.GetChallenge(challengeID)
	assert.False(t, exists)
}

// TestPathValidator_HandlePathChallenge tests receiving a challenge.
func TestPathValidator_HandlePathChallenge(t *testing.T) {
	conn := &mockPathValidationConn{}
	pv := NewPathValidator(conn)

	// Create a challenge block
	challengeID := uint64(12345)
	block := EncodePathChallenge(challengeID)
	fromAddr := &net.UDPAddr{IP: net.ParseIP("10.0.0.50"), Port: 9090}

	// Handle the challenge
	err := pv.HandlePathChallenge(block, fromAddr)
	require.NoError(t, err)

	// Verify challenge was recorded
	challenge, exists := pv.GetChallenge(challengeID)
	require.True(t, exists)
	assert.Equal(t, challengeID, challenge.ChallengeID)
	assert.Equal(t, fromAddr.String(), challenge.NewAddr.String())
	assert.Equal(t, ChallengeReceived, challenge.State)

	// Verify Path Response was sent
	assert.Equal(t, 1, conn.sendToAddressCalled)
	sentBlock := conn.getLastSentBlock()
	require.NotNil(t, sentBlock)
	assert.Equal(t, BlockTypePathResponse, sentBlock.Type)
	assert.Equal(t, fromAddr.String(), conn.getLastSentAddr().String())
}

// TestPathValidator_HandlePathChallenge_NilBlock tests nil block handling.
func TestPathValidator_HandlePathChallenge_NilBlock(t *testing.T) {
	conn := &mockPathValidationConn{}
	pv := NewPathValidator(conn)

	fromAddr := &net.UDPAddr{IP: net.ParseIP("10.0.0.50"), Port: 9090}
	err := pv.HandlePathChallenge(nil, fromAddr)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "block is nil")
}

// TestPathValidator_HandlePathChallenge_NilAddress tests nil address handling.
func TestPathValidator_HandlePathChallenge_NilAddress(t *testing.T) {
	conn := &mockPathValidationConn{}
	pv := NewPathValidator(conn)

	challengeID := uint64(12345)
	block := EncodePathChallenge(challengeID)

	err := pv.HandlePathChallenge(block, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "fromAddr is nil")
}

// TestPathValidator_HandlePathResponse tests receiving a response.
func TestPathValidator_HandlePathResponse(t *testing.T) {
	conn := &mockPathValidationConn{}
	pv := NewPathValidator(conn)

	// First, initiate a challenge
	newAddr := &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 8080}
	challengeID, err := pv.InitiatePathValidation(newAddr)
	require.NoError(t, err)

	// Verify initial state
	challenge, exists := pv.GetChallenge(challengeID)
	require.True(t, exists)
	assert.Equal(t, ChallengeSent, challenge.State)

	conn.resetCalls()

	// Create and handle response
	responseBlock := EncodePathResponse(challengeID)
	err = pv.HandlePathResponse(responseBlock, newAddr)
	require.NoError(t, err)

	// Verify challenge was validated and removed (completed)
	_, exists = pv.GetChallenge(challengeID)
	assert.False(t, exists)

	// Verify remote address was updated
	assert.Equal(t, newAddr.String(), conn.GetRemoteAddr().String())
}

// TestPathValidator_HandlePathResponse_NoMatchingChallenge tests unknown challenge ID.
func TestPathValidator_HandlePathResponse_NoMatchingChallenge(t *testing.T) {
	conn := &mockPathValidationConn{}
	pv := NewPathValidator(conn)

	// Create response for non-existent challenge
	challengeID := uint64(99999)
	responseBlock := EncodePathResponse(challengeID)
	fromAddr := &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 8080}

	err := pv.HandlePathResponse(responseBlock, fromAddr)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no matching challenge")
}

// TestPathValidator_HandlePathResponse_WrongAddress tests response from wrong address.
func TestPathValidator_HandlePathResponse_WrongAddress(t *testing.T) {
	conn := &mockPathValidationConn{}
	pv := NewPathValidator(conn)

	// Initiate challenge to address A
	addrA := &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 8080}
	challengeID, err := pv.InitiatePathValidation(addrA)
	require.NoError(t, err)

	// Receive response from address B
	addrB := &net.UDPAddr{IP: net.ParseIP("10.0.0.50"), Port: 9090}
	responseBlock := EncodePathResponse(challengeID)
	err = pv.HandlePathResponse(responseBlock, addrB)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected address")

	// Challenge should still exist
	challenge, exists := pv.GetChallenge(challengeID)
	require.True(t, exists)
	assert.Equal(t, ChallengeSent, challenge.State)
}

// TestPathValidator_HandlePathResponse_NilBlock tests nil block handling.
func TestPathValidator_HandlePathResponse_NilBlock(t *testing.T) {
	conn := &mockPathValidationConn{}
	pv := NewPathValidator(conn)

	fromAddr := &net.UDPAddr{IP: net.ParseIP("10.0.0.50"), Port: 9090}
	err := pv.HandlePathResponse(nil, fromAddr)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "block is nil")
}

// TestPathValidator_HandlePathResponse_NilAddress tests nil address handling.
func TestPathValidator_HandlePathResponse_NilAddress(t *testing.T) {
	conn := &mockPathValidationConn{}
	pv := NewPathValidator(conn)

	challengeID := uint64(12345)
	responseBlock := EncodePathResponse(challengeID)

	err := pv.HandlePathResponse(responseBlock, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "fromAddr is nil")
}

// TestPathValidator_ValidatePath tests path validation completion.
func TestPathValidator_ValidatePath(t *testing.T) {
	conn := &mockPathValidationConn{}
	pv := NewPathValidator(conn)

	// Create a validated challenge
	newAddr := &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 8080}
	challengeID := uint64(54321)
	pv.challenges[challengeID] = &PathChallenge{
		ChallengeID: challengeID,
		NewAddr:     newAddr,
		Timestamp:   time.Now(),
		State:       ChallengeValidated,
	}

	// Validate the path
	err := pv.ValidatePath(challengeID)
	require.NoError(t, err)

	// Verify remote address was updated
	assert.Equal(t, newAddr.String(), conn.GetRemoteAddr().String())

	// Challenge should be cleaned up
	_, exists := pv.GetChallenge(challengeID)
	assert.False(t, exists)
}

// TestPathValidator_ValidatePath_NotValidated tests validating non-validated challenge.
func TestPathValidator_ValidatePath_NotValidated(t *testing.T) {
	conn := &mockPathValidationConn{}
	pv := NewPathValidator(conn)

	// Create a challenge that's not yet validated
	newAddr := &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 8080}
	challengeID := uint64(54321)
	pv.challenges[challengeID] = &PathChallenge{
		ChallengeID: challengeID,
		NewAddr:     newAddr,
		Timestamp:   time.Now(),
		State:       ChallengeSent,
	}

	// Try to validate
	err := pv.ValidatePath(challengeID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not validated")
}

// TestPathValidator_ValidatePath_NonExistent tests validating non-existent challenge.
func TestPathValidator_ValidatePath_NonExistent(t *testing.T) {
	conn := &mockPathValidationConn{}
	pv := NewPathValidator(conn)

	err := pv.ValidatePath(99999)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no challenge found")
}

// TestPathValidator_ValidatePath_SetAddrError tests handling SetRemoteAddr failure.
func TestPathValidator_ValidatePath_SetAddrError(t *testing.T) {
	conn := &mockPathValidationConn{
		setRemoteAddrError: assert.AnError,
	}
	pv := NewPathValidator(conn)

	// Create a validated challenge
	newAddr := &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 8080}
	challengeID := uint64(54321)
	pv.challenges[challengeID] = &PathChallenge{
		ChallengeID: challengeID,
		NewAddr:     newAddr,
		Timestamp:   time.Now(),
		State:       ChallengeValidated,
	}

	// Try to validate
	err := pv.ValidatePath(challengeID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to set remote address")

	// BUG-002 fix: Challenge is deleted before side effects to prevent TOCTOU race
	// When SetRemoteAddr fails, challenge is already gone (not marked as failed)
	_, exists := pv.GetChallenge(challengeID)
	require.False(t, exists)
}

// TestPathValidator_FailPath tests marking path validation as failed.
func TestPathValidator_FailPath(t *testing.T) {
	conn := &mockPathValidationConn{}
	pv := NewPathValidator(conn)

	// Create a challenge
	challengeID := uint64(11111)
	pv.challenges[challengeID] = &PathChallenge{
		ChallengeID: challengeID,
		NewAddr:     &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 8080},
		Timestamp:   time.Now(),
		State:       ChallengeSent,
	}

	// Fail the path
	pv.FailPath(challengeID, assert.AnError)

	// Verify state changed to failed
	challenge, exists := pv.GetChallenge(challengeID)
	require.True(t, exists)
	assert.Equal(t, ChallengeFailed, challenge.State)
}

// TestPathValidator_FailPath_NonExistent tests failing non-existent challenge.
func TestPathValidator_FailPath_NonExistent(t *testing.T) {
	conn := &mockPathValidationConn{}
	pv := NewPathValidator(conn)

	// Should not panic
	pv.FailPath(99999, assert.AnError)
}

// TestPathValidator_GetChallenge tests retrieving challenge info.
func TestPathValidator_GetChallenge(t *testing.T) {
	conn := &mockPathValidationConn{}
	pv := NewPathValidator(conn)

	// Create a challenge
	challengeID := uint64(22222)
	originalAddr := &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 8080}
	pv.challenges[challengeID] = &PathChallenge{
		ChallengeID: challengeID,
		NewAddr:     originalAddr,
		Timestamp:   time.Now(),
		State:       ChallengeSent,
	}

	// Get challenge
	challenge, exists := pv.GetChallenge(challengeID)
	require.True(t, exists)
	assert.Equal(t, challengeID, challenge.ChallengeID)
	assert.Equal(t, originalAddr.String(), challenge.NewAddr.String())
	assert.Equal(t, ChallengeSent, challenge.State)

	// Verify it's a defensive copy (mutation doesn't affect original)
	challenge.State = ChallengeFailed
	originalChallenge, _ := pv.GetChallenge(challengeID)
	assert.Equal(t, ChallengeSent, originalChallenge.State)
}

// TestPathValidator_GetChallenge_NonExistent tests getting non-existent challenge.
func TestPathValidator_GetChallenge_NonExistent(t *testing.T) {
	conn := &mockPathValidationConn{}
	pv := NewPathValidator(conn)

	challenge, exists := pv.GetChallenge(99999)
	assert.False(t, exists)
	assert.Nil(t, challenge)
}

// TestPathValidator_CleanupExpired tests cleanup of expired challenges.
func TestPathValidator_CleanupExpired(t *testing.T) {
	conn := &mockPathValidationConn{}
	pv := NewPathValidator(conn)

	now := time.Now()

	// Add expired challenge (older than timeout)
	expiredID := uint64(1)
	pv.challenges[expiredID] = &PathChallenge{
		ChallengeID: expiredID,
		NewAddr:     &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080},
		Timestamp:   now.Add(-PathValidationTimeout - time.Second),
		State:       ChallengeSent,
	}

	// Add recent challenge (within timeout)
	recentID := uint64(2)
	pv.challenges[recentID] = &PathChallenge{
		ChallengeID: recentID,
		NewAddr:     &net.UDPAddr{IP: net.ParseIP("192.168.1.2"), Port: 8080},
		Timestamp:   now.Add(-time.Second),
		State:       ChallengeSent,
	}

	// Add validated challenge (should not be cleaned)
	validatedID := uint64(3)
	pv.challenges[validatedID] = &PathChallenge{
		ChallengeID: validatedID,
		NewAddr:     &net.UDPAddr{IP: net.ParseIP("192.168.1.3"), Port: 8080},
		Timestamp:   now.Add(-PathValidationTimeout - time.Second),
		State:       ChallengeValidated,
	}

	// Add failed challenge (should not be cleaned)
	failedID := uint64(4)
	pv.challenges[failedID] = &PathChallenge{
		ChallengeID: failedID,
		NewAddr:     &net.UDPAddr{IP: net.ParseIP("192.168.1.4"), Port: 8080},
		Timestamp:   now.Add(-PathValidationTimeout - time.Second),
		State:       ChallengeFailed,
	}

	// Run cleanup
	cleaned := pv.CleanupExpired()
	assert.Equal(t, 1, cleaned)

	// Verify expired challenge was removed
	_, exists := pv.GetChallenge(expiredID)
	assert.False(t, exists)

	// Verify recent challenge still exists
	_, exists = pv.GetChallenge(recentID)
	assert.True(t, exists)

	// Verify terminal state challenges still exist
	_, exists = pv.GetChallenge(validatedID)
	assert.True(t, exists)
	_, exists = pv.GetChallenge(failedID)
	assert.True(t, exists)
}

// TestPathValidator_CleanupExpired_Empty tests cleanup with no challenges.
func TestPathValidator_CleanupExpired_Empty(t *testing.T) {
	conn := &mockPathValidationConn{}
	pv := NewPathValidator(conn)

	cleaned := pv.CleanupExpired()
	assert.Equal(t, 0, cleaned)
}

// TestEncodeDecodePathChallenge tests Path Challenge encoding/decoding.
func TestEncodeDecodePathChallenge(t *testing.T) {
	challengeID := uint64(0x0123456789ABCDEF)

	// Encode
	block := EncodePathChallenge(challengeID)
	require.NotNil(t, block)
	assert.Equal(t, BlockTypePathChallenge, block.Type)
	assert.Equal(t, 8, len(block.Data))

	// Decode
	decoded, err := DecodePathChallenge(block)
	require.NoError(t, err)
	assert.Equal(t, challengeID, decoded)
}

// TestDecodePathChallenge_NilBlock tests nil block handling.
func TestDecodePathChallenge_NilBlock(t *testing.T) {
	_, err := DecodePathChallenge(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "block is nil")
}

// TestDecodePathChallenge_WrongType tests wrong block type handling.
func TestDecodePathChallenge_WrongType(t *testing.T) {
	block := &SSU2Block{
		Type: BlockTypePathResponse, // Wrong type
		Data: make([]byte, 8),
	}

	_, err := DecodePathChallenge(block)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid block type")
}

// TestDecodePathChallenge_TooShort tests short data handling.
func TestDecodePathChallenge_TooShort(t *testing.T) {
	block := &SSU2Block{
		Type: BlockTypePathChallenge,
		Data: make([]byte, 7), // Too short
	}

	_, err := DecodePathChallenge(block)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}

// TestEncodeDecodePathResponse tests Path Response encoding/decoding.
func TestEncodeDecodePathResponse(t *testing.T) {
	challengeID := uint64(0xFEDCBA9876543210)

	// Encode
	block := EncodePathResponse(challengeID)
	require.NotNil(t, block)
	assert.Equal(t, BlockTypePathResponse, block.Type)
	assert.Equal(t, 8, len(block.Data))

	// Decode
	decoded, err := DecodePathResponse(block)
	require.NoError(t, err)
	assert.Equal(t, challengeID, decoded)
}

// TestDecodePathResponse_NilBlock tests nil block handling.
func TestDecodePathResponse_NilBlock(t *testing.T) {
	_, err := DecodePathResponse(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "block is nil")
}

// TestDecodePathResponse_WrongType tests wrong block type handling.
func TestDecodePathResponse_WrongType(t *testing.T) {
	block := &SSU2Block{
		Type: BlockTypePathChallenge, // Wrong type
		Data: make([]byte, 8),
	}

	_, err := DecodePathResponse(block)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid block type")
}

// TestDecodePathResponse_TooShort tests short data handling.
func TestDecodePathResponse_TooShort(t *testing.T) {
	block := &SSU2Block{
		Type: BlockTypePathResponse,
		Data: make([]byte, 7), // Too short
	}

	_, err := DecodePathResponse(block)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}

// TestPathChallengeState_String tests string representation.
func TestPathChallengeState_String(t *testing.T) {
	assert.Equal(t, "ChallengeSent", ChallengeSent.String())
	assert.Equal(t, "ChallengeReceived", ChallengeReceived.String())
	assert.Equal(t, "ChallengeValidated", ChallengeValidated.String())
	assert.Equal(t, "ChallengeFailed", ChallengeFailed.String())
	assert.Equal(t, "Unknown", PathChallengeState(99).String())
}

// TestPathValidator_ConcurrentOperations tests thread safety.
func TestPathValidator_ConcurrentOperations(t *testing.T) {
	conn := &mockPathValidationConn{}
	pv := NewPathValidator(conn)

	const numGoroutines = 10
	var wg sync.WaitGroup
	wg.Add(numGoroutines * 2)

	// Concurrent initiations
	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			addr := &net.UDPAddr{
				IP:   net.ParseIP("192.168.1.100"),
				Port: 8080 + idx,
			}
			_, _ = pv.InitiatePathValidation(addr)
		}(i)
	}

	// Concurrent cleanup
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			_ = pv.CleanupExpired()
		}()
	}

	wg.Wait()
	// Should not panic
}

// TestPathValidator_CompleteFlow tests end-to-end validation flow.
func TestPathValidator_CompleteFlow(t *testing.T) {
	conn := &mockPathValidationConn{}
	pv := NewPathValidator(conn)

	newAddr := &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 8080}

	// Step 1: Initiate validation
	challengeID, err := pv.InitiatePathValidation(newAddr)
	require.NoError(t, err)

	// Verify challenge sent
	challenge, exists := pv.GetChallenge(challengeID)
	require.True(t, exists)
	assert.Equal(t, ChallengeSent, challenge.State)

	// Step 2: Simulate receiving response
	responseBlock := EncodePathResponse(challengeID)
	err = pv.HandlePathResponse(responseBlock, newAddr)
	require.NoError(t, err)

	// Step 3: Verify migration completed
	assert.Equal(t, newAddr.String(), conn.GetRemoteAddr().String())

	// Challenge should be cleaned up
	_, exists = pv.GetChallenge(challengeID)
	assert.False(t, exists)
}

// TestGenerateChallengeID tests challenge ID generation.
func TestGenerateChallengeID(t *testing.T) {
	// Generate multiple IDs
	ids := make(map[uint64]bool)
	for i := 0; i < 100; i++ {
		id, err := generateChallengeID()
		require.NoError(t, err)
		assert.NotEqual(t, uint64(0), id)

		// Should be unique
		assert.False(t, ids[id], "duplicate challenge ID generated")
		ids[id] = true
	}
}
