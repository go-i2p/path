package ssu2path

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
	challengeData, err := pv.InitiatePathValidation(newAddr)
	require.NoError(t, err)
	assert.NotEmpty(t, challengeData)

	// Verify challenge was recorded
	challenge, exists := pv.GetChallenge(challengeData)
	require.True(t, exists)
	assert.Equal(t, challengeData, challenge.ChallengeData)
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

	challengeData, err := pv.InitiatePathValidation(nil)
	assert.Error(t, err)
	assert.Nil(t, challengeData)
	assert.Contains(t, err.Error(), "new address is nil")
}

// TestPathValidator_InitiatePathValidation_SendError tests send failure handling.
func TestPathValidator_InitiatePathValidation_SendError(t *testing.T) {
	conn := &mockPathValidationConn{
		sendToAddressError: assert.AnError,
	}
	pv := NewPathValidator(conn)

	newAddr := &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 8080}

	challengeData, err := pv.InitiatePathValidation(newAddr)
	assert.Error(t, err)
	assert.Nil(t, challengeData)

	// Challenge should be cleaned up on failure
	_, exists := pv.GetChallenge(challengeData)
	assert.False(t, exists)
}

// TestPathValidator_HandlePathChallenge tests receiving a challenge.
func TestPathValidator_HandlePathChallenge(t *testing.T) {
	conn := &mockPathValidationConn{}
	pv := NewPathValidator(conn)

	// Create a challenge block
	challengeData := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	block := EncodePathChallenge(challengeData)
	fromAddr := &net.UDPAddr{IP: net.ParseIP("10.0.0.50"), Port: 9090}

	// Handle the challenge
	err := pv.HandlePathChallenge(block, fromAddr)
	require.NoError(t, err)

	// Verify challenge was recorded
	challenge, exists := pv.GetChallenge(challengeData)
	require.True(t, exists)
	assert.Equal(t, challengeData, challenge.ChallengeData)
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

	challengeData := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	block := EncodePathChallenge(challengeData)

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
	challengeData, err := pv.InitiatePathValidation(newAddr)
	require.NoError(t, err)

	// Verify initial state
	challenge, exists := pv.GetChallenge(challengeData)
	require.True(t, exists)
	assert.Equal(t, ChallengeSent, challenge.State)

	conn.resetCalls()

	// Create and handle response
	responseBlock := EncodePathResponse(challengeData)
	err = pv.HandlePathResponse(responseBlock, newAddr)
	require.NoError(t, err)

	// Verify challenge was validated and removed (completed)
	_, exists = pv.GetChallenge(challengeData)
	assert.False(t, exists)

	// Verify remote address was updated
	assert.Equal(t, newAddr.String(), conn.GetRemoteAddr().String())
}

// TestPathValidator_HandlePathResponse_NoMatchingChallenge tests unknown challenge data.
func TestPathValidator_HandlePathResponse_NoMatchingChallenge(t *testing.T) {
	conn := &mockPathValidationConn{}
	pv := NewPathValidator(conn)

	// Create response for non-existent challenge
	challengeData := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	responseBlock := EncodePathResponse(challengeData)
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
	challengeData, err := pv.InitiatePathValidation(addrA)
	require.NoError(t, err)

	// Receive response from address B
	addrB := &net.UDPAddr{IP: net.ParseIP("10.0.0.50"), Port: 9090}
	responseBlock := EncodePathResponse(challengeData)
	err = pv.HandlePathResponse(responseBlock, addrB)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected address")

	// Challenge should still exist
	challenge, exists := pv.GetChallenge(challengeData)
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

	challengeData := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	responseBlock := EncodePathResponse(challengeData)

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
	challengeData := []byte{0x05, 0x04, 0x03, 0x02, 0x01, 0x00, 0x09, 0x08}
	pv.challenges[string(challengeData)] = &PathChallenge{
		ChallengeData: challengeData,
		NewAddr:       newAddr,
		Timestamp:     time.Now(),
		State:         ChallengeValidated,
	}

	// Validate the path
	err := pv.ValidatePath(challengeData)
	require.NoError(t, err)

	// Verify remote address was updated
	assert.Equal(t, newAddr.String(), conn.GetRemoteAddr().String())

	// Challenge should be cleaned up
	_, exists := pv.GetChallenge(challengeData)
	assert.False(t, exists)
}

// TestPathValidator_ValidatePath_NotValidated tests validating non-validated challenge.
func TestPathValidator_ValidatePath_NotValidated(t *testing.T) {
	conn := &mockPathValidationConn{}
	pv := NewPathValidator(conn)

	// Create a challenge that's not yet validated
	newAddr := &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 8080}
	challengeData := []byte{0x05, 0x04, 0x03, 0x02, 0x01, 0x00, 0x09, 0x08}
	pv.challenges[string(challengeData)] = &PathChallenge{
		ChallengeData: challengeData,
		NewAddr:       newAddr,
		Timestamp:     time.Now(),
		State:         ChallengeSent,
	}

	// Try to validate
	err := pv.ValidatePath(challengeData)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not validated")
}

// TestPathValidator_ValidatePath_NonExistent tests validating non-existent challenge.
func TestPathValidator_ValidatePath_NonExistent(t *testing.T) {
	conn := &mockPathValidationConn{}
	pv := NewPathValidator(conn)

	err := pv.ValidatePath([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
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
	challengeData := []byte{0x05, 0x04, 0x03, 0x02, 0x01, 0x00, 0x09, 0x08}
	pv.challenges[string(challengeData)] = &PathChallenge{
		ChallengeData: challengeData,
		NewAddr:       newAddr,
		Timestamp:     time.Now(),
		State:         ChallengeValidated,
	}

	// Try to validate
	err := pv.ValidatePath(challengeData)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to set remote address")

	// BUG-002 fix: Challenge is deleted before side effects to prevent TOCTOU race
	// When SetRemoteAddr fails, challenge is already gone (not marked as failed)
	_, exists := pv.GetChallenge(challengeData)
	require.False(t, exists)
}

// TestPathValidator_FailPath tests marking path validation as failed.
func TestPathValidator_FailPath(t *testing.T) {
	conn := &mockPathValidationConn{}
	pv := NewPathValidator(conn)

	// Create a challenge
	challengeData := []byte{0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11}
	pv.challenges[string(challengeData)] = &PathChallenge{
		ChallengeData: challengeData,
		NewAddr:       &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 8080},
		Timestamp:     time.Now(),
		State:         ChallengeSent,
	}

	// Fail the path
	pv.FailPath(challengeData, assert.AnError)

	// M-2 fix: FailPath now deletes the entry to prevent memory leaks.
	// The challenge should no longer exist after being failed.
	_, exists := pv.GetChallenge(challengeData)
	require.False(t, exists)
}

// TestPathValidator_FailPath_NonExistent tests failing non-existent challenge.
func TestPathValidator_FailPath_NonExistent(t *testing.T) {
	conn := &mockPathValidationConn{}
	pv := NewPathValidator(conn)

	// Should not panic
	pv.FailPath([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, assert.AnError)
}

// TestPathValidator_GetChallenge tests retrieving challenge info.
func TestPathValidator_GetChallenge(t *testing.T) {
	conn := &mockPathValidationConn{}
	pv := NewPathValidator(conn)

	// Create a challenge
	challengeData := []byte{0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22}
	originalAddr := &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 8080}
	pv.challenges[string(challengeData)] = &PathChallenge{
		ChallengeData: challengeData,
		NewAddr:       originalAddr,
		Timestamp:     time.Now(),
		State:         ChallengeSent,
	}

	// Get challenge
	challenge, exists := pv.GetChallenge(challengeData)
	require.True(t, exists)
	assert.Equal(t, challengeData, challenge.ChallengeData)
	assert.Equal(t, originalAddr.String(), challenge.NewAddr.String())
	assert.Equal(t, ChallengeSent, challenge.State)

	// Verify it's a defensive copy (mutation doesn't affect original)
	challenge.State = ChallengeFailed
	originalChallenge, _ := pv.GetChallenge(challengeData)
	assert.Equal(t, ChallengeSent, originalChallenge.State)
}

// TestPathValidator_GetChallenge_NonExistent tests getting non-existent challenge.
func TestPathValidator_GetChallenge_NonExistent(t *testing.T) {
	conn := &mockPathValidationConn{}
	pv := NewPathValidator(conn)

	challenge, exists := pv.GetChallenge([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
	assert.False(t, exists)
	assert.Nil(t, challenge)
}

// TestPathValidator_CleanupExpired tests cleanup of expired challenges.
func TestPathValidator_CleanupExpired(t *testing.T) {
	conn := &mockPathValidationConn{}
	pv := NewPathValidator(conn)

	now := time.Now()

	// Add expired challenge (older than timeout)
	expiredData := []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	pv.challenges[string(expiredData)] = &PathChallenge{
		ChallengeData: expiredData,
		NewAddr:       &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080},
		Timestamp:     now.Add(-PathValidationTimeout - time.Second),
		State:         ChallengeSent,
	}

	// Add recent challenge (within timeout, Path Response timer not yet expired)
	recentData := []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	pv.challenges[string(recentData)] = &PathChallenge{
		ChallengeData: recentData,
		NewAddr:       &net.UDPAddr{IP: net.ParseIP("192.168.1.2"), Port: 8080},
		Timestamp:     now.Add(-time.Second),
		LastSentAt:    now.Add(-time.Second),
		ResponseTimer: PathResponseBaseTimer,
		State:         ChallengeSent,
	}

	// Add validated challenge (should not be cleaned)
	validatedData := []byte{0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	pv.challenges[string(validatedData)] = &PathChallenge{
		ChallengeData: validatedData,
		NewAddr:       &net.UDPAddr{IP: net.ParseIP("192.168.1.3"), Port: 8080},
		Timestamp:     now.Add(-PathValidationTimeout - time.Second),
		State:         ChallengeValidated,
	}

	// Add failed challenge (should not be cleaned)
	failedData := []byte{0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	pv.challenges[string(failedData)] = &PathChallenge{
		ChallengeData: failedData,
		NewAddr:       &net.UDPAddr{IP: net.ParseIP("192.168.1.4"), Port: 8080},
		Timestamp:     now.Add(-PathValidationTimeout - time.Second),
		State:         ChallengeFailed,
	}

	// Run cleanup
	// M-1/M-2 fix: CleanupExpired now also removes terminal-state entries as a safety
	// net. All 3 non-recent entries (expired + validated + failed) are removed.
	cleaned := pv.CleanupExpired()
	assert.Equal(t, 3, cleaned)

	// Verify expired challenge was removed
	_, exists := pv.GetChallenge(expiredData)
	assert.False(t, exists)

	// Verify recent challenge still exists
	_, exists = pv.GetChallenge(recentData)
	assert.True(t, exists)

	// Terminal-state challenges are also removed by CleanupExpired (M-1/M-2 safety net).
	_, exists = pv.GetChallenge(validatedData)
	assert.False(t, exists)
	_, exists = pv.GetChallenge(failedData)
	assert.False(t, exists)
}

// TestPathValidator_CleanupExpired_Resend tests that a challenge whose Path
// Response timer expired (but whose Path Validation timer has not) is resent
// and its timer doubled, per the SSU2 spec.
func TestPathValidator_CleanupExpired_Resend(t *testing.T) {
	conn := &mockPathValidationConn{}
	pv := NewPathValidator(conn)

	now := time.Now()
	addr := &net.UDPAddr{IP: net.ParseIP("192.168.1.5"), Port: 8080}

	// Challenge sent 3s ago: Path Response timer (2s) expired, but Path
	// Validation timer (10s) has not.
	data := []byte{0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	pv.challenges[string(data)] = &PathChallenge{
		ChallengeData: data,
		NewAddr:       addr,
		Timestamp:     now.Add(-3 * time.Second),
		LastSentAt:    now.Add(-3 * time.Second),
		ResponseTimer: PathResponseBaseTimer,
		State:         ChallengeSent,
	}

	cleaned := pv.CleanupExpired()

	// Not removed (validation timer not expired)
	assert.Equal(t, 0, cleaned)

	// Challenge still exists, timer doubled, LastSentAt updated
	ch, exists := pv.GetChallenge(data)
	assert.True(t, exists)
	assert.Equal(t, PathResponseBaseTimer*2, ch.ResponseTimer)
	assert.WithinDuration(t, now, ch.LastSentAt, 2*time.Second)

	// A Path Challenge was resent to the new address
	assert.Equal(t, 1, len(conn.sentBlocks))
	assert.Equal(t, uint8(BlockTypePathChallenge), conn.sentBlocks[0].Type)
	assert.Equal(t, addr, conn.sentAddrs[0])
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
	challengeData := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}

	// Encode
	block := EncodePathChallenge(challengeData)
	require.NotNil(t, block)
	assert.Equal(t, BlockTypePathChallenge, block.Type)
	assert.Equal(t, 8, len(block.Data))

	// Decode
	decoded, err := DecodePathChallenge(block)
	require.NoError(t, err)
	assert.Equal(t, challengeData, decoded)
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

// TestEncodeDecodePathResponse tests Path Response encoding/decoding.
func TestEncodeDecodePathResponse(t *testing.T) {
	challengeData := []byte{0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}

	// Encode
	block := EncodePathResponse(challengeData)
	require.NotNil(t, block)
	assert.Equal(t, BlockTypePathResponse, block.Type)
	assert.Equal(t, 8, len(block.Data))

	// Decode
	decoded, err := DecodePathResponse(block)
	require.NoError(t, err)
	assert.Equal(t, challengeData, decoded)
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
// mockCongestionController records SetCWND calls for testing.
type mockCongestionController struct {
	mutex    sync.Mutex
	cwnd     int
	resetCnt int
}

func (m *mockCongestionController) Reset() {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.resetCnt++
}

func (m *mockCongestionController) SetCWND(cwnd int) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.cwnd = cwnd
}

func (m *mockCongestionController) getCWND() int {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	return m.cwnd
}

// TestPathValidator_ReduceCongestionForValidation verifies that entering the
// path validation phase reduces the congestion window to the minimum (1280),
// as required by the SSU2 spec (Connection Migration).
func TestPathValidator_ReduceCongestionForValidation(t *testing.T) {
	mockConn := &mockPathValidationConn{}
	pv := NewPathValidator(mockConn)
	defer pv.Stop()

	cc := &mockCongestionController{cwnd: 100000}
	pv.SetCongestionController(cc)

	newAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 12345}
	_, err := pv.InitiatePathValidation(newAddr)
	assert.NoError(t, err)

	// The congestion window must be reduced to the minimum (MinMTU = 1280).
	assert.Equal(t, MinMTU, cc.getCWND())
}

func TestPathValidator_CompleteFlow(t *testing.T) {
	conn := &mockPathValidationConn{}
	pv := NewPathValidator(conn)

	newAddr := &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 8080}

	// Step 1: Initiate validation
	challengeData, err := pv.InitiatePathValidation(newAddr)
	require.NoError(t, err)

	// Verify challenge sent
	challenge, exists := pv.GetChallenge(challengeData)
	require.True(t, exists)
	assert.Equal(t, ChallengeSent, challenge.State)

	// Step 2: Simulate receiving response
	responseBlock := EncodePathResponse(challengeData)
	err = pv.HandlePathResponse(responseBlock, newAddr)
	require.NoError(t, err)

	// Step 3: Verify migration completed
	assert.Equal(t, newAddr.String(), conn.GetRemoteAddr().String())

	// Challenge should be cleaned up
	_, exists = pv.GetChallenge(challengeData)
	assert.False(t, exists)
}

// TestGenerateChallengeData tests challenge data generation.
func TestGenerateChallengeData(t *testing.T) {
	// Generate multiple data values
	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id, err := generateChallengeData()
		require.NoError(t, err)
		assert.NotEmpty(t, id)

		// Should be unique
		assert.False(t, ids[string(id)], "duplicate challenge data generated")
		ids[string(id)] = true
	}
}

// TestRunPMTUD_H1Fix validates H-1: RunPMTUD must return a value > MinMTU when
// a probe is answered successfully.  The done channel is now copied by GetChallenge
// so waitForProbeResult can observe the completion signal.
func TestRunPMTUD_H1Fix(t *testing.T) {
	ctx := t.Context()

	conn := &mockPathValidationConn{}
	pv := NewPathValidator(conn)
	defer pv.Stop()

	addr := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 9000}

	// Intercept probes and answer them in a background goroutine.
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			conn.mutex.Lock()
			blocks := make([]*SSU2Block, len(conn.sentBlocks))
			addrs := make([]*net.UDPAddr, len(conn.sentAddrs))
			copy(blocks, conn.sentBlocks)
			copy(addrs, conn.sentAddrs)
			conn.sentBlocks = nil
			conn.sentAddrs = nil
			conn.mutex.Unlock()

			for i, b := range blocks {
				if b.Type == BlockTypePathChallenge {
					resp := EncodePathResponse(func() []byte {
						id, _ := DecodePathChallenge(b)
						return id
					}())
					_ = pv.HandlePathResponse(resp, addrs[i])
				}
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()

	mtu := pv.RunPMTUD(ctx, addr, MinMTU, 1400)
	// H-1 fix: with done channel properly copied, at least one probe should
	// succeed, so the result must be greater than MinMTU.
	assert.Greater(t, mtu, MinMTU, "H-1: RunPMTUD must return > MinMTU when probes succeed")
}

// TestHandlePathResponse_H2Fix validates H-2: sending two identical Path Response
// messages for the same challenge must not panic.
func TestHandlePathResponse_H2Fix(t *testing.T) {
	conn := &mockPathValidationConn{
		remoteAddr: &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 9000},
	}
	pv := NewPathValidator(conn)
	defer pv.Stop()

	addr := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 9000}
	challengeData, err := pv.InitiatePathValidation(addr)
	require.NoError(t, err)

	responseBlock := EncodePathResponse(challengeData)

	const goroutines = 10
	errs := make(chan error, goroutines)
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for range goroutines {
		go func() {
			defer wg.Done()
			errs <- pv.HandlePathResponse(responseBlock, addr)
		}()
	}

	// Must complete without panic.
	wg.Wait()
	close(errs)
}