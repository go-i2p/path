package ssu2path

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"net"
	"sync"
	"time"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// PendingSessionRegistry is the relay dependency of HolePunchCoordinator.
// *RelayManager satisfies this interface.
type PendingSessionRegistry interface {
	AddPendingSession(sessionID uint64, remoteAddr, introducerAddr *net.UDPAddr, relayTag uint32) error
	IncrementRetries(sessionID uint64) int
	RemovePendingSession(sessionID uint64)
}

// HolePunchCoordinator coordinates UDP hole punching for NAT traversal.
// It manages hole punch attempts with state tracking, retries, and timeout handling.
//
// The HolePunch message (type 11) uses the same wire format as RelayIntro:
//
//	[Flag:1][SenderHash:32][Nonce:4][RelayTag:4][Timestamp:4][Ver:1][Asz:1][Port:2][IP:asz-2]
//
// See RelayIntroBlock in relay_blocks.go for the encoder/decoder.
//
// Design rationale:
// - Session IDs are cryptographically random 64-bit values for security
// - Maximum 3 retry attempts per I2P convention
// - 30-second timeout per attempt (I2P spec recommendation)
// - State machine: Requested → Sent → Waiting → Success/Failed
// - Signature verification is MANDATORY per SSU2 spec and must be provided at construction
//
// Thread Safety: All public methods are thread-safe.
type HolePunchCoordinator struct {
	// manager is the pending session registry (typically *RelayManager)
	manager PendingSessionRegistry

	// attempts maps session ID to hole punch attempt
	attempts map[uint64]*HolePunchAttempt

	// verifyHolePunchSignatureFn is called to verify incoming HolePunch messages.
	// Per SSU2 spec §Hole Punch, messages transiting through a relay MUST be
	// authenticated cryptographically. This field is set at construction and
	// is immutable to prevent misconfiguration.
	verifyHolePunchSignatureFn func(block *RelayIntroBlock, signerKey ed25519.PublicKey) error

	// stopCh is closed by Stop() to signal the cleanup goroutine to exit.
	stopCh chan struct{}

	// stopOnce ensures Stop() is idempotent and cannot panic on double-call.
	stopOnce sync.Once

	// mutex protects all fields
	mutex sync.RWMutex
}

// HolePunchAttempt represents an active hole punch operation.
type HolePunchAttempt struct {
	// SessionID uniquely identifies this attempt
	SessionID uint64

	// RemoteAddr is the target peer's UDP address
	RemoteAddr *net.UDPAddr

	// Introducer is the introducer facilitating the hole punch
	Introducer *net.UDPAddr

	// State is the current state of the attempt
	State HolePunchState

	// StartTime is when the attempt was initiated
	StartTime time.Time

	// Retries is the number of retry attempts made
	Retries int

	// RelayTag is the tag for relay communication
	RelayTag uint32

	// FailureReason stores the error passed to FailHolePunch (H-03 fix).
	// Nil if the attempt succeeded or has not yet failed.
	FailureReason error
}

// HolePunchState represents the state of a hole punch attempt.
type HolePunchState int

const (
	// HolePunchRequested indicates hole punch has been requested
	HolePunchRequested HolePunchState = iota

	// HolePunchSent indicates hole punch packet has been sent
	HolePunchSent

	// HolePunchWaiting indicates waiting for response
	HolePunchWaiting

	// HolePunchSuccess indicates hole punch succeeded
	HolePunchSuccess

	// HolePunchFailed indicates hole punch failed
	HolePunchFailed
)

// String returns human-readable state name.
func (s HolePunchState) String() string {
	switch s {
	case HolePunchRequested:
		return "Requested"
	case HolePunchSent:
		return "Sent"
	case HolePunchWaiting:
		return "Waiting"
	case HolePunchSuccess:
		return "Success"
	case HolePunchFailed:
		return "Failed"
	default:
		return "Unknown"
	}
}

// NewHolePunchCoordinator creates a new HolePunchCoordinator.
//
// L-3 fix: Returns an error instead of panicking on nil verifyFn, following
// Go constructor conventions. Per SSU2 spec §Hole Punch, all messages must be
// cryptographically authenticated, so a nil verifier is a programming error.
//
// Parameters:
//   - manager: The PendingSessionRegistry to coordinate with (typically *RelayManager)
//   - verifyFn: Function to verify HolePunch message signatures (MUST NOT be nil)
//
// Returns a new HolePunchCoordinator, or an error if verifyFn is nil.
func NewHolePunchCoordinator(manager PendingSessionRegistry, verifyFn func(block *RelayIntroBlock, signerKey ed25519.PublicKey) error) (*HolePunchCoordinator, error) {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "NewHolePunchCoordinator"}).Debug("Creating new HolePunchCoordinator")
	if verifyFn == nil {
		return nil, oops.Errorf("hole punch signature verifier cannot be nil - required by SSU2 spec")
	}
	hpc := &HolePunchCoordinator{
		manager:                    manager,
		attempts:                   make(map[uint64]*HolePunchAttempt),
		verifyHolePunchSignatureFn: verifyFn,
		stopCh:                     make(chan struct{}),
	}
	go hpc.cleanupLoop()
	return hpc, nil
}

// Stop halts the background cleanup goroutine. Call when the coordinator
// is no longer needed to avoid goroutine leaks. Safe to call multiple times.
func (hpc *HolePunchCoordinator) Stop() {
	hpc.stopOnce.Do(func() { close(hpc.stopCh) })
}

// cleanupLoop periodically removes expired hole punch attempts.
// BUG-L04: 30-second interval matches I2P SSU2 spec §Hole Punch timeout.
// Each attempt expires after 30s, so cleanup runs at same frequency.
func (hpc *HolePunchCoordinator) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			hpc.CleanupExpired()
		case <-hpc.stopCh:
			return
		}
	}
}

// InitiateHolePunch starts a new hole punch attempt to reach a remote peer.
//
// Design rationale:
// - Uses introducer to coordinate hole punch with target peer
// - Generates cryptographically random session ID
// - Registers pending session with RelayManager
// - 30-second timeout per I2P spec
//
// Parameters:
//   - remoteAddr: Target peer's UDP address
//   - introducerAddr: Introducer's UDP address
//   - relayTag: Tag for relay communication
//
// Returns session ID on success, error otherwise.
func (hpc *HolePunchCoordinator) InitiateHolePunch(remoteAddr, introducerAddr *net.UDPAddr, relayTag uint32) (uint64, error) {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "InitiateHolePunch", "relayTag": relayTag}).Debug("Initiating hole punch")
	if remoteAddr == nil {
		return 0, oops.
			Code("INVALID_ADDRESS").
			In("holepunch_coordinator").
			Errorf("remote address cannot be nil")
	}

	// BUG-L01 fix: Validate remote address port
	if !IsValidSourcePort(remoteAddr) {
		return 0, oops.
			Code("INVALID_PORT").
			In("holepunch_coordinator").
			With("port", remoteAddr.Port).
			Errorf("remote address has invalid source port %d", remoteAddr.Port)
	}

	if introducerAddr == nil {
		return 0, oops.
			Code("INVALID_ADDRESS").
			In("holepunch_coordinator").
			Errorf("introducer address cannot be nil")
	}

	// BUG-L01 fix: Validate introducer address port
	if !IsValidSourcePort(introducerAddr) {
		return 0, oops.
			Code("INVALID_PORT").
			In("holepunch_coordinator").
			With("port", introducerAddr.Port).
			Errorf("introducer address has invalid source port %d", introducerAddr.Port)
	}

	if relayTag == 0 {
		return 0, oops.
			Code("INVALID_RELAY_TAG").
			In("holepunch_coordinator").
			Errorf("relay tag cannot be zero")
	}

	// Generate a cryptographically random session ID.
	// H-04 fix: retry on collision, consistent with InitiatePeerTest.
	const maxSessionIDRetries = 10
	var destConnID uint64
	hpc.mutex.Lock()
	defer hpc.mutex.Unlock()

	for attempt := 0; attempt < maxSessionIDRetries; attempt++ {
		var sessionIDBuf [8]byte
		if _, err := rand.Read(sessionIDBuf[:]); err != nil {
			return 0, oops.
				Code("SESSION_ID_GENERATION_FAILED").
				In("holepunch_coordinator").
				Wrapf(err, "failed to generate session ID")
		}
		id := binary.BigEndian.Uint64(sessionIDBuf[:])
		if id == 0 {
			continue // retry; probability 1/2^64 per attempt
		}
		if _, exists := hpc.attempts[id]; !exists {
			destConnID = id
			break
		}
	}
	if destConnID == 0 {
		return 0, oops.
			Code("SESSION_ID_EXHAUSTED").
			In("holepunch_coordinator").
			With("max_attempts", maxSessionIDRetries).
			Errorf("failed to generate unique session ID after %d attempts", maxSessionIDRetries)
	}

	// Create attempt
	attempt := &HolePunchAttempt{
		SessionID:  destConnID,
		RemoteAddr: remoteAddr,
		Introducer: introducerAddr,
		State:      HolePunchRequested,
		StartTime:  time.Now(),
		Retries:    0,
		RelayTag:   relayTag,
	}

	hpc.attempts[destConnID] = attempt

	// Register with relay manager
	if err := hpc.manager.AddPendingSession(destConnID, remoteAddr, introducerAddr, relayTag); err != nil {
		delete(hpc.attempts, destConnID)
		return 0, oops.
			Code("PENDING_SESSION_FAILED").
			In("holepunch_coordinator").
			With("session_id", destConnID).
			Wrapf(err, "failed to register pending session")
	}

	return destConnID, nil
}

// lookupAttempt validates inputs and returns the attempt under lock.
// Caller must hold hpc.mutex. If addr is nil, the address check is skipped.
func (hpc *HolePunchCoordinator) lookupAttempt(sessionID uint64, addr *net.UDPAddr, addrLabel string) (*HolePunchAttempt, error) {
	if sessionID == 0 {
		return nil, oops.
			Code("INVALID_SESSION_ID").
			In("holepunch_coordinator").
			Errorf("session ID cannot be zero")
	}

	if addr == nil && addrLabel != "" {
		return nil, oops.
			Code("INVALID_ADDRESS").
			In("holepunch_coordinator").
			Errorf("%s address cannot be nil", addrLabel)
	}

	// BUG-L01 fix: Validate port if address is non-nil
	if addr != nil && !IsValidSourcePort(addr) {
		return nil, oops.
			Code("INVALID_PORT").
			In("holepunch_coordinator").
			With("port", addr.Port).
			With("label", addrLabel).
			Errorf("%s address has invalid source port %d", addrLabel, addr.Port)
	}

	attempt, exists := hpc.attempts[sessionID]
	if !exists {
		return nil, oops.
			Code("SESSION_NOT_FOUND").
			In("holepunch_coordinator").
			With("session_id", sessionID).
			Errorf("hole punch session not found")
	}

	return attempt, nil
}

// SendHolePunch sends a hole punch packet to the target address.
//
// Parameters:
//   - sessionID: Session identifier
//   - targetAddr: Target peer's UDP address
//
// Returns error if session not found or send fails.
func (hpc *HolePunchCoordinator) SendHolePunch(sessionID uint64, targetAddr *net.UDPAddr) error {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "SendHolePunch", "sessionID": sessionID}).Debug("Sending hole punch packet")
	hpc.mutex.Lock()
	defer hpc.mutex.Unlock()

	attempt, err := hpc.lookupAttempt(sessionID, targetAddr, "target")
	if err != nil {
		return err
	}

	attempt.State = HolePunchSent
	return nil
}

// verifyHolePunchSignatureInternal validates the block signature using the
// configured verifier. Per SSU2 spec §Hole Punch, signatures are mandatory.
// The verifier function is guaranteed to be non-nil (checked at construction).
func (hpc *HolePunchCoordinator) verifyHolePunchSignature(sessionID uint64, block *RelayIntroBlock, signerKey ed25519.PublicKey) error {
	if block == nil {
		log.WithFields(logger.Fields{
			"pkg":        "ssu2",
			"func":       "verifyHolePunchSignature",
			"session_id": sessionID,
		}).Warn("Rejecting hole punch with nil block - signature verification required")
		return oops.
			Code("MISSING_BLOCK").
			In("holepunch_coordinator").
			With("session_id", sessionID).
			Errorf("hole punch block cannot be nil - signature verification required per SSU2 spec")
	}
	// BUG-M02 fix: verifier is guaranteed non-nil at construction, no need to check
	if err := hpc.verifyHolePunchSignatureFn(block, signerKey); err != nil {
		return oops.
			Code("SIGNATURE_VERIFICATION_FAILED").
			In("holepunch_coordinator").
			With("session_id", sessionID).
			Wrapf(err, "hole punch signature verification failed")
	}
	return nil
}

// HandleHolePunch processes an incoming hole punch packet from a remote peer.
// Per SSU2 spec §Hole Punch, the message's signature MUST be verified before
// processing. The block parameter MUST NOT be nil - signature verification is
// mandatory per the SSU2 specification. If VerifyHolePunchSignature is not set,
// the message is rejected to prevent unauthenticated state transitions.
//
// Parameters:
//   - sessionID: Session identifier from the packet
//   - fromAddr: Address the packet came from
//   - block: The decoded RelayIntro-format block (MUST NOT be nil)
//   - signerKey: Ed25519 public key of the message signer
//
// Returns error if session not found, block is nil, or signature verification fails.
// BUG-M03 fix: Clarified that block parameter cannot be nil.
func (hpc *HolePunchCoordinator) HandleHolePunch(sessionID uint64, fromAddr *net.UDPAddr, block *RelayIntroBlock, signerKey ed25519.PublicKey) error {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "HandleHolePunch", "sessionID": sessionID}).Debug("Handling hole punch")
	hpc.mutex.Lock()
	defer hpc.mutex.Unlock()

	attempt, err := hpc.lookupAttempt(sessionID, fromAddr, "from")
	if err != nil {
		return err
	}

	if err := hpc.verifyHolePunchSignature(sessionID, block, signerKey); err != nil {
		return err
	}

	attempt.State = HolePunchWaiting
	return nil
}

// ProcessHolePunchResponse processes a response to a hole punch attempt.
// Per SSU2 spec §Hole Punch, the response's signature MUST be verified.
// The block parameter MUST NOT be nil - signature verification is mandatory.
//
// Parameters:
//   - sessionID: Session identifier
//   - addr: Address that responded
//   - block: The decoded RelayIntro-format block (MUST NOT be nil)
//   - signerKey: Ed25519 public key of the message signer
//
// Returns error if session not found, block is nil, or signature verification fails.
// BUG-M03 fix: Clarified that block parameter cannot be nil.
func (hpc *HolePunchCoordinator) ProcessHolePunchResponse(sessionID uint64, addr *net.UDPAddr, block *RelayIntroBlock, signerKey ed25519.PublicKey) error {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "ProcessHolePunchResponse", "sessionID": sessionID}).Debug("Processing hole punch response")
	hpc.mutex.Lock()
	defer hpc.mutex.Unlock()

	attempt, err := hpc.lookupAttempt(sessionID, addr, "response")
	if err != nil {
		return err
	}

	if err := hpc.verifyHolePunchSignature(sessionID, block, signerKey); err != nil {
		return err
	}

	// Verify address matches expected remote (M-01 fix: use addrEqual for IPv4/IPv6 parity)
	if !addrEqual(attempt.RemoteAddr, addr) {
		return oops.
			Code("ADDRESS_MISMATCH").
			In("holepunch_coordinator").
			With("session_id", sessionID).
			With("expected", attempt.RemoteAddr.String()).
			With("actual", addr.String()).
			Errorf("response address does not match expected remote")
	}

	// Mark as successful
	attempt.State = HolePunchSuccess

	return nil
}

// validateAndGetAttempt validates a session ID and returns the attempt.
// Caller must hold hpc.mutex.
func (hpc *HolePunchCoordinator) validateAndGetAttempt(sessionID uint64) (*HolePunchAttempt, error) {
	return hpc.lookupAttempt(sessionID, nil, "")
}

// RetryHolePunch retries a failed hole punch attempt.
//
// Parameters:
//   - sessionID: Session identifier
//
// Returns error if session not found or max retries exceeded.
func (hpc *HolePunchCoordinator) RetryHolePunch(sessionID uint64) error {
	hpc.mutex.Lock()
	defer hpc.mutex.Unlock()

	attempt, err := hpc.validateAndGetAttempt(sessionID)
	if err != nil {
		return err
	}

	// Check max retries (3 per I2P convention)
	if attempt.Retries >= 3 {
		attempt.State = HolePunchFailed
		return oops.
			Code("MAX_RETRIES_EXCEEDED").
			In("holepunch_coordinator").
			With("session_id", sessionID).
			With("retries", attempt.Retries).
			Errorf("maximum retry attempts exceeded")
	}

	// Increment retry count
	attempt.Retries++

	// Increment in relay manager too
	hpc.manager.IncrementRetries(sessionID)

	// Reset state to requested
	attempt.State = HolePunchRequested

	return nil
}

// setAttemptState is a helper that validates and sets the state of a hole punch attempt.
// BUG-010 fix: Extract common code from CompleteHolePunch/FailHolePunch
func (hpc *HolePunchCoordinator) setAttemptState(sessionID uint64, state HolePunchState) error {
	hpc.mutex.Lock()
	defer hpc.mutex.Unlock()

	attempt, err := hpc.validateAndGetAttempt(sessionID)
	if err != nil {
		return err
	}

	attempt.State = state
	return nil
}

// CompleteHolePunch marks a hole punch attempt as successfully completed.
//
// Parameters:
//   - sessionID: Session identifier
//
// Returns error if session not found.
func (hpc *HolePunchCoordinator) CompleteHolePunch(sessionID uint64) error {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "CompleteHolePunch", "sessionID": sessionID}).Debug("Completing hole punch")
	return hpc.setAttemptState(sessionID, HolePunchSuccess)
}

// FailHolePunch marks a hole punch attempt as failed with a reason.
//
// Parameters:
//   - sessionID: Session identifier
//   - reason: Error explaining failure
//
// Returns error if session not found.
func (hpc *HolePunchCoordinator) FailHolePunch(sessionID uint64, reason error) error {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "FailHolePunch", "sessionID": sessionID, "reason": reason}).Debug("Failing hole punch")
	hpc.mutex.Lock()
	defer hpc.mutex.Unlock()

	attempt, err := hpc.validateAndGetAttempt(sessionID)
	if err != nil {
		return err
	}

	// H-03 fix: persist the reason so callers can inspect it via GetAttempt.
	attempt.State = HolePunchFailed
	attempt.FailureReason = reason
	return nil
}

// GetAttempt retrieves hole punch attempt information.
//
// Parameters:
//   - sessionID: Session identifier
//
// Returns attempt info, or nil if not found.
func (hpc *HolePunchCoordinator) GetAttempt(sessionID uint64) *HolePunchAttempt {
	if sessionID == 0 {
		return nil
	}

	hpc.mutex.RLock()
	defer hpc.mutex.RUnlock()

	attempt, exists := hpc.attempts[sessionID]
	if !exists {
		return nil
	}

	// Return defensive copy — H-02 fix: deep-copy pointer fields to prevent
	// callers from mutating internal state without holding the mutex.
	c := &HolePunchAttempt{
		SessionID:     attempt.SessionID,
		State:         attempt.State,
		StartTime:     attempt.StartTime,
		Retries:       attempt.Retries,
		RelayTag:      attempt.RelayTag,
		FailureReason: attempt.FailureReason, // H-03 fix: copy reason
	}
	if attempt.RemoteAddr != nil {
		a := *attempt.RemoteAddr
		c.RemoteAddr = &a
	}
	if attempt.Introducer != nil {
		a := *attempt.Introducer
		c.Introducer = &a
	}
	return c
}

// RemoveAttempt removes a hole punch attempt from tracking.
//
// Parameters:
//   - sessionID: Session identifier
func (hpc *HolePunchCoordinator) RemoveAttempt(sessionID uint64) {
	if sessionID == 0 {
		return
	}

	hpc.mutex.Lock()
	defer hpc.mutex.Unlock()

	delete(hpc.attempts, sessionID)

	// Remove from relay manager too
	hpc.manager.RemovePendingSession(sessionID)
}

// CleanupExpired removes expired hole punch attempts.
// Attempts are considered expired after 30 seconds per I2P spec.
func (hpc *HolePunchCoordinator) CleanupExpired() {
	hpc.mutex.Lock()
	defer hpc.mutex.Unlock()

	now := time.Now()

	for sessionID, attempt := range hpc.attempts {
		if now.Sub(attempt.StartTime) > HolePunchSessionTimeout {
			delete(hpc.attempts, sessionID)
			hpc.manager.RemovePendingSession(sessionID)
		}
	}
}

// GetStats returns statistics about active hole punch attempts.
//
// Returns a map with attempt counts by state.
func (hpc *HolePunchCoordinator) GetStats() map[string]int {
	hpc.mutex.RLock()
	defer hpc.mutex.RUnlock()

	stats := map[string]int{
		"total":     len(hpc.attempts),
		"requested": 0,
		"sent":      0,
		"waiting":   0,
		"success":   0,
		"failed":    0,
	}

	for _, attempt := range hpc.attempts {
		switch attempt.State {
		case HolePunchRequested:
			stats["requested"]++
		case HolePunchSent:
			stats["sent"]++
		case HolePunchWaiting:
			stats["waiting"]++
		case HolePunchSuccess:
			stats["success"]++
		case HolePunchFailed:
			stats["failed"]++
		}
	}

	return stats
}

// SetAttemptStartTime sets the StartTime of an attempt (test helper).
func (hpc *HolePunchCoordinator) SetAttemptStartTime(sessionID uint64, t time.Time) {
	hpc.mutex.Lock()
	defer hpc.mutex.Unlock()
	if attempt, exists := hpc.attempts[sessionID]; exists {
		attempt.StartTime = t
	}
}

// SetAttemptState sets the State of an attempt (test helper).
func (hpc *HolePunchCoordinator) SetAttemptState(sessionID uint64, state HolePunchState) {
	hpc.mutex.Lock()
	defer hpc.mutex.Unlock()
	if attempt, exists := hpc.attempts[sessionID]; exists {
		attempt.State = state
	}
}
