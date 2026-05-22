// Package ssu2 provides SSU2-specific implementations for the Noise Protocol Framework
// supporting I2P's SSU2 transport protocol with UDP-based connections and NAT traversal.
package path

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"net"
	"sync"
	"time"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// PathValidator implements connection migration with path validation.
//
// Path validation allows an SSU2 connection to migrate to a new UDP path
// (different IP address or port) while maintaining security and preventing
// amplification attacks. This is useful for:
//   - IP address changes (network switch, VPN, mobile roaming)
//   - Port changes (NAT rebinding)
//   - Failover to backup paths
//   - Load balancing across multiple paths
//
// The validation protocol uses Path Challenge (Type 18) and Path Response (Type 19) blocks
// to verify bidirectional connectivity on the new path before migration.
//
// Design rationale:
// - Cryptographic challenge IDs prevent spoofing
// - Timeout-based cleanup prevents resource leaks
// - Thread-safe for concurrent path validations
// - Follows ssu2.rst specification for path validation
type PathValidator struct {
	// conn is the SSU2 connection this validator belongs to
	conn PathValidationConn

	// challenges tracks active path validation attempts by challenge ID
	challenges map[uint64]*PathChallenge

	// tokenCache is the optional token cache for invalidation on migration
	tokenCache TokenCacheAccessor

	// congestionController is reset after successful path migration (G-7).
	// Per spec, path changes should trigger congestion window reset.
	congestionController CongestionControllerAccessor

	// discoveredMTU is the largest packet size that received a response
	// during MTU probing. 0 means no probe has completed yet.
	discoveredMTU int

	// mutex protects the challenges map and discoveredMTU
	mutex sync.RWMutex
}

// PathValidationConn defines the interface for sending path validation messages.
// This interface is implemented by SSU2Conn to allow testing with mocks.
type PathValidationConn interface {
	// SendToAddress sends a block to a specific UDP address
	SendToAddress(block *SSU2Block, addr *net.UDPAddr) error

	// GetRemoteAddr returns the current remote address
	GetRemoteAddr() *net.UDPAddr

	// SetRemoteAddr updates the remote address after successful validation
	SetRemoteAddr(addr *net.UDPAddr) error
}

// PathChallenge represents an active path validation attempt.
type PathChallenge struct {
	// ChallengeID uniquely identifies this validation (8 bytes)
	ChallengeID uint64

	// NewAddr is the new UDP address being validated
	NewAddr *net.UDPAddr

	// Timestamp is when the challenge was created
	Timestamp time.Time

	// State tracks the validation progress
	State PathChallengeState

	// ProbeSize is the total packet size this challenge probes (G-5).
	// 0 for non-MTU challenges.
	ProbeSize int
}

// PathChallengeState represents the state of a path validation attempt.
type PathChallengeState int

const (
	// ChallengeSent indicates we sent a challenge, awaiting response
	ChallengeSent PathChallengeState = iota

	// ChallengeReceived indicates we received a challenge, need to respond
	ChallengeReceived

	// ChallengeValidated indicates successful bidirectional validation
	ChallengeValidated

	// ChallengeFailed indicates validation failed (timeout or error)
	ChallengeFailed
)

// String returns a human-readable representation of the challenge state.
func (s PathChallengeState) String() string {
	switch s {
	case ChallengeSent:
		return "ChallengeSent"
	case ChallengeReceived:
		return "ChallengeReceived"
	case ChallengeValidated:
		return "ChallengeValidated"
	case ChallengeFailed:
		return "ChallengeFailed"
	default:
		return "Unknown"
	}
}

// Path validation timeouts
const (
	// PathValidationTimeout is how long to wait for path response
	PathValidationTimeout = 10 * time.Second

	// PathValidationCleanupInterval is how often to clean up expired challenges
	PathValidationCleanupInterval = 30 * time.Second
)

// MTU probing constants (G-5).
const (
	// MinMTU is the minimum MTU for SSU2 (spec-defined floor).
	MinMTU = 1280

	// MaxMTU is the upper bound for MTU probing.
	MaxMTU = 1500

	// MTUProbeStep is the size increment between probe steps.
	MTUProbeStep = 20
)

// NewPathValidator creates a new path validator for a connection.
//
// Parameters:
//   - conn: The connection to manage path validation for
//
// Returns an initialized validator.
func NewPathValidator(conn PathValidationConn) *PathValidator {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "NewPathValidator"}).Debug("Creating new PathValidator")
	return &PathValidator{
		conn:       conn,
		challenges: make(map[uint64]*PathChallenge),
	}
}

// SetTokenCache sets the token cache used for invalidation when a path migrates.
// Per spec, tokens are bound to an IP:port and must be invalidated on address change.
func (pv *PathValidator) SetTokenCache(tc TokenCacheAccessor) {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "SetTokenCache"}).Debug("Setting token cache for path validator")
	pv.tokenCache = tc
}

// SetCongestionController sets the congestion controller to reset on path migration (G-7).
func (pv *PathValidator) SetCongestionController(cc CongestionControllerAccessor) {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "SetCongestionController"}).Debug("Setting congestion controller for path validator")
	pv.congestionController = cc
}

// InitiatePathValidation starts path validation for a new address.
//
// This sends a Path Challenge (Type 18) block to the new address with a
// cryptographically random challenge ID. The peer must respond with a
// Path Response (Type 19) containing the same challenge ID.
//
// Parameters:
//   - newAddr: The new UDP address to validate
//
// Returns:
//   - uint64: The challenge ID for tracking this validation
//   - error: If challenge creation or sending fails
func (pv *PathValidator) InitiatePathValidation(newAddr *net.UDPAddr) (uint64, error) {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "InitiatePathValidation"}).Debug("Initiating path validation")
	if newAddr == nil {
		return 0, oops.Errorf("new address is nil")
	}

	// Generate cryptographic random challenge ID (8 bytes)
	challengeID, err := generateChallengeID()
	if err != nil {
		return 0, oops.Wrapf(err, "failed to generate challenge ID")
	}

	// Create challenge tracking entry
	challenge := &PathChallenge{
		ChallengeID: challengeID,
		NewAddr:     newAddr,
		Timestamp:   time.Now(),
		State:       ChallengeSent,
	}

	pv.mutex.Lock()
	pv.challenges[challengeID] = challenge
	pv.mutex.Unlock()

	// Send path challenge to new address
	if err := pv.SendPathChallenge(challengeID, newAddr); err != nil {
		pv.mutex.Lock()
		delete(pv.challenges, challengeID)
		pv.mutex.Unlock()
		return 0, oops.Wrapf(err, "failed to send path challenge")
	}

	return challengeID, nil
}

// SendPathChallenge sends a Path Challenge block to the specified address.
//
// Parameters:
//   - challengeID: The 8-byte challenge identifier
//   - addr: The UDP address to send to
//
// Returns error if encoding or sending fails.
func (pv *PathValidator) SendPathChallenge(challengeID uint64, addr *net.UDPAddr) error {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "SendPathChallenge", "challengeID": challengeID, "addr": addr}).Debug("Sending path challenge")
	block := EncodePathChallenge(challengeID)
	if err := pv.conn.SendToAddress(block, addr); err != nil {
		return oops.Wrapf(err, "failed to send path challenge to %v", addr)
	}
	return nil
}

// HandlePathChallenge processes a received Path Challenge block.
//
// When we receive a challenge, we:
//  1. Record it as ChallengeReceived
//  2. Send a Path Response with the same challenge ID
//
// Parameters:
//   - block: The received Path Challenge block
//   - fromAddr: The UDP address it came from
//
// Returns error if decoding or response fails.
func (pv *PathValidator) HandlePathChallenge(block *SSU2Block, fromAddr *net.UDPAddr) error {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "HandlePathChallenge", "fromAddr": fromAddr}).Debug("Processing received path challenge")
	if block == nil {
		return oops.Errorf("block is nil")
	}
	if fromAddr == nil {
		return oops.Errorf("fromAddr is nil")
	}

	// Decode challenge ID
	challengeID, err := DecodePathChallenge(block)
	if err != nil {
		return oops.Wrapf(err, "failed to decode path challenge")
	}

	// Record challenge
	challenge := &PathChallenge{
		ChallengeID: challengeID,
		NewAddr:     fromAddr,
		Timestamp:   time.Now(),
		State:       ChallengeReceived,
	}

	pv.mutex.Lock()
	pv.challenges[challengeID] = challenge
	pv.mutex.Unlock()

	// Send response immediately
	return pv.SendPathResponse(challengeID, fromAddr)
}

// SendPathResponse sends a Path Response block to the specified address.
//
// Parameters:
//   - challengeID: The 8-byte challenge identifier from the Path Challenge
//   - addr: The UDP address to send to
//
// Returns error if encoding or sending fails.
func (pv *PathValidator) SendPathResponse(challengeID uint64, addr *net.UDPAddr) error {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "SendPathResponse", "challengeID": challengeID, "addr": addr}).Debug("Sending path response")
	block := EncodePathResponse(challengeID)
	if err := pv.conn.SendToAddress(block, addr); err != nil {
		return oops.Wrapf(err, "failed to send path response to %v", addr)
	}
	return nil
}

// HandlePathResponse processes a received Path Response block.
//
// When we receive a response:
//  1. Verify it matches a pending challenge
//  2. Mark the challenge as validated
//  3. Complete the path migration if validation succeeds
//
// Parameters:
//   - block: The received Path Response block
//   - fromAddr: The UDP address it came from
//
// Returns error if validation fails.
func (pv *PathValidator) HandlePathResponse(block *SSU2Block, fromAddr *net.UDPAddr) error {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "HandlePathResponse", "fromAddr": fromAddr}).Debug("Processing received path response")
	if block == nil {
		return oops.Errorf("block is nil")
	}
	if fromAddr == nil {
		return oops.Errorf("fromAddr is nil")
	}

	// Decode response
	challengeID, err := DecodePathResponse(block)
	if err != nil {
		return oops.Wrapf(err, "failed to decode path response")
	}

	// Find matching challenge, verify address, and mark validated — all under one lock
	pv.mutex.Lock()
	challenge, exists := pv.challenges[challengeID]
	if !exists {
		pv.mutex.Unlock()
		return oops.Errorf("no matching challenge for ID %d", challengeID)
	}

	// Verify response came from expected address
	if challenge.NewAddr.String() != fromAddr.String() {
		pv.mutex.Unlock()
		return oops.Errorf("path response from unexpected address: expected %v, got %v",
			challenge.NewAddr, fromAddr)
	}

	// Mark as validated
	challenge.State = ChallengeValidated

	// Update discovered MTU if this was a probe challenge (G-5)
	if challenge.ProbeSize > 0 && challenge.ProbeSize > pv.discoveredMTU {
		pv.discoveredMTU = challenge.ProbeSize
	}

	pv.mutex.Unlock()

	// Complete path validation (skip for MTU-only probes)
	if challenge.ProbeSize > 0 {
		return nil
	}
	return pv.ValidatePath(challengeID)
}

// ValidatePath completes the path validation and migrates the connection.
//
// This should be called after receiving a valid Path Response.
// It updates the connection's remote address to the validated path.
//
// Parameters:
//   - challengeID: The challenge ID that was validated
//
// Returns error if migration fails.
func (pv *PathValidator) ValidatePath(challengeID uint64) error {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "ValidatePath", "challengeID": challengeID}).Debug("Validating path")
	pv.mutex.Lock()
	challenge, exists := pv.challenges[challengeID]
	if !exists {
		pv.mutex.Unlock()
		return oops.Errorf("no challenge found for ID %d", challengeID)
	}

	if challenge.State != ChallengeValidated {
		pv.mutex.Unlock()
		return oops.Errorf("challenge %d not validated (state: %v)", challengeID, challenge.State)
	}

	newAddr := challenge.NewAddr
	pv.mutex.Unlock()

	// Invalidate tokens bound to the old address before migration
	if pv.tokenCache != nil {
		oldAddr := pv.conn.GetRemoteAddr()
		if oldAddr != nil {
			pv.tokenCache.InvalidateAddress(oldAddr)
		}
	}

	// Update connection remote address
	if err := pv.conn.SetRemoteAddr(newAddr); err != nil {
		pv.FailPath(challengeID, err)
		return oops.Wrapf(err, "failed to set remote address")
	}

	// G-7: Reset congestion controller after successful path migration
	// to re-enter slow start on the new path.
	if pv.congestionController != nil {
		pv.congestionController.Reset()
	}

	// Clean up challenge after successful migration
	pv.mutex.Lock()
	delete(pv.challenges, challengeID)
	pv.mutex.Unlock()

	return nil
}

// FailPath marks a path validation as failed.
//
// Parameters:
//   - challengeID: The challenge ID to fail
//   - reason: Error describing why validation failed
func (pv *PathValidator) FailPath(challengeID uint64, reason error) {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "FailPath", "challengeID": challengeID}).Debug("Path validation failed")
	pv.mutex.Lock()
	defer pv.mutex.Unlock()

	if challenge, exists := pv.challenges[challengeID]; exists {
		challenge.State = ChallengeFailed
	}
}

// GetChallenge returns information about a specific challenge.
//
// Parameters:
//   - challengeID: The challenge ID to look up
//
// Returns:
//   - *PathChallenge: Challenge information (defensive copy)
//   - bool: Whether the challenge exists
func (pv *PathValidator) GetChallenge(challengeID uint64) (*PathChallenge, bool) {
	pv.mutex.RLock()
	defer pv.mutex.RUnlock()

	challenge, exists := pv.challenges[challengeID]
	if !exists {
		return nil, false
	}

	// Return defensive copy
	pc := &PathChallenge{
		ChallengeID: challenge.ChallengeID,
		Timestamp:   challenge.Timestamp,
		State:       challenge.State,
		ProbeSize:   challenge.ProbeSize,
	}
	if challenge.NewAddr != nil {
		addrCopy := *challenge.NewAddr
		pc.NewAddr = &addrCopy
	}
	return pc, true
}

// CleanupExpired removes expired path validation challenges.
//
// Challenges are expired if they're older than PathValidationTimeout
// and not in a terminal state (Validated or Failed).
//
// Returns the number of challenges cleaned up.
func (pv *PathValidator) CleanupExpired() int {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "CleanupExpired"}).Debug("Removing expired path validation challenges")
	pv.mutex.Lock()
	defer pv.mutex.Unlock()

	now := time.Now()
	cleaned := 0

	for id, challenge := range pv.challenges {
		// Skip terminal states
		if challenge.State == ChallengeValidated || challenge.State == ChallengeFailed {
			continue
		}

		// Check timeout
		if now.Sub(challenge.Timestamp) > PathValidationTimeout {
			challenge.State = ChallengeFailed
			delete(pv.challenges, id)
			cleaned++
		}
	}

	return cleaned
}

// generateChallengeID generates a cryptographically random 8-byte challenge ID.
func generateChallengeID() (uint64, error) {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0, oops.Wrapf(err, "failed to read random bytes")
	}
	return binary.BigEndian.Uint64(buf[:]), nil
}

// EncodePathChallenge encodes a Path Challenge block (Type 18).
//
// Wire format: [ChallengeID:8]
//
// Parameters:
//   - challengeID: 8-byte challenge identifier
//
// Returns encoded block.
func EncodePathChallenge(challengeID uint64) *SSU2Block {
	data := make([]byte, 8)
	binary.BigEndian.PutUint64(data, challengeID)
	return NewSSU2Block(BlockTypePathChallenge, data)
}

// DecodePathChallenge decodes a Path Challenge block.
//
// Parameters:
//   - block: SSU2Block with Type 18
//
// Returns:
//   - uint64: The challenge ID
//   - error: If decoding fails
func DecodePathChallenge(block *SSU2Block) (uint64, error) {
	return decodePathUint64Block(block, BlockTypePathChallenge, "PathChallenge")
}

// EncodePathResponse encodes a Path Response block (Type 19).
//
// Wire format: [ChallengeID:8]
//
// Parameters:
//   - challengeID: 8-byte challenge identifier from the Path Challenge
//
// Returns encoded block.
func EncodePathResponse(challengeID uint64) *SSU2Block {
	data := make([]byte, 8)
	binary.BigEndian.PutUint64(data, challengeID)
	return NewSSU2Block(BlockTypePathResponse, data)
}

// DecodePathResponse decodes a Path Response block.
//
// Parameters:
//   - block: SSU2Block with Type 19
//
// Returns:
//   - uint64: The challenge ID
//   - error: If decoding fails
func DecodePathResponse(block *SSU2Block) (uint64, error) {
	return decodePathUint64Block(block, BlockTypePathResponse, "PathResponse")
}

// decodePathUint64Block is the shared decoder for PathChallenge and PathResponse blocks,
// which both carry a single uint64 challenge ID.
func decodePathUint64Block(block *SSU2Block, expectedType uint8, label string) (uint64, error) {
	if block == nil {
		return 0, oops.Errorf("block is nil")
	}
	if block.Type != expectedType {
		return 0, oops.Errorf("invalid block type: expected %d, got %d",
			expectedType, block.Type)
	}
	if len(block.Data) < 8 {
		return 0, oops.Errorf("%s block too short: %d bytes (minimum 8)",
			label, len(block.Data))
	}
	return binary.BigEndian.Uint64(block.Data[:8]), nil
}

// EncodePathChallengeWithPadding creates a Path Challenge block padded to
// probeSize bytes (total block data length). The first 8 bytes are the
// challenge ID; remaining bytes are random padding for MTU probing (G-5).
func EncodePathChallengeWithPadding(challengeID uint64, probeSize int) *SSU2Block {
	if probeSize < 8 {
		probeSize = 8
	}
	data := make([]byte, probeSize)
	binary.BigEndian.PutUint64(data[:8], challengeID)
	// Fill remaining bytes with random padding; failure is non-fatal
	if probeSize > 8 {
		_, _ = rand.Read(data[8:])
	}
	return NewSSU2Block(BlockTypePathChallenge, data)
}

// InitiateMTUProbe starts an MTU probe by sending a Path Challenge padded
// to the given size. If a Path Response is received for this challenge,
// the discovered MTU is updated (G-5).
func (pv *PathValidator) InitiateMTUProbe(addr *net.UDPAddr, size int) (uint64, error) {
	if addr == nil {
		return 0, oops.Errorf("address is nil")
	}
	if size < MinMTU || size > MaxMTU {
		return 0, oops.Errorf("probe size %d out of range [%d, %d]", size, MinMTU, MaxMTU)
	}

	challengeID, err := generateChallengeID()
	if err != nil {
		return 0, oops.Wrapf(err, "failed to generate challenge ID for MTU probe")
	}

	challenge := &PathChallenge{
		ChallengeID: challengeID,
		NewAddr:     addr,
		Timestamp:   time.Now(),
		State:       ChallengeSent,
		ProbeSize:   size,
	}

	pv.mutex.Lock()
	pv.challenges[challengeID] = challenge
	pv.mutex.Unlock()

	block := EncodePathChallengeWithPadding(challengeID, size)
	if err := pv.conn.SendToAddress(block, addr); err != nil {
		pv.mutex.Lock()
		delete(pv.challenges, challengeID)
		pv.mutex.Unlock()
		return 0, oops.Wrapf(err, "failed to send MTU probe of size %d", size)
	}

	return challengeID, nil
}

// CompleteMTUProbe is called when a Path Response is received for an MTU
// probe challenge. Updates discoveredMTU if this probe was larger than
// the previously discovered value (G-5).
func (pv *PathValidator) CompleteMTUProbe(challengeID uint64) {
	pv.mutex.Lock()
	defer pv.mutex.Unlock()

	challenge, exists := pv.challenges[challengeID]
	if !exists || challenge.ProbeSize == 0 {
		return
	}
	challenge.State = ChallengeValidated
	if challenge.ProbeSize > pv.discoveredMTU {
		pv.discoveredMTU = challenge.ProbeSize
	}
}

// GetDiscoveredMTU returns the largest validated MTU from probing, or 0
// if no MTU probe has completed (G-5).
func (pv *PathValidator) GetDiscoveredMTU() int {
	pv.mutex.RLock()
	defer pv.mutex.RUnlock()
	return pv.discoveredMTU
}

// RunPMTUD performs Path MTU Discovery using binary search between low and
// high. Each step sends a padded Path Challenge and waits for a response.
// On success the discovered MTU is updated; on timeout (no response within
// PathValidationTimeout) the probe size is reduced. The final discovered
// MTU is returned, or MinMTU if no probe succeeded (G-4).
//
// Parameters:
//   - addr: the remote address to probe
//   - low:  minimum probe size (typically MinMTU, 1280)
//   - high: maximum probe size (e.g. MaxPacketSizeIPv4 or MaxPacketSizeIPv6)
//
// RunPMTUD blocks until the search completes or ctx is cancelled.
func (pv *PathValidator) RunPMTUD(ctx context.Context, addr *net.UDPAddr, low, high int) int {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "RunPMTUD", "low": low, "high": high}).Debug("Running PMTUD")
	if low < MinMTU {
		low = MinMTU
	}
	if high > MaxMTU {
		high = MaxMTU
	}
	if low >= high {
		return low
	}

	best := low

	for low+MTUProbeStep <= high {
		mid := (low + high) / 2

		id, err := pv.InitiateMTUProbe(addr, mid)
		if err != nil {
			high = mid - 1
			continue
		}

		// Wait for probe response or timeout
		deadline := time.Now().Add(PathValidationTimeout)
		probed := false
		for time.Now().Before(deadline) {
			select {
			case <-ctx.Done():
				return best
			case <-time.After(100 * time.Millisecond):
			}
			ch, exists := pv.GetChallenge(id)
			if exists && ch.State == ChallengeValidated {
				probed = true
				break
			}
			if exists && ch.State == ChallengeFailed {
				break
			}
		}

		if probed {
			best = mid
			low = mid + 1
		} else {
			high = mid - 1
		}
	}

	return best
}
