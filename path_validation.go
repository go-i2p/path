// Package ssu2path provides SSU2 path-management primitives for I2P's SSU2
// transport protocol: hole-punching coordination, relay request/response
// handling, peer testing, path validation, and their wire codecs.
//
// # Resource Management
//
// This package creates managers with background goroutines for cleanup and maintenance:
//   - HolePunchCoordinator (cleanup every 30s)
//   - PeerTestManager (cleanup every 60s)
//   - RelayManager (cleanup timer-based)
//
// IMPORTANT: Callers MUST call Stop() on these managers when done to prevent goroutine leaks.
// Failure to call Stop() will cause background goroutines to run until process termination.
package ssu2path

import (
	"context"
	"github.com/go-i2p/crypto/rand"
	"net"
	"sync"
	"time"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// TokenCacheAccessor provides address-based token invalidation.
// Implemented by *ssu2.TokenCache.
type TokenCacheAccessor interface {
	InvalidateAddress(addr *net.UDPAddr)
}

// CongestionControllerAccessor provides congestion reset and window control.
// Implemented by *ssu2/reliability.CongestionController.
type CongestionControllerAccessor interface {
	Reset()
	SetCWND(cwnd int)
}

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

	// challenges tracks active path validation attempts by challenge data
	challenges map[string]*PathChallenge

	// tokenCache is the optional token cache for invalidation on migration
	tokenCache TokenCacheAccessor

	// congestionController is reset after successful path migration (G-7).
	// Per spec, path changes should trigger congestion window reset.
	congestionController CongestionControllerAccessor

	// discoveredMTU is the largest packet size that received a response
	// during MTU probing. 0 means no probe has completed yet.
	discoveredMTU int

	// stopCh is closed by Stop() to signal the cleanup goroutine to exit.
	// BUG-M07 fix: Added to enable proper resource cleanup
	stopCh chan struct{}

	// stopOnce ensures Stop() is idempotent and cannot panic on double-call.
	// BUG-M07 fix: Added to enable proper resource cleanup
	stopOnce sync.Once

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
	// ChallengeData is the arbitrary challenge payload (min 8 bytes recommended).
	// The Path Response must echo this data verbatim.
	ChallengeData []byte

	// NewAddr is the new UDP address being validated
	NewAddr *net.UDPAddr

	// Timestamp is when the challenge was created (Path Validation timer start).
	Timestamp time.Time

	// LastSentAt is when the challenge was last sent (Path Response timer start).
	// Per the SSU2 spec, if no Path Response is received before the Path Response
	// timer expires, the Path Challenge is resent and the timer is doubled.
	LastSentAt time.Time

	// ResponseTimer is the current Path Response timeout. It doubles on each
	// expiry per the SSU2 spec. 0 means use PathResponseBaseTimer.
	ResponseTimer time.Duration

	// State tracks the validation progress
	State PathChallengeState

	// ProbeSize is the total packet size this challenge probes (G-5).
	// 0 for non-MTU challenges.
	ProbeSize int

	// BUG-014 fix: done is closed when the challenge completes (validated or failed)
	// to wake RunPMTUD without polling
	done chan struct{}
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
	// PathValidationTimeout is the Path Validation timer: the maximum total
	// time to wait for path validation to complete. Per the SSU2 spec
	// (Connection Migration), path validation fails when this timer expires.
	// The spec leaves the exact value TBD ("several seconds or several times
	// RTO"); 10 seconds is a reasonable default.
	PathValidationTimeout = 10 * time.Second

	// PathResponseBaseTimer is the initial Path Response timer. Per the SSU2
	// spec, if no Path Response is received before it expires, the Path
	// Challenge is resent and the timer is doubled.
	PathResponseBaseTimer = 2 * time.Second

	// PathValidationCleanupInterval is how often to clean up expired challenges.
	// 30 seconds = 3× PathValidationTimeout, balancing cleanup cost
	// against memory pressure from abandoned challenges.
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

// MinCongestionWindow is the minimum congestion window per the SSU2 spec
// (Connection Migration → Initiating Path Validation: "Reduce the congestion
// window to the minimum"). It is 1280 bytes, matching the spec's minimum
// congestion window. This is a distinct quantity from MinMTU (the minimum
// packet size); the two happen to share the same numeric value but must not
// be conflated.
const MinCongestionWindow = 1280

// NewPathValidator creates a new path validator for a connection.
//
// BUG-M07 fix: Now starts a background cleanup goroutine. Callers MUST call
// Stop() when done to prevent goroutine leaks (see package-level documentation).
//
// Parameters:
//   - conn: The connection to manage path validation for
//
// Returns an initialized validator.
func NewPathValidator(conn PathValidationConn) *PathValidator {
	log.WithFields(logger.Fields{"pkg": "ssu2path", "func": "NewPathValidator"}).Debug("Creating new PathValidator")
	pv := &PathValidator{
		conn:       conn,
		challenges: make(map[string]*PathChallenge),
		stopCh:     make(chan struct{}),
	}
	go pv.cleanupLoop()
	return pv
}

// Stop halts the background cleanup goroutine. Call when the validator is
// no longer needed to avoid goroutine leaks. Safe to call multiple times.
// BUG-M07 fix: Added to mirror RelayManager/HolePunchCoordinator pattern.
func (pv *PathValidator) Stop() {
	pv.stopOnce.Do(func() { close(pv.stopCh) })
}

// cleanupLoop periodically removes expired path validation challenges.
// BUG-M07 fix: Added to prevent challenges from persisting indefinitely.
func (pv *PathValidator) cleanupLoop() {
	ticker := time.NewTicker(PathValidationCleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			pv.CleanupExpired()
		case <-pv.stopCh:
			return
		}
	}
}

// SetTokenCache sets the token cache used for invalidation when a path migrates.
// Per spec, tokens are bound to an IP:port and must be invalidated on address change.
func (pv *PathValidator) SetTokenCache(tc TokenCacheAccessor) {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "SetTokenCache"}).Debug("Setting token cache for path validator")
	// BUG-006 fix: Protect with mutex for thread safety
	pv.mutex.Lock()
	defer pv.mutex.Unlock()
	pv.tokenCache = tc
}

// SetCongestionController sets the congestion controller to reset on path migration (G-7).
func (pv *PathValidator) SetCongestionController(cc CongestionControllerAccessor) {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "SetCongestionController"}).Debug("Setting congestion controller for path validator")
	// BUG-006 fix: Protect with mutex for thread safety
	pv.mutex.Lock()
	defer pv.mutex.Unlock()
	pv.congestionController = cc
}

// reduceCongestionForValidation reduces the congestion window to the minimum
// upon entering the path validation phase, as required by the SSU2 spec
// (Connection Migration): "Reduce the congestion window to the minimum" and
// "the congestion window and PMTU must remain at the minimum values during
// the path validation phase". The PMTU is held at MinMTU (1280) by the
// caller, which sends only Path Challenge blocks (no data) during validation.
//
// The congestion window is set to MinCongestionWindow (the spec's minimum
// congestion window), NOT MinMTU — these are distinct quantities that happen
// to share the same numeric value.
func (pv *PathValidator) reduceCongestionForValidation() {
	pv.mutex.RLock()
	cc := pv.congestionController
	pv.mutex.RUnlock()
	if cc != nil {
		cc.SetCWND(MinCongestionWindow)
	}
}

// InitiatePathValidation starts path validation for a new address.
//
// This sends a Path Challenge (Type 18) block to the new address with
// cryptographically random challenge data. The peer must respond with a
// Path Response (Type 19) containing the same challenge data.
//
// Parameters:
//   - newAddr: The new UDP address to validate
//
// Returns:
//   - []byte: The challenge data for tracking this validation
//   - error: If challenge creation or sending fails
func (pv *PathValidator) InitiatePathValidation(newAddr *net.UDPAddr) ([]byte, error) {
	log.WithFields(logger.Fields{"pkg": "ssu2path", "func": "InitiatePathValidation"}).Debug("Initiating path validation")
	if newAddr == nil {
		return nil, oops.Errorf("new address is nil")
	}

	// Generate cryptographic random challenge data (8 bytes recommended)
	challengeData, err := generateChallengeData()
	if err != nil {
		return nil, oops.Wrapf(err, "failed to generate challenge data")
	}

	// Create challenge tracking entry
	now := time.Now()
	challenge := &PathChallenge{
		ChallengeData: challengeData,
		NewAddr:       newAddr,
		Timestamp:     now,
		LastSentAt:    now,
		ResponseTimer: PathResponseBaseTimer,
		State:         ChallengeSent,
		done:          make(chan struct{}),
	}

	key := string(challengeData)
	pv.mutex.Lock()
	pv.challenges[key] = challenge
	pv.mutex.Unlock()

	// Per the SSU2 spec (Connection Migration), upon entering the path
	// validation phase the congestion window must be reduced to the minimum
	// and the PMTU reduced to the minimum (1280), and both must remain at
	// their minimum values during the validation phase.
	pv.reduceCongestionForValidation()

	// Send path challenge to new address
	if err := pv.SendPathChallenge(challengeData, newAddr); err != nil {
		pv.mutex.Lock()
		delete(pv.challenges, key)
		pv.mutex.Unlock()
		return nil, oops.Wrapf(err, "failed to send path challenge")
	}

	return challengeData, nil
}

// SendPathChallenge sends a Path Challenge block to the specified address.
//
// Parameters:
//   - challengeData: The arbitrary challenge payload
//   - addr: The UDP address to send to
//
// Returns error if encoding or sending fails.
func (pv *PathValidator) SendPathChallenge(challengeData []byte, addr *net.UDPAddr) error {
	log.WithFields(logger.Fields{"pkg": "ssu2path", "func": "SendPathChallenge", "addr": addr}).Debug("Sending path challenge")
	block := EncodePathChallenge(challengeData)
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
	log.WithFields(logger.Fields{"pkg": "ssu2path", "func": "HandlePathChallenge", "fromAddr": fromAddr}).Debug("Processing received path challenge")
	if block == nil {
		return oops.Errorf("block is nil")
	}
	if fromAddr == nil {
		return oops.Errorf("fromAddr is nil")
	}

	// Decode challenge data
	challengeData, err := DecodePathChallenge(block)
	if err != nil {
		return oops.Wrapf(err, "failed to decode path challenge")
	}

	// Record challenge
	challenge := &PathChallenge{
		ChallengeData: challengeData,
		NewAddr:       fromAddr,
		Timestamp:     time.Now(),
		State:         ChallengeReceived,
		done:          make(chan struct{}), // BUG-014 fix: signal channel
	}

	key := string(challengeData)
	pv.mutex.Lock()
	// L-4 fix: close old done channel before overwriting to unblock any waiter.
	if old, exists := pv.challenges[key]; exists && old.done != nil {
		close(old.done)
	}
	pv.challenges[key] = challenge
	pv.mutex.Unlock()

	// Send response immediately
	return pv.SendPathResponse(challengeData, fromAddr)
}

// SendPathResponse sends a Path Response block to the specified address.
//
// Parameters:
//   - challengeData: The challenge data to echo back verbatim
//   - addr: The UDP address to send to
//
// Returns error if encoding or sending fails.
func (pv *PathValidator) SendPathResponse(challengeData []byte, addr *net.UDPAddr) error {
	log.WithFields(logger.Fields{"pkg": "ssu2path", "func": "SendPathResponse", "addr": addr}).Debug("Sending path response")
	block := EncodePathResponse(challengeData)
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
	log.WithFields(logger.Fields{"pkg": "ssu2path", "func": "HandlePathResponse", "fromAddr": fromAddr}).Debug("Processing received path response")
	if block == nil {
		return oops.Errorf("block is nil")
	}
	if fromAddr == nil {
		return oops.Errorf("fromAddr is nil")
	}

	// Decode response
	challengeData, err := DecodePathResponse(block)
	if err != nil {
		return oops.Wrapf(err, "failed to decode path response")
	}

	key := string(challengeData)
	// Find matching challenge, verify address, and mark validated — all under one lock
	pv.mutex.Lock()
	challenge, exists := pv.challenges[key]
	if !exists {
		pv.mutex.Unlock()
		return oops.Errorf("no matching challenge found")
	}

	// H-2 fix: guard against duplicate responses — second response for an already-validated
	// challenge would close an already-closed channel, causing a panic.
	if challenge.State == ChallengeValidated {
		pv.mutex.Unlock()
		return nil
	}

	// The spec (Connection Migration → Initiating Path Validation) states that
	// "the source IP/port of the Path Response message is not required to be the
	// same as the Path Challenge was sent to." The authoritative validation is the
	// opaque challenge-data match above (at least 8 bytes of entropy, so it cannot
	// be spoofed); the source address is therefore NOT compared here.

	// Mark as validated
	challenge.State = ChallengeValidated

	// BUG-014 fix: Signal completion
	if challenge.done != nil {
		close(challenge.done)
	}

	// Update discovered MTU if this was a probe challenge (G-5)
	if challenge.ProbeSize > 0 && challenge.ProbeSize > pv.discoveredMTU {
		pv.discoveredMTU = challenge.ProbeSize
	}

	pv.mutex.Unlock()

	// Complete path validation (skip for MTU-only probes)
	if challenge.ProbeSize > 0 {
		// M-1 fix: delete the MTU probe challenge so it does not accumulate indefinitely.
		pv.mutex.Lock()
		delete(pv.challenges, key)
		pv.mutex.Unlock()
		return nil
	}
	return pv.ValidatePath(challengeData)
}

// ValidatePath completes the path validation and migrates the connection.
//
// This should be called after receiving a valid Path Response.
// It updates the connection's remote address to the validated path.
//
// Parameters:
//   - challengeData: The challenge data that was validated
//
// Returns error if migration fails.
func (pv *PathValidator) ValidatePath(challengeData []byte) error {
	log.WithFields(logger.Fields{"pkg": "ssu2path", "func": "ValidatePath"}).Debug("Validating path")
	key := string(challengeData)
	pv.mutex.Lock()
	challenge, exists := pv.challenges[key]
	if !exists {
		pv.mutex.Unlock()
		return oops.Errorf("no challenge found")
	}

	if challenge.State != ChallengeValidated {
		pv.mutex.Unlock()
		return oops.Errorf("challenge not validated (state: %v)", challenge.State)
	}

	newAddr := challenge.NewAddr
	// BUG-002 fix: Delete challenge before unlock to prevent TOCTOU race
	// This ensures side effects execute exactly once even with concurrent calls
	delete(pv.challenges, key)

	// BUG-006 fix: Read accessor fields under lock to prevent race
	tokenCache := pv.tokenCache
	congestionController := pv.congestionController
	pv.mutex.Unlock()

	// BUG-002 fix: capture old address before migration so we can invalidate
	// tokens only after SetRemoteAddr succeeds. Invalidating first would leave
	// the connection in a broken state if SetRemoteAddr fails.
	var oldAddr *net.UDPAddr
	if tokenCache != nil {
		oldAddr = pv.conn.GetRemoteAddr()
	}

	// Update connection remote address first; only proceed with side effects on success.
	if err := pv.conn.SetRemoteAddr(newAddr); err != nil {
		// Note: Challenge already deleted above to prevent TOCTOU race.
		// Cannot call FailPath since challenge no longer exists.
		return oops.Wrapf(err, "failed to set remote address")
	}

	// Invalidate tokens bound to the old address now that migration succeeded.
	if tokenCache != nil && oldAddr != nil {
		tokenCache.InvalidateAddress(oldAddr)
	}

	// G-7: Reset congestion controller after successful path migration
	// to re-enter slow start on the new path.
	if congestionController != nil {
		congestionController.Reset()
	}

	return nil
}

// FailPath marks a path validation as failed.
//
// Parameters:
//   - challengeData: The challenge data to fail
//   - reason: Error describing why validation failed
func (pv *PathValidator) FailPath(challengeData []byte, reason error) {
	log.WithFields(logger.Fields{"pkg": "ssu2path", "func": "FailPath"}).Debug("Path validation failed")
	key := string(challengeData)
	pv.mutex.Lock()
	defer pv.mutex.Unlock()

	if challenge, exists := pv.challenges[key]; exists {
		// H-2/M-2 fix: guard against double-fail and delete to prevent memory leak.
		if challenge.State == ChallengeFailed || challenge.State == ChallengeValidated {
			return
		}
		challenge.State = ChallengeFailed
		// BUG-014 fix: Signal completion
		if challenge.done != nil {
			close(challenge.done)
		}
		// M-2 fix: delete terminal entry so it does not accumulate indefinitely.
		delete(pv.challenges, key)
	}
}

// GetChallenge returns information about a specific challenge.
//
// Parameters:
//   - challengeData: The challenge data to look up
//
// Returns:
//   - *PathChallenge: Challenge information (defensive copy)
//   - bool: Whether the challenge exists
func (pv *PathValidator) GetChallenge(challengeData []byte) (*PathChallenge, bool) {
	pv.mutex.RLock()
	defer pv.mutex.RUnlock()

	challenge, exists := pv.challenges[string(challengeData)]
	if !exists {
		return nil, false
	}

	// Return defensive copy — include done so waitForProbeResult can select on it (H-1 fix).
	pc := &PathChallenge{
		ChallengeData: challenge.ChallengeData,
		Timestamp:     challenge.Timestamp,
		LastSentAt:    challenge.LastSentAt,
		ResponseTimer: challenge.ResponseTimer,
		State:         challenge.State,
		ProbeSize:     challenge.ProbeSize,
		done:          challenge.done,
	}
	if challenge.NewAddr != nil {
		addrCopy := *challenge.NewAddr
		pc.NewAddr = &addrCopy
	}
	return pc, true
}

// CleanupExpired processes expired path validation challenges.
//
// Per the SSU2 spec (Connection Migration), two timers apply:
//   - Path Response timer: if no Path Response is received before it expires,
//     the Path Challenge is resent and the timer is doubled.
//   - Path Validation timer: if it expires, path validation fails.
//
// This method resends challenges whose Path Response timer has expired (and
// doubles that timer), and fails challenges whose Path Validation timer has
// expired. Terminal-state entries are removed.
//
// Returns the number of challenges removed (failed or terminal-state).
func (pv *PathValidator) CleanupExpired() int {
	log.WithFields(logger.Fields{"pkg": "ssu2path", "func": "CleanupExpired"}).Debug("Processing expired path validation challenges")
	now := time.Now()

	// Phase 1: under the lock, classify challenges and collect resends.
	pv.mutex.Lock()
	cleaned := 0
	var resends []struct {
		challengeData []byte
		addr          *net.UDPAddr
	}

	for id, challenge := range pv.challenges {
		// Delete terminal-state entries that were not cleaned up at transition time
		// (e.g., due to a code path that predates the M-1/M-2 fixes).
		if challenge.State == ChallengeValidated || challenge.State == ChallengeFailed {
			delete(pv.challenges, id)
			cleaned++
			continue
		}

		// Path Validation timer expired: fail the challenge.
		if now.Sub(challenge.Timestamp) > PathValidationTimeout {
			challenge.State = ChallengeFailed
			// M-03 fix: close done channel so waitForProbeResult is woken up
			// instead of blocking until its own timer fires.
			if challenge.done != nil {
				close(challenge.done)
			}
			delete(pv.challenges, id)
			cleaned++
			continue
		}

		// Path Response timer expired: resend the challenge and double the timer.
		timer := challenge.ResponseTimer
		if timer <= 0 {
			timer = PathResponseBaseTimer
		}
		if now.Sub(challenge.LastSentAt) > timer {
			resends = append(resends, struct {
				challengeData []byte
				addr          *net.UDPAddr
			}{challenge.ChallengeData, challenge.NewAddr})
			challenge.ResponseTimer = timer * 2
			challenge.LastSentAt = now
		}
	}
	pv.mutex.Unlock()

	// Phase 2: outside the lock, resend challenges whose Path Response timer
	// expired. Sending while holding the lock risks deadlock if the transport
	// re-enters the validator.
	for _, r := range resends {
		if err := pv.SendPathChallenge(r.challengeData, r.addr); err != nil {
			log.WithFields(logger.Fields{"pkg": "ssu2path", "func": "CleanupExpired"}).
				Warnf("Failed to resend path challenge: %v", err)
		}
	}

	return cleaned
}

// generateChallengeData generates a cryptographically random 8-byte challenge
// payload. Per the SSU2 spec, Path Challenge data is arbitrary bytes (min 8
// bytes recommended); the Path Response must echo it verbatim.
func generateChallengeData() ([]byte, error) {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return nil, oops.Wrapf(err, "failed to read random bytes for challenge data")
	}
	return buf, nil
}

// InitiateMTUProbe starts an MTU probe by sending a Path Challenge padded
// to the given size. If a Path Response is received for this challenge,
// the discovered MTU is updated (G-5).
func (pv *PathValidator) InitiateMTUProbe(addr *net.UDPAddr, size int) ([]byte, error) {
	if addr == nil {
		return nil, oops.Errorf("address is nil")
	}
	if size < MinMTU || size > MaxMTU {
		return nil, oops.Errorf("probe size %d out of range [%d, %d]", size, MinMTU, MaxMTU)
	}

	core, err := generateChallengeData()
	if err != nil {
		return nil, oops.Wrapf(err, "failed to generate challenge data for MTU probe")
	}

	// The probe payload is the core challenge data padded to `size` bytes. Per
	// the SSU2 spec the Path Response echoes the challenge data verbatim, so the
	// peer returns the full padded payload — key the challenge by the exact bytes
	// sent so the echoed response matches.
	block := EncodePathChallengeWithPadding(core, size)
	challengeData := block.Data
	key := string(challengeData)

	now := time.Now()
	challenge := &PathChallenge{
		ChallengeData: challengeData,
		NewAddr:       addr,
		Timestamp:     now,
		LastSentAt:    now,
		ResponseTimer: PathResponseBaseTimer,
		State:         ChallengeSent,
		ProbeSize:     size,
		done:          make(chan struct{}),
	}

	pv.mutex.Lock()
	pv.challenges[key] = challenge
	pv.mutex.Unlock()

	if err := pv.conn.SendToAddress(block, addr); err != nil {
		pv.mutex.Lock()
		delete(pv.challenges, key)
		pv.mutex.Unlock()
		return nil, oops.Wrapf(err, "failed to send MTU probe of size %d", size)
	}

	return challengeData, nil
}

// CompleteMTUProbe is called when a Path Response is received for an MTU
// probe challenge. Updates discoveredMTU if this probe was larger than
// the previously discovered value (G-5).
func (pv *PathValidator) CompleteMTUProbe(challengeData []byte) {
	key := string(challengeData)
	pv.mutex.Lock()
	defer pv.mutex.Unlock()

	challenge, exists := pv.challenges[key]
	if !exists || challenge.ProbeSize == 0 {
		return
	}
	challenge.State = ChallengeValidated
	if challenge.ProbeSize > pv.discoveredMTU {
		pv.discoveredMTU = challenge.ProbeSize
	}
	// BUG-014 fix: Signal completion
	if challenge.done != nil {
		close(challenge.done)
	}
	// M-1 fix: delete terminal MTU probe entry to prevent memory leak.
	delete(pv.challenges, key)
}

// GetDiscoveredMTU returns the largest validated MTU from probing, or 0
// if no MTU probe has completed (G-5).
func (pv *PathValidator) GetDiscoveredMTU() int {
	pv.mutex.RLock()
	defer pv.mutex.RUnlock()
	return pv.discoveredMTU
}

// waitForProbeResult waits for a probe to complete or timeout.
// Returns true if the probe was validated, false otherwise.
// This helper reduces cyclomatic complexity in RunPMTUD.
func (pv *PathValidator) waitForProbeResult(ctx context.Context, challengeData []byte) bool {
	deadline := time.Now().Add(PathValidationTimeout)
	timeout := time.Until(deadline)
	if timeout < 0 {
		timeout = 0
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	ch, exists := pv.GetChallenge(challengeData)
	if !exists {
		return false
	}

	select {
	case <-ctx.Done():
		pv.FailPath(challengeData, ctx.Err())
		return false
	case <-ch.done:
		// done is closed on both success (ChallengeValidated) and failure (ChallengeFailed).
		// For MTU probes the challenge is deleted from the map on completion (M-1 fix),
		// so re-fetching with GetChallenge would find nothing. Instead, check whether
		// discoveredMTU reached the probe size — it is only updated on success. (H-1 fix)
		return pv.GetDiscoveredMTU() >= ch.ProbeSize
	case <-timer.C:
		// BUG-003 fix: check discoveredMTU before returning false.
		// When done and timer fire simultaneously, Go selects randomly between them.
		// If timer wins but the response was already processed, discoveredMTU will
		// reflect the successful probe — return the correct result rather than false.
		return pv.GetDiscoveredMTU() >= ch.ProbeSize
	}
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
// BUG-L02 fix: Refactored to reduce cyclomatic complexity by extracting probe logic.
func (pv *PathValidator) RunPMTUD(ctx context.Context, addr *net.UDPAddr, low, high int) int {
	log.WithFields(logger.Fields{"pkg": "ssu2path", "func": "RunPMTUD", "low": low, "high": high}).Debug("Running PMTUD")
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
		// BUG-M06 fix: Check context cancellation before each probe to avoid
		// unnecessary work and ensure timely cancellation response
		select {
		case <-ctx.Done():
			return best
		default:
		}

		// BUG-M04 fix: Use overflow-safe binary search calculation
		// mid := (low + high) / 2 could overflow if low + high > MaxInt32
		mid := low + (high-low)/2

		challengeData, err := pv.InitiateMTUProbe(addr, mid)
		if err != nil {
			high = mid - 1
			continue
		}

		if pv.waitForProbeResult(ctx, challengeData) {
			best = mid
			low = mid + 1
		} else {
			high = mid - 1
		}
	}

	return best
}
