package path

import (
	"crypto/rand"
	"encoding/binary"
	"net"
	"sync"
	"time"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// RelayResponseTokenTTL is the maximum lifetime for a relay response token.
// Per SSU2 spec, "The token must be used immediately by Alice in the Session Request."
// We enforce a 10-second window to allow for network latency while still
// requiring near-immediate use.
const RelayResponseTokenTTL = 10 * time.Second

// RelayManager manages relay connections and introducer services for NAT traversal.
// It handles relay tag allocation, introducer registration, and relay request processing.
//
// Design rationale:
// - Relay tags are cryptographically random 4-byte values for security
// - Introducers expire after 1 hour (I2P spec recommendation)
// - Pending sessions track connections awaiting hole punch completion
// - Thread-safe for concurrent relay operations
//
// Thread Safety: All public methods are thread-safe.
type RelayManager struct {
	// listener is the parent SSU2Listener
	listener ListenerRef

	// introducers tracks available introducers for this peer
	introducers []*IntroducerInfo

	// relayTags maps tag to relay information
	relayTags map[uint32]*RelayTag

	// pendingSessions maps session ID to pending connection
	pendingSessions map[uint64]*PendingSession

	// mutex protects all fields
	mutex sync.RWMutex

	// cleanupTimer periodically removes expired entries
	cleanupTimer *time.Timer

	// stopped is set by Stop() to prevent writes to nil maps after shutdown
	stopped bool

	// stopOnce ensures Stop() is idempotent and cannot panic on double-call.
	stopOnce sync.Once
}

// IntroducerInfo represents an available introducer for NAT traversal.
type IntroducerInfo struct {
	// Addr is the UDP address of the introducer
	Addr *net.UDPAddr

	// RouterHash is the I2P router identity hash
	RouterHash data.Hash

	// RelayTag is the tag assigned by the introducer
	RelayTag uint32

	// ExpiresAt is when this introducer registration expires
	ExpiresAt time.Time
}

// RelayTag represents an active relay tag allocation.
type RelayTag struct {
	// Tag is the 4-byte relay tag value
	Tag uint32

	// ForAddr is the address this tag was allocated for
	ForAddr *net.UDPAddr

	// CreatedAt is when this tag was created
	CreatedAt time.Time

	// ExpiresAt is when this tag expires
	ExpiresAt time.Time
}

// PendingSession represents a connection awaiting hole punch completion.
type PendingSession struct {
	// SessionID uniquely identifies this pending session
	SessionID uint64

	// RemoteAddr is the target peer's UDP address
	RemoteAddr *net.UDPAddr

	// IntroducerAddr is the introducer being used
	IntroducerAddr *net.UDPAddr

	// RelayTag is the tag provided by the introducer
	RelayTag uint32

	// CreatedAt is when this session was initiated
	CreatedAt time.Time

	// Retries tracks the number of retry attempts
	Retries int
}

// NewRelayManager creates a new RelayManager for the specified listener.
//
// Parameters:
//   - listener: The SSU2Listener to manage relays for
//
// Returns a new RelayManager with empty state.
func NewRelayManager(listener ListenerRef) *RelayManager {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "NewRelayManager"}).Debug("Creating new RelayManager")
	rm := &RelayManager{
		listener:        listener,
		introducers:     make([]*IntroducerInfo, 0, 3), // I2P spec allows up to 3
		relayTags:       make(map[uint32]*RelayTag),
		pendingSessions: make(map[uint64]*PendingSession),
	}

	// Start cleanup timer (every 5 minutes)
	rm.cleanupTimer = time.AfterFunc(5*time.Minute, rm.CleanupExpired)

	return rm
}

// Stop stops the relay manager and cleans up resources.
// Safe to call multiple times (idempotent).
func (rm *RelayManager) Stop() {
	rm.stopOnce.Do(func() {
		log.WithFields(logger.Fields{"pkg": "ssu2", "func": "Stop"}).Debug("Stopping RelayManager")
		rm.mutex.Lock()
		defer rm.mutex.Unlock()

		if rm.cleanupTimer != nil {
			rm.cleanupTimer.Stop()
			rm.cleanupTimer = nil
		}

		// Clear all state
		rm.stopped = true
		rm.introducers = nil
		rm.relayTags = nil
		rm.pendingSessions = nil
	})
}

// RegisterIntroducer registers a new introducer for this peer.
// The introducer can be used to relay connection requests to this peer when behind NAT.
//
// Design rationale:
// - Maximum 3 introducers per I2P spec
// - Introducers expire after 1 hour
// - Oldest introducer is replaced if at capacity
//
// Parameters:
//   - addr: UDP address of the introducer
//   - routerHash: router identity hash of the introducer
//   - relayTag: Tag assigned by the introducer for relay requests
//
// Returns error if parameters are invalid.
func (rm *RelayManager) RegisterIntroducer(addr *net.UDPAddr, routerHash data.Hash, relayTag uint32) error {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "RegisterIntroducer", "relayTag": relayTag}).Debug("Registering introducer")
	if addr == nil {
		return oops.
			Code("INVALID_ADDRESS").
			In("relay_manager").
			Errorf("introducer address cannot be nil")
	}

	if relayTag == 0 {
		return oops.
			Code("INVALID_RELAY_TAG").
			In("relay_manager").
			Errorf("relay tag cannot be zero")
	}

	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	// BUG-007 fix: Check if manager has been stopped
	if rm.stopped {
		return oops.
			Code("MANAGER_STOPPED").
			In("relay_manager").
			Errorf("relay manager has been stopped")
	}

	// Check if already registered
	for _, intro := range rm.introducers {
		if intro.Addr.String() == addr.String() {
			// Update existing
			intro.RelayTag = relayTag
			intro.ExpiresAt = time.Now().Add(1 * time.Hour)
			return nil
		}
	}

	// Create new introducer info
	info := &IntroducerInfo{
		Addr:       addr,
		RouterHash: routerHash,
		RelayTag:   relayTag,
		ExpiresAt:  time.Now().Add(1 * time.Hour),
	}

	// Add or replace oldest
	if len(rm.introducers) < 3 {
		rm.introducers = append(rm.introducers, info)
	} else {
		// Replace oldest introducer
		oldest := 0
		for i, intro := range rm.introducers {
			if intro.ExpiresAt.Before(rm.introducers[oldest].ExpiresAt) {
				oldest = i
			}
		}
		rm.introducers[oldest] = info
	}

	return nil
}

// GetIntroducers returns a copy of all active introducers.
//
// Returns a slice of IntroducerInfo pointers (defensive copies).
func (rm *RelayManager) GetIntroducers() []*IntroducerInfo {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "GetIntroducers"}).Debug("Retrieving active introducers")
	rm.mutex.RLock()
	defer rm.mutex.RUnlock()

	// BUG-007 fix: Return empty if stopped
	if rm.stopped {
		return nil
	}

	// Create defensive copies
	result := make([]*IntroducerInfo, 0, len(rm.introducers))
	now := time.Now()

	for _, intro := range rm.introducers {
		if intro.ExpiresAt.After(now) {
			infoCopy := &IntroducerInfo{
				RouterHash: intro.RouterHash,
				RelayTag:   intro.RelayTag,
				ExpiresAt:  intro.ExpiresAt,
			}
			if intro.Addr != nil {
				addrCopy := *intro.Addr
				infoCopy.Addr = &addrCopy
			}
			result = append(result, infoCopy)
		}
	}

	return result
}

// RemoveIntroducer removes an introducer by address.
//
// Parameters:
//   - addr: UDP address of the introducer to remove
func (rm *RelayManager) RemoveIntroducer(addr *net.UDPAddr) {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "RemoveIntroducer", "addr": addr}).Debug("Removing introducer")
	if addr == nil {
		return
	}

	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	// BUG-007 fix: Return early if stopped
	if rm.stopped {
		return
	}

	for i, intro := range rm.introducers {
		if intro.Addr.String() == addr.String() {
			// Remove by replacing with last element and shrinking
			rm.introducers[i] = rm.introducers[len(rm.introducers)-1]
			rm.introducers = rm.introducers[:len(rm.introducers)-1]
			return
		}
	}
}

// AllocateRelayTag allocates a new relay tag for the specified address.
// Relay tags are used to identify connections being relayed through this peer.
//
// Design rationale:
// - Tags are cryptographically random 4-byte values
// - Tags expire after 1 hour per I2P spec
// - Zero tag is reserved and never allocated
//
// Parameters:
//   - addr: UDP address to allocate tag for
//
// Returns the allocated tag, or error if allocation fails.
func (rm *RelayManager) AllocateRelayTag(addr *net.UDPAddr) (uint32, error) {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "AllocateRelayTag"}).Debug("Allocating relay tag")
	if addr == nil {
		return 0, oops.
			Code("INVALID_ADDRESS").
			In("relay_manager").
			Errorf("address cannot be nil")
	}

	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	if rm.stopped {
		return 0, oops.
			Code("MANAGER_STOPPED").
			In("relay_manager").
			Errorf("relay manager has been stopped")
	}

	const maxAttempts = 3
	for attempt := 0; attempt < maxAttempts; attempt++ {
		var tag uint32
		for tag == 0 {
			var buf [4]byte
			if _, err := rand.Read(buf[:]); err != nil {
				return 0, oops.
					Code("TAG_GENERATION_FAILED").
					In("relay_manager").
					Wrapf(err, "failed to generate relay tag")
			}
			tag = binary.BigEndian.Uint32(buf[:])
		}

		if _, exists := rm.relayTags[tag]; exists {
			continue
		}

		rm.relayTags[tag] = &RelayTag{
			Tag:       tag,
			ForAddr:   addr,
			CreatedAt: time.Now(),
			ExpiresAt: time.Now().Add(1 * time.Hour),
		}
		return tag, nil
	}

	return 0, oops.
		Code("TAG_COLLISION").
		In("relay_manager").
		Errorf("relay tag collision after %d attempts", maxAttempts)
}

// ValidateRelayTag validates that a relay tag is active and matches the specified address.
//
// Parameters:
//   - tag: Relay tag to validate
//   - addr: Expected address for the tag
//
// Returns true if tag is valid and matches address.
func (rm *RelayManager) ValidateRelayTag(tag uint32, addr *net.UDPAddr) bool {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "ValidateRelayTag", "tag": tag}).Debug("Validating relay tag")
	if tag == 0 || addr == nil {
		return false
	}

	rm.mutex.RLock()
	defer rm.mutex.RUnlock()

	// BUG-007 fix: Return false if stopped
	if rm.stopped {
		return false
	}

	relayTag, exists := rm.relayTags[tag]
	if !exists {
		return false
	}

	// Check expiration
	if time.Now().After(relayTag.ExpiresAt) {
		return false
	}

	// BUG-008 fix: Guard against nil ForAddr
	if relayTag.ForAddr == nil {
		return false
	}

	// Check address match
	return relayTag.ForAddr.String() == addr.String()
}

// GetRelayTag retrieves relay tag information.
//
// Parameters:
//   - tag: Relay tag to look up
//
// Returns RelayTag info, or nil if not found.
func (rm *RelayManager) GetRelayTag(tag uint32) *RelayTag {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "GetRelayTag", "tag": tag}).Debug("Retrieving relay tag info")
	if tag == 0 {
		return nil
	}

	rm.mutex.RLock()
	defer rm.mutex.RUnlock()

	// BUG-007 fix: Return nil if stopped
	if rm.stopped {
		return nil
	}

	relayTag, exists := rm.relayTags[tag]
	if !exists || time.Now().After(relayTag.ExpiresAt) {
		return nil
	}

	// Return defensive copy
	copied := &RelayTag{
		Tag:       relayTag.Tag,
		CreatedAt: relayTag.CreatedAt,
		ExpiresAt: relayTag.ExpiresAt,
	}
	// BUG-003 fix: Deep copy ForAddr to prevent aliasing
	if relayTag.ForAddr != nil {
		addrCopy := *relayTag.ForAddr
		// Deep copy IP slice to prevent shared memory
		if addrCopy.IP != nil {
			addrCopy.IP = make(net.IP, len(addrCopy.IP))
			copy(addrCopy.IP, relayTag.ForAddr.IP)
		}
		copied.ForAddr = &addrCopy
	}
	return copied
}

// AddPendingSession adds a session awaiting hole punch completion.
//
// Parameters:
//   - sessionID: Unique session identifier
//   - remoteAddr: Target peer's UDP address
//   - introducerAddr: Introducer's UDP address
//   - relayTag: Tag for relay requests
//
// Returns error if parameters are invalid.
func (rm *RelayManager) AddPendingSession(sessionID uint64, remoteAddr, introducerAddr *net.UDPAddr, relayTag uint32) error {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "AddPendingSession", "sessionID": sessionID}).Debug("Adding pending session")
	if sessionID == 0 {
		return oops.
			Code("INVALID_SESSION_ID").
			In("relay_manager").
			Errorf("session ID cannot be zero")
	}

	if remoteAddr == nil || introducerAddr == nil {
		return oops.
			Code("INVALID_ADDRESS").
			In("relay_manager").
			Errorf("addresses cannot be nil")
	}

	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	if rm.stopped {
		return oops.
			Code("MANAGER_STOPPED").
			In("relay_manager").
			Errorf("relay manager has been stopped")
	}

	rm.pendingSessions[sessionID] = &PendingSession{
		SessionID:      sessionID,
		RemoteAddr:     remoteAddr,
		IntroducerAddr: introducerAddr,
		RelayTag:       relayTag,
		CreatedAt:      time.Now(),
		Retries:        0,
	}

	return nil
}

// GetPendingSession retrieves a pending session by ID.
//
// Parameters:
//   - sessionID: Session identifier
//
// Returns PendingSession info, or nil if not found.
func (rm *RelayManager) GetPendingSession(sessionID uint64) *PendingSession {
	rm.mutex.RLock()
	defer rm.mutex.RUnlock()

	session, exists := rm.pendingSessions[sessionID]
	if !exists {
		return nil
	}

	// Return defensive copy
	copy := &PendingSession{
		SessionID: session.SessionID,
		RelayTag:  session.RelayTag,
		CreatedAt: session.CreatedAt,
		Retries:   session.Retries,
	}
	if session.RemoteAddr != nil {
		addrCopy := *session.RemoteAddr
		copy.RemoteAddr = &addrCopy
	}
	if session.IntroducerAddr != nil {
		addrCopy := *session.IntroducerAddr
		copy.IntroducerAddr = &addrCopy
	}
	return copy
}

// RemovePendingSession removes a pending session.
//
// Parameters:
//   - sessionID: Session identifier to remove
func (rm *RelayManager) RemovePendingSession(sessionID uint64) {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	delete(rm.pendingSessions, sessionID)
}

// IncrementRetries increments the retry counter for a pending session.
//
// Parameters:
//   - sessionID: Session identifier
//
// Returns the new retry count, or -1 if session not found.
func (rm *RelayManager) IncrementRetries(sessionID uint64) int {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	session, exists := rm.pendingSessions[sessionID]
	if !exists {
		return -1
	}

	session.Retries++
	return session.Retries
}

// CleanupExpired removes expired relay tags, introducers, and pending sessions.
// This is called periodically by the cleanup timer.
func (rm *RelayManager) CleanupExpired() {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "cleanupExpired"}).Debug("Removing expired relay tags and introducers")
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	if rm.stopped {
		return
	}

	now := time.Now()

	// Clean expired relay tags
	for tag, relayTag := range rm.relayTags {
		if now.After(relayTag.ExpiresAt) {
			delete(rm.relayTags, tag)
		}
	}

	// Clean expired introducers
	validIntroducers := make([]*IntroducerInfo, 0, len(rm.introducers))
	for _, intro := range rm.introducers {
		if now.Before(intro.ExpiresAt) {
			validIntroducers = append(validIntroducers, intro)
		}
	}
	rm.introducers = validIntroducers

	// Clean old pending sessions (timeout after 30 seconds)
	for sessionID, session := range rm.pendingSessions {
		if now.Sub(session.CreatedAt) > 30*time.Second {
			delete(rm.pendingSessions, sessionID)
		}
	}

	// Reschedule cleanup
	if rm.cleanupTimer != nil {
		rm.cleanupTimer.Reset(5 * time.Minute)
	}
}

// GetStats returns statistics about the relay manager state.
func (rm *RelayManager) GetStats() map[string]int {
	rm.mutex.RLock()
	defer rm.mutex.RUnlock()

	return map[string]int{
		"introducers":      len(rm.introducers),
		"relay_tags":       len(rm.relayTags),
		"pending_sessions": len(rm.pendingSessions),
	}
}

// ExpireAllIntroducers immediately expires all registered introducers (test helper).
func (rm *RelayManager) ExpireAllIntroducers() {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()
	for i := range rm.introducers {
		rm.introducers[i].ExpiresAt = time.Now().Add(-1 * time.Hour)
	}
}

// GetListener returns the listener reference (for testing).
func (rm *RelayManager) GetListener() ListenerRef {
	return rm.listener
}

// GetAllIntroducers returns all introducers including expired (for testing).
func (rm *RelayManager) GetAllIntroducers() []*IntroducerInfo {
	rm.mutex.RLock()
	defer rm.mutex.RUnlock()
	result := make([]*IntroducerInfo, len(rm.introducers))
	copy(result, rm.introducers)
	return result
}

// GetRelayTagsMap returns a copy of the relay tags map (for testing).
func (rm *RelayManager) GetRelayTagsMap() map[uint32]*RelayTag {
	rm.mutex.RLock()
	defer rm.mutex.RUnlock()
	result := make(map[uint32]*RelayTag, len(rm.relayTags))
	for k, v := range rm.relayTags {
		result[k] = v
	}
	return result
}

// GetPendingSessionsMap returns a copy of the pending sessions map (for testing).
func (rm *RelayManager) GetPendingSessionsMap() map[uint64]*PendingSession {
	rm.mutex.RLock()
	defer rm.mutex.RUnlock()
	result := make(map[uint64]*PendingSession, len(rm.pendingSessions))
	for k, v := range rm.pendingSessions {
		result[k] = v
	}
	return result
}

// SetRelayTagExpiry sets the expiry of a relay tag (for testing).
func (rm *RelayManager) SetRelayTagExpiry(tag uint32, t time.Time) {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()
	if relayTag, exists := rm.relayTags[tag]; exists {
		relayTag.ExpiresAt = t
	}
}

// SetIntroducerExpiry sets the expiry of the introducer at given index (for testing).
func (rm *RelayManager) SetIntroducerExpiry(idx int, t time.Time) {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()
	if idx < len(rm.introducers) {
		rm.introducers[idx].ExpiresAt = t
	}
}
