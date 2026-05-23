package ssu2path

import (
	"net"
	"sync"
	"time"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// IntroducerRegistry maintains a list of introducers for publishing in RouterInfo.
// Introducers help peers behind NAT establish connections through relay mechanisms.
//
// Design rationale:
// - Maximum 3 introducers per I2P specification
// - Introducers are sorted by last seen time for freshness
// - Thread-safe for concurrent access
// - Defensive copies prevent external mutation
//
// Thread Safety: All public methods are thread-safe.
type IntroducerRegistry struct {
	// introducers is the list of registered introducers
	introducers []*RegisteredIntroducer

	// maxCount is the maximum number of introducers (typically 3)
	maxCount int

	// mutex protects all fields
	mutex sync.RWMutex
}

// RegisteredIntroducer represents an introducer registered for RouterInfo publication.
type RegisteredIntroducer struct {
	// Addr is the UDP address of the introducer
	Addr *net.UDPAddr

	// RouterHash is the 32-byte I2P router identity
	RouterHash []byte

	// StaticKey is the introducer's static public key for RouterInfo publication.
	// This is the 44-byte base64-encoded form (encoding 32 raw bytes) as required
	// by the RouterInfo address format. Other key fields in this package (e.g.,
	// IntroKeySize in key_rotation.go) use raw 32-byte slices (M-5).
	StaticKey []byte

	// IntroKey is the introducer's introduction key for RouterInfo publication.
	// This is the 44-byte base64-encoded form (encoding 32 raw bytes) as required
	// by the RouterInfo address format (M-5).
	IntroKey []byte

	// RelayTag is the tag assigned by this introducer
	RelayTag uint32

	// AddedAt is when this introducer was registered
	AddedAt time.Time

	// LastSeen is when we last communicated with this introducer
	LastSeen time.Time
}

// NewIntroducerRegistry creates a new IntroducerRegistry with the specified maximum count.
//
// Parameters:
//   - maxCount: Maximum number of introducers to maintain (typically 3 per I2P spec)
//
// Returns a new IntroducerRegistry.
func NewIntroducerRegistry(maxCount int) *IntroducerRegistry {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "NewIntroducerRegistry", "maxCount": maxCount}).Debug("Creating new IntroducerRegistry")
	if maxCount <= 0 {
		maxCount = 3 // Default per I2P spec
	}

	return &IntroducerRegistry{
		introducers: make([]*RegisteredIntroducer, 0, maxCount),
		maxCount:    maxCount,
	}
}

// AddIntroducer registers a new introducer or updates an existing one.
//
// Design rationale:
// - Updates existing introducer if address matches
// - Removes oldest introducer when at capacity
// - Validates all required fields
//
// Parameters:
//   - info: Introducer information to register
//
// Returns error if validation fails.
func (ir *IntroducerRegistry) AddIntroducer(info *RegisteredIntroducer) error {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "AddIntroducer"}).Debug("Adding introducer to registry")
	if err := validateIntroducer(info); err != nil {
		return err
	}

	ir.mutex.Lock()
	defer ir.mutex.Unlock()

	// Check if introducer already exists
	for i, intro := range ir.introducers {
		if intro.Addr.String() == info.Addr.String() {
			ir.introducers[i] = ir.copyIntroducer(info)
			return nil
		}
	}

	// Add new introducer or replace oldest
	if len(ir.introducers) < ir.maxCount {
		ir.introducers = append(ir.introducers, ir.copyIntroducer(info))
	} else {
		ir.introducers[ir.findOldestIndex()] = ir.copyIntroducer(info)
	}

	return nil
}

// validateIntroducer checks that all required fields are present and valid.
func validateIntroducer(info *RegisteredIntroducer) error {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "validateIntroducer"}).Debug("Validating introducer fields")
	if info == nil {
		return oops.
			Code("INVALID_INTRODUCER").
			In("introducer_registry").
			Errorf("introducer info cannot be nil")
	}

	if info.Addr == nil {
		return oops.
			Code("INVALID_ADDRESS").
			In("introducer_registry").
			Errorf("introducer address cannot be nil")
	}

	if len(info.RouterHash) != 32 {
		return oops.
			Code("INVALID_ROUTER_HASH").
			In("introducer_registry").
			With("hash_length", len(info.RouterHash)).
			Errorf("router hash must be exactly 32 bytes")
	}

	if len(info.StaticKey) != 44 {
		return oops.
			Code("INVALID_STATIC_KEY").
			In("introducer_registry").
			With("key_length", len(info.StaticKey)).
			Errorf("static key must be exactly 44 bytes (base64)")
	}

	if len(info.IntroKey) != 44 {
		return oops.
			Code("INVALID_INTRO_KEY").
			In("introducer_registry").
			With("key_length", len(info.IntroKey)).
			Errorf("intro key must be exactly 44 bytes (base64)")
	}

	if info.RelayTag == 0 {
		return oops.
			Code("INVALID_RELAY_TAG").
			In("introducer_registry").
			Errorf("relay tag cannot be zero")
	}

	return nil
}

// findOldestIndex returns the index of the introducer with the oldest LastSeen time.
// Must be called with ir.mutex held.
func (ir *IntroducerRegistry) findOldestIndex() int {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "findOldestIndex", "count": len(ir.introducers)}).Debug("Locating oldest introducer")
	oldestIdx := 0
	oldestTime := ir.introducers[0].LastSeen
	for i, intro := range ir.introducers[1:] {
		if intro.LastSeen.Before(oldestTime) {
			oldestIdx = i + 1
			oldestTime = intro.LastSeen
		}
	}
	return oldestIdx
}

// RemoveIntroducer removes an introducer by address.
// Note: This method uses swap-and-truncate for O(1) removal, which does NOT preserve
// the order of remaining introducers. If the removed introducer is not the last element,
// the last introducer will be moved to the removed position.
//
// Parameters:
//   - addr: UDP address of the introducer to remove
//
// BUG-L03 fix: Documented order instability in removal operation.
func (ir *IntroducerRegistry) RemoveIntroducer(addr *net.UDPAddr) {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "RemoveIntroducer"}).Debug("Removing introducer by address")
	if addr == nil {
		return
	}

	ir.mutex.Lock()
	defer ir.mutex.Unlock()

	for i, intro := range ir.introducers {
		if intro.Addr.String() == addr.String() {
			// Remove by swapping with last and truncating
			ir.introducers[i] = ir.introducers[len(ir.introducers)-1]
			ir.introducers = ir.introducers[:len(ir.introducers)-1]
			return
		}
	}
}

// GetIntroducers returns all registered introducers.
//
// Returns a defensive copy of the introducer list.
func (ir *IntroducerRegistry) GetIntroducers() []*RegisteredIntroducer {
	ir.mutex.RLock()
	defer ir.mutex.RUnlock()

	result := make([]*RegisteredIntroducer, len(ir.introducers))
	for i, intro := range ir.introducers {
		result[i] = ir.copyIntroducer(intro)
	}

	return result
}

// UpdateLastSeen updates the last seen time for an introducer.
//
// Parameters:
//   - addr: UDP address of the introducer
func (ir *IntroducerRegistry) UpdateLastSeen(addr *net.UDPAddr) {
	if addr == nil {
		return
	}

	ir.mutex.Lock()
	defer ir.mutex.Unlock()

	for _, intro := range ir.introducers {
		if intro.Addr.String() == addr.String() {
			intro.LastSeen = time.Now()
			return
		}
	}
}

// SelectBestIntroducers selects the best introducers based on recency.
//
// Design rationale:
// - Returns introducers sorted by most recently seen
// - Returns up to count introducers
// - Ensures fresh introducers are prioritized
//
// Parameters:
//   - count: Maximum number of introducers to select
//
// Returns selected introducers (up to count).
func (ir *IntroducerRegistry) SelectBestIntroducers(count int) []*RegisteredIntroducer {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "SelectBestIntroducers", "count": count}).Debug("Selecting best introducers by recency")
	if count <= 0 {
		return nil
	}

	ir.mutex.RLock()
	defer ir.mutex.RUnlock()

	if len(ir.introducers) == 0 {
		return nil
	}

	// Create a copy and sort by LastSeen (most recent first)
	sorted := make([]*RegisteredIntroducer, len(ir.introducers))
	copy(sorted, ir.introducers)

	// Simple selection sort by LastSeen (descending)
	for i := 0; i < len(sorted)-1; i++ {
		maxIdx := i
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j].LastSeen.After(sorted[maxIdx].LastSeen) {
				maxIdx = j
			}
		}
		if maxIdx != i {
			sorted[i], sorted[maxIdx] = sorted[maxIdx], sorted[i]
		}
	}

	// Return up to count introducers
	if count > len(sorted) {
		count = len(sorted)
	}

	result := make([]*RegisteredIntroducer, count)
	for i := 0; i < count; i++ {
		result[i] = ir.copyIntroducer(sorted[i])
	}

	return result
}

// GetCount returns the current number of registered introducers.
func (ir *IntroducerRegistry) GetCount() int {
	ir.mutex.RLock()
	defer ir.mutex.RUnlock()

	return len(ir.introducers)
}

// GetMaxCount returns the maximum number of introducers allowed.
func (ir *IntroducerRegistry) GetMaxCount() int {
	ir.mutex.RLock()
	defer ir.mutex.RUnlock()

	return ir.maxCount
}

// copyIntroducer creates a defensive copy of a RegisteredIntroducer.
func (ir *IntroducerRegistry) copyIntroducer(intro *RegisteredIntroducer) *RegisteredIntroducer {
	if intro == nil {
		return nil
	}

	result := &RegisteredIntroducer{
		RouterHash: make([]byte, len(intro.RouterHash)),
		StaticKey:  make([]byte, len(intro.StaticKey)),
		IntroKey:   make([]byte, len(intro.IntroKey)),
		RelayTag:   intro.RelayTag,
		AddedAt:    intro.AddedAt,
		LastSeen:   intro.LastSeen,
	}
	if intro.Addr != nil {
		addrCopy := *intro.Addr
		result.Addr = &addrCopy
	}

	copy(result.RouterHash, intro.RouterHash)
	copy(result.StaticKey, intro.StaticKey)
	copy(result.IntroKey, intro.IntroKey)

	return result
}
