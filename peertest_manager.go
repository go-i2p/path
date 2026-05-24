package ssu2path

import (
	"crypto/rand"
	"encoding/binary"
	"net"
	"sync"
	"time"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// PeerTestManager manages the seven-message NAT traversal testing protocol.
// It coordinates peer tests to determine NAT type and external reachability.
//
// Design rationale:
// - Nonce generation uses crypto/rand for security
// - State machine tracks test progression through 7 messages
// - Results cached by remote address for efficiency
// - Thread-safe for concurrent test operations
//
// Protocol flow:
// 1. Alice → Bob: Request (InitiatePeerTest)
// 2. Bob → Charlie: Relay request
// 3. Charlie → Bob: Relay response
// 4. Bob → Alice: Result
// 5. Charlie → Alice: Probe
// 6. Alice → Charlie: Reply
// 7. Charlie → Alice: Confirmation
//
// Thread Safety: All public methods are thread-safe.
type PeerTestManager struct {
	// listener is the parent SSU2Listener
	listener ListenerRef

	// tests maps nonce to active peer test
	tests map[uint32]*PeerTest

	// results maps remote address to test result
	results map[string]*TestResult

	// mutex protects all fields
	mutex sync.RWMutex

	// stopCh is closed by Stop() to signal the cleanup goroutine to exit.
	stopCh chan struct{}

	// stopOnce ensures Stop() is idempotent and cannot panic on double-call.
	stopOnce sync.Once
}

// PeerTestRole represents the role of a peer in the test.
type PeerTestRole int

const (
	// RoleInitiator is Alice who initiates the test
	RoleInitiator PeerTestRole = iota

	// RoleRelay is Bob who relays messages
	RoleRelay

	// RoleResponder is Charlie who responds to test
	RoleResponder
)

// String returns human-readable role name.
func (r PeerTestRole) String() string {
	switch r {
	case RoleInitiator:
		return "Initiator"
	case RoleRelay:
		return "Relay"
	case RoleResponder:
		return "Responder"
	default:
		return "Unknown"
	}
}

// PeerTestState represents the current state of a peer test.
type PeerTestState int

const (
	// TestRequested indicates test has been requested
	TestRequested PeerTestState = iota

	// TestRelayed indicates test has been relayed to responder
	TestRelayed

	// TestProbed indicates probe has been sent
	TestProbed

	// TestComplete indicates test completed successfully
	TestComplete

	// TestFailed indicates test failed
	TestFailed
)

// String returns human-readable state name.
func (s PeerTestState) String() string {
	switch s {
	case TestRequested:
		return "Requested"
	case TestRelayed:
		return "Relayed"
	case TestProbed:
		return "Probed"
	case TestComplete:
		return "Complete"
	case TestFailed:
		return "Failed"
	default:
		return "Unknown"
	}
}

// NonceConnectionIDs derives deterministic connection IDs from a 4-byte nonce
// per spec: dest = (uint64(nonce) << 32) | uint64(nonce), src = ^dest.
// Used for out-of-session PeerTest (messages 5-7) and HolePunch packets.
func NonceConnectionIDs(nonce uint32) (dest, src uint64) {
	dest = (uint64(nonce) << 32) | uint64(nonce)
	src = ^dest
	return dest, src
}

// PeerTest represents an active peer test operation.
type PeerTest struct {
	// Nonce uniquely identifies this test
	Nonce uint32

	// DestConnectionID is the nonce-derived destination connection ID
	// for out-of-session PeerTest packets (messages 5-7).
	DestConnectionID uint64

	// SrcConnectionID is the nonce-derived source connection ID
	// for out-of-session PeerTest packets (messages 5-7).
	SrcConnectionID uint64

	// Role is this peer's role in the test
	Role PeerTestRole

	// State is the current test state
	State PeerTestState

	// AliceAddr is the initiator's address
	AliceAddr *net.UDPAddr

	// BobAddr is the relay's address
	BobAddr *net.UDPAddr

	// CharlieAddr is the responder's address
	CharlieAddr *net.UDPAddr

	// StartTime is when the test was initiated
	StartTime time.Time

	// Timeouts tracks timeout times for each message
	Timeouts []time.Time

	// NATType is the determined NAT type
	NATType NATType

	// Reachable indicates if peer is directly reachable
	Reachable bool

	// ExternalAddr is the detected external address
	ExternalAddr *net.UDPAddr
}

// NATType represents the type of NAT detected.
type NATType int

const (
	// NATUnknown indicates NAT type is not yet determined
	NATUnknown NATType = iota

	// NATNone indicates no NAT (public IP)
	NATNone

	// NATCone indicates full cone NAT
	NATCone

	// NATRestricted indicates restricted cone NAT
	NATRestricted

	// NATPortRestricted indicates port-restricted cone NAT
	NATPortRestricted

	// NATSymmetric indicates symmetric NAT
	NATSymmetric
)

// String returns human-readable NAT type name.
func (n NATType) String() string {
	switch n {
	case NATUnknown:
		return "Unknown"
	case NATNone:
		return "None"
	case NATCone:
		return "Full Cone"
	case NATRestricted:
		return "Restricted Cone"
	case NATPortRestricted:
		return "Port-Restricted Cone"
	case NATSymmetric:
		return "Symmetric"
	default:
		return "Unknown"
	}
}

// TestResult stores the results of a completed peer test.
type TestResult struct {
	// NATType is the determined NAT type
	NATType NATType

	// ExternalAddr is the detected external address
	ExternalAddr *net.UDPAddr

	// ExternalPort is the detected external port
	ExternalPort uint16

	// Reachable indicates if peer is directly reachable
	Reachable bool

	// TestTime is when the test completed
	TestTime time.Time

	// DirectProbeSuccess indicates if Charlie → Alice direct probe succeeded
	DirectProbeSuccess bool

	// RelayedProbeSuccess indicates if Charlie → Alice via Bob succeeded
	RelayedProbeSuccess bool

	// PortConsistent indicates if external port is consistent
	PortConsistent bool

	// IPConsistent indicates if external IP is consistent
	IPConsistent bool
}

// NewPeerTestManager creates a new PeerTestManager.
//
// Parameters:
//   - listener: The SSU2Listener to manage peer tests for
//
// Returns a new PeerTestManager with empty state.
func NewPeerTestManager(listener ListenerRef) *PeerTestManager {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "NewPeerTestManager"}).Debug("Creating new PeerTestManager")
	ptm := &PeerTestManager{
		listener: listener,
		tests:    make(map[uint32]*PeerTest),
		results:  make(map[string]*TestResult),
		stopCh:   make(chan struct{}),
	}
	go ptm.cleanupLoop()
	return ptm
}

// Stop halts the background cleanup goroutine. Call when the manager is
// no longer needed to avoid goroutine leaks. Safe to call multiple times.
func (ptm *PeerTestManager) Stop() {
	ptm.stopOnce.Do(func() { close(ptm.stopCh) })
}

// cleanupLoop periodically removes expired peer tests.
// BUG-L04: 60-second interval matches I2P SSU2 spec §Peer Test timeout.
// Peer tests use 7 messages and involve 3 parties (Alice, Bob, Charlie),
// so longer timeout than hole punch (30s) or path validation (10s).
func (ptm *PeerTestManager) cleanupLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			ptm.CleanupExpired()
		case <-ptm.stopCh:
			return
		}
	}
}

// InitiatePeerTest starts a new peer test as Alice (initiator).
//
// Design rationale:
// - Generates cryptographically random nonce for test identification
// - Creates test record with 60-second timeout per I2P spec
// - Returns nonce for tracking test progress
//
// Parameters:
//   - bobAddr: Address of Bob (relay peer)
//
// Returns nonce on success, error otherwise.
func (ptm *PeerTestManager) InitiatePeerTest(bobAddr *net.UDPAddr) (uint32, error) {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "InitiatePeerTest"}).Debug("Initiating peer test")
	if bobAddr == nil {
		return 0, oops.
			Code("INVALID_ADDRESS").
			In("peertest_manager").
			Errorf("bob address cannot be nil")
	}
	if !IsValidSourcePort(bobAddr) {
		return 0, oops.
			Code("INVALID_PORT").
			In("peertest_manager").
			With("port", bobAddr.Port).
			Errorf("bob address has invalid source port %d", bobAddr.Port)
	}

	var nonce uint32

	ptm.mutex.Lock()
	defer ptm.mutex.Unlock()

	// Retry nonce generation on collision (extremely unlikely but safe).
	const maxRetries = 10
	for attempt := 0; attempt < maxRetries; attempt++ {
		var nonceBytes [4]byte
		if _, err := rand.Read(nonceBytes[:]); err != nil {
			return 0, oops.
				Code("RANDOM_GENERATION_FAILED").
				In("peertest_manager").
				Wrapf(err, "failed to generate nonce")
		}
		nonce = binary.BigEndian.Uint32(nonceBytes[:])
		if nonce == 0 {
			nonce = 1
		}
		if _, exists := ptm.tests[nonce]; !exists {
			break
		}
		// BUG-M05 fix: Log collision at WARN level with diagnostic info
		log.WithFields(logger.Fields{
			"pkg":          "ssu2",
			"func":         "InitiatePeerTest",
			"attempt":      attempt + 1,
			"active_tests": len(ptm.tests),
			"load_factor":  float64(len(ptm.tests)) / float64(1<<32) * 100,
		}).Warn("Peer test nonce collision detected - retrying")

		if attempt == maxRetries-1 {
			// BUG-M05 fix: Include diagnostic info in error for debugging
			return 0, oops.
				Code("NONCE_EXHAUSTED").
				In("peertest_manager").
				With("active_tests", len(ptm.tests)).
				With("max_attempts", maxRetries).
				Errorf("failed to generate unique nonce after %d attempts (active tests: %d, load factor: %.6f%%)",
					maxRetries, len(ptm.tests), float64(len(ptm.tests))/float64(1<<32)*100)
		}
	}

	// Derive deterministic connection IDs from nonce per spec
	destConnID, srcConnID := NonceConnectionIDs(nonce)

	// Create peer test
	test := &PeerTest{
		Nonce:            nonce,
		DestConnectionID: destConnID,
		SrcConnectionID:  srcConnID,
		Role:             RoleInitiator,
		State:            TestRequested,
		BobAddr:          bobAddr,
		StartTime:        time.Now(),
		Timeouts:         make([]time.Time, 7), // 7 messages in protocol
	}

	// Set timeout for first message (60 seconds per I2P spec)
	test.Timeouts[0] = time.Now().Add(60 * time.Second)

	ptm.tests[nonce] = test

	return nonce, nil
}

// GetTest retrieves peer test information by nonce.
//
// Parameters:
//   - nonce: Test nonce
//
// Returns test copy, or nil if not found.
//
// Performance Note (BUG-L05): This method returns a defensive copy to prevent
// external mutation of internal state. This involves 4-5 allocations per call
// (UDPAddr copies + struct copy). The current approach prioritizes safety over
// performance and is acceptable for typical usage patterns. If profiling reveals
// this is a hot path causing GC pressure, consider alternatives like read-only
// views or sync.Pool, but only after demonstrating actual performance impact.
func (ptm *PeerTestManager) GetTest(nonce uint32) *PeerTest {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "GetTest", "nonce": nonce}).Debug("Retrieving peer test")
	if nonce == 0 {
		return nil
	}

	ptm.mutex.RLock()
	defer ptm.mutex.RUnlock()

	test, exists := ptm.tests[nonce]
	if !exists {
		return nil
	}

	// Return defensive copy
	testCopy := *test
	if test.AliceAddr != nil {
		addr := *test.AliceAddr
		testCopy.AliceAddr = &addr
	}
	if test.BobAddr != nil {
		addr := *test.BobAddr
		testCopy.BobAddr = &addr
	}
	if test.CharlieAddr != nil {
		addr := *test.CharlieAddr
		testCopy.CharlieAddr = &addr
	}
	if test.ExternalAddr != nil {
		addr := *test.ExternalAddr
		testCopy.ExternalAddr = &addr
	}

	return &testCopy
}

// withTest validates a nonce, looks up the test under the mutex, and calls fn
// with the found test. Returns an error if the nonce is zero or not found.
func (ptm *PeerTestManager) withTest(nonce uint32, fn func(*PeerTest)) error {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "withTest", "nonce": nonce}).Debug("Looking up peer test")
	if nonce == 0 {
		return oops.
			Code("INVALID_NONCE").
			In("peertest_manager").
			Errorf("nonce cannot be zero")
	}

	ptm.mutex.Lock()
	defer ptm.mutex.Unlock()

	test, exists := ptm.tests[nonce]
	if !exists {
		return oops.
			Code("TEST_NOT_FOUND").
			In("peertest_manager").
			With("nonce", nonce).
			Errorf("peer test not found")
	}

	fn(test)
	return nil
}

// UpdateState updates the state of a peer test.
//
// Parameters:
//   - nonce: Test nonce
//   - state: New state
//
// Returns error if test not found.
func (ptm *PeerTestManager) UpdateState(nonce uint32, state PeerTestState) error {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "UpdateState", "nonce": nonce, "state": state}).Debug("Updating peer test state")
	return ptm.withTest(nonce, func(test *PeerTest) {
		test.State = state
	})
}

// CompleteTest marks a test as complete and stores the result.
//
// Parameters:
//   - nonce: Test nonce
//   - result: Test result to store
//
// Returns error if test not found.
func (ptm *PeerTestManager) CompleteTest(nonce uint32, result *TestResult) error {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "CompleteTest", "nonce": nonce}).Debug("Completing peer test")
	if nonce == 0 {
		return oops.
			Code("INVALID_NONCE").
			In("peertest_manager").
			Errorf("nonce cannot be zero")
	}

	if result == nil {
		return oops.
			Code("INVALID_RESULT").
			In("peertest_manager").
			Errorf("result cannot be nil")
	}

	ptm.mutex.Lock()
	defer ptm.mutex.Unlock()

	test, exists := ptm.tests[nonce]
	if !exists {
		return oops.
			Code("TEST_NOT_FOUND").
			In("peertest_manager").
			With("nonce", nonce).
			Errorf("peer test not found")
	}

	// Update test state
	test.State = TestComplete
	test.NATType = result.NATType
	test.Reachable = result.Reachable
	test.ExternalAddr = result.ExternalAddr

	// Store result by address (if available)
	if test.AliceAddr != nil {
		ptm.results[test.AliceAddr.String()] = result
	}

	return nil
}

// FailTest marks a test as failed.
//
// Parameters:
//   - nonce: Test nonce
//   - reason: Error explaining failure
//
// Returns error if test not found.
func (ptm *PeerTestManager) FailTest(nonce uint32, reason error) error {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "FailTest", "nonce": nonce, "reason": reason}).Debug("Failing peer test")
	return ptm.withTest(nonce, func(test *PeerTest) {
		test.State = TestFailed
	})
}

// GetResult retrieves cached test result for an address.
//
// Parameters:
//   - addr: Remote address
//
// Returns result copy, or nil if not found.
func (ptm *PeerTestManager) GetResult(addr *net.UDPAddr) *TestResult {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "GetResult", "addr": addr}).Debug("Retrieving cached test result")
	if addr == nil {
		return nil
	}

	ptm.mutex.RLock()
	defer ptm.mutex.RUnlock()

	result, exists := ptm.results[addr.String()]
	if !exists {
		return nil
	}

	// Return defensive copy
	resultCopy := *result
	if result.ExternalAddr != nil {
		addrCopy := *result.ExternalAddr
		resultCopy.ExternalAddr = &addrCopy
	}

	return &resultCopy
}

// RemoveTest removes a test from tracking.
//
// Parameters:
//   - nonce: Test nonce
func (ptm *PeerTestManager) RemoveTest(nonce uint32) {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "RemoveTest", "nonce": nonce}).Debug("Removing peer test")
	if nonce == 0 {
		return
	}

	ptm.mutex.Lock()
	defer ptm.mutex.Unlock()

	delete(ptm.tests, nonce)
}

// CleanupExpired removes tests that have exceeded their timeout.
func (ptm *PeerTestManager) CleanupExpired() {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "CleanupExpired"}).Debug("Removing expired peer tests")
	now := time.Now()

	ptm.mutex.Lock()
	defer ptm.mutex.Unlock()

	// Clean expired tests
	for nonce, test := range ptm.tests {
		// Check if test has timed out (60 seconds per I2P spec)
		if now.Sub(test.StartTime) > 60*time.Second {
			// Also remove the corresponding result entry keyed by AliceAddr.
			if test.AliceAddr != nil {
				delete(ptm.results, test.AliceAddr.String())
			}
			delete(ptm.tests, nonce)
		}
	}

	// Clean orphaned results older than 5 minutes.
	// This handles cases where results exist without corresponding tests:
	// 1. CompleteTest() followed by RemoveTest()
	// 2. Tests that timeout before AliceAddr is set
	for addr, result := range ptm.results {
		if now.Sub(result.TestTime) > 5*time.Minute {
			// Verify no corresponding test exists
			hasTest := false
			for _, test := range ptm.tests {
				if test.AliceAddr != nil && test.AliceAddr.String() == addr {
					hasTest = true
					break
				}
			}
			if !hasTest {
				delete(ptm.results, addr)
			}
		}
	}
}

// GetStats returns statistics about active tests.
func (ptm *PeerTestManager) GetStats() map[string]int {
	ptm.mutex.RLock()
	defer ptm.mutex.RUnlock()

	stats := make(map[string]int)
	stats["total_tests"] = len(ptm.tests)
	stats["cached_results"] = len(ptm.results)

	// Count by state
	for _, test := range ptm.tests {
		switch test.State {
		case TestRequested:
			stats["requested"]++
		case TestRelayed:
			stats["relayed"]++
		case TestProbed:
			stats["probed"]++
		case TestComplete:
			stats["complete"]++
		case TestFailed:
			stats["failed"]++
		}
	}

	// Count by role
	for _, test := range ptm.tests {
		switch test.Role {
		case RoleInitiator:
			stats["role_initiator"]++
		case RoleRelay:
			stats["role_relay"]++
		case RoleResponder:
			stats["role_responder"]++
		}
	}

	return stats
}

// CreateRelayTest creates a relay test when Bob receives request from Alice.
//
// Bob acts as relay between Alice (initiator) and Charlie (responder).
//
// Parameters:
//   - nonce: Test nonce from Alice
//   - aliceAddr: Alice's address
//   - charlieAddr: Charlie's address
//
// Returns nonce on success, error otherwise.
func (ptm *PeerTestManager) CreateRelayTest(nonce uint32, aliceAddr, charlieAddr *net.UDPAddr) (uint32, error) {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "CreateRelayTest", "nonce": nonce}).Debug("Creating relay test as Bob")
	if nonce == 0 {
		return 0, oops.
			Code("INVALID_NONCE").
			In("peertest_manager").
			Errorf("nonce cannot be zero")
	}
	if aliceAddr == nil {
		return 0, oops.
			Code("INVALID_ADDRESS").
			In("peertest_manager").
			Errorf("alice address cannot be nil")
	}
	if !IsValidSourcePort(aliceAddr) {
		return 0, oops.
			Code("INVALID_PORT").
			In("peertest_manager").
			With("port", aliceAddr.Port).
			Errorf("alice address has invalid source port %d", aliceAddr.Port)
	}
	if charlieAddr == nil {
		return 0, oops.
			Code("INVALID_ADDRESS").
			In("peertest_manager").
			Errorf("charlie address cannot be nil")
	}
	if !IsValidSourcePort(charlieAddr) {
		return 0, oops.
			Code("INVALID_PORT").
			In("peertest_manager").
			With("port", charlieAddr.Port).
			Errorf("charlie address has invalid source port %d", charlieAddr.Port)
	}

	ptm.mutex.Lock()
	defer ptm.mutex.Unlock()

	// Create relay test
	test := &PeerTest{
		Nonce:       nonce,
		Role:        RoleRelay,
		State:       TestRelayed,
		AliceAddr:   aliceAddr,
		CharlieAddr: charlieAddr,
		StartTime:   time.Now(),
		Timeouts:    make([]time.Time, 7),
	}

	ptm.tests[nonce] = test

	return nonce, nil
}

// CreateResponderTest creates a responder test when Charlie receives relay from Bob.
//
// Charlie acts as responder to probe Alice.
//
// Parameters:
//   - nonce: Test nonce
//   - aliceAddr: Alice's address
//   - bobAddr: Bob's address
//
// Returns error on failure.
func (ptm *PeerTestManager) CreateResponderTest(nonce uint32, aliceAddr, bobAddr *net.UDPAddr) error {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "CreateResponderTest", "nonce": nonce}).Debug("Creating responder test as Charlie")
	if nonce == 0 {
		return oops.
			Code("INVALID_NONCE").
			In("peertest_manager").
			Errorf("nonce cannot be zero")
	}
	if aliceAddr == nil {
		return oops.
			Code("INVALID_ADDRESS").
			In("peertest_manager").
			Errorf("alice address cannot be nil")
	}
	if !IsValidSourcePort(aliceAddr) {
		return oops.
			Code("INVALID_PORT").
			In("peertest_manager").
			With("port", aliceAddr.Port).
			Errorf("alice address has invalid source port %d", aliceAddr.Port)
	}
	if bobAddr == nil {
		return oops.
			Code("INVALID_ADDRESS").
			In("peertest_manager").
			Errorf("bob address cannot be nil")
	}
	if !IsValidSourcePort(bobAddr) {
		return oops.
			Code("INVALID_PORT").
			In("peertest_manager").
			With("port", bobAddr.Port).
			Errorf("bob address has invalid source port %d", bobAddr.Port)
	}

	ptm.mutex.Lock()
	defer ptm.mutex.Unlock()

	// Create responder test
	test := &PeerTest{
		Nonce:     nonce,
		Role:      RoleResponder,
		State:     TestProbed,
		AliceAddr: aliceAddr,
		BobAddr:   bobAddr,
		StartTime: time.Now(),
		Timeouts:  make([]time.Time, 7),
	}

	ptm.tests[nonce] = test

	return nil
}

// SetAliceAddr sets Alice's address in an existing test.
//
// Used when Alice's external address is determined during the test.
//
// Parameters:
//   - nonce: Test nonce
//   - addr: Alice's address
//
// Returns error if test not found.
func (ptm *PeerTestManager) SetAliceAddr(nonce uint32, addr *net.UDPAddr) error {
	if addr == nil {
		return oops.
			Code("INVALID_ADDRESS").
			In("peertest_manager").
			Errorf("address cannot be nil")
	}
	if !IsValidSourcePort(addr) {
		return oops.
			Code("INVALID_PORT").
			In("peertest_manager").
			With("port", addr.Port).
			Errorf("alice address has invalid source port %d", addr.Port)
	}
	return ptm.withTest(nonce, func(test *PeerTest) {
		test.AliceAddr = addr
	})
}

// DetermineNATType analyzes test results to determine NAT type.
//
// Logic per I2P specification:
// - Both probes succeed + consistent port/IP = No NAT or Full Cone
// - Direct fails + relayed succeeds = Symmetric or Port-Restricted
// - Port inconsistent = Symmetric NAT
// - IP inconsistent = Multiple NATs or proxy
//
// Parameters:
//   - result: Test result with probe outcomes
//
// Returns determined NAT type.
// BUG-L02 fix: Refactored to reduce cyclomatic complexity by extracting NAT determination logic.
func (ptm *PeerTestManager) DetermineNATType(result *TestResult) NATType {
	if result == nil {
		return NATUnknown
	}

	// Both probes succeeded
	if result.DirectProbeSuccess && result.RelayedProbeSuccess {
		return ptm.determineNATFromBothProbes(result)
	}

	// Only relayed probe succeeded
	if !result.DirectProbeSuccess && result.RelayedProbeSuccess {
		return ptm.determineNATFromRelayedOnly(result)
	}

	// Neither probe succeeded
	if !result.DirectProbeSuccess && !result.RelayedProbeSuccess {
		return NATUnknown
	}

	// BUG-011 fix: Direct succeeded but relay failed
	// This may indicate an introducer/relay problem rather than NAT characteristics.
	// Return NATUnknown to trigger re-probing rather than assuming NATCone.
	if result.DirectProbeSuccess && !result.RelayedProbeSuccess {
		return NATUnknown
	}

	return NATUnknown
}

// determineNATFromBothProbes determines NAT type when both direct and relayed probes succeeded.
// This helper reduces cyclomatic complexity in DetermineNATType.
func (ptm *PeerTestManager) determineNATFromBothProbes(result *TestResult) NATType {
	if result.PortConsistent && result.IPConsistent {
		// Check whether the observed external address matches a local interface.
		// If it does, the peer has a public IP with no NAT; otherwise full cone NAT.
		if result.ExternalAddr != nil && isLocalAddress(result.ExternalAddr.IP) {
			return NATNone
		}
		return NATCone
	}
	if !result.PortConsistent {
		// Port changes = symmetric or port-restricted
		return NATPortRestricted
	}
	if !result.IPConsistent {
		// IP changes = multiple NATs or proxies
		return NATRestricted
	}
	return NATUnknown
}

// determineNATFromRelayedOnly determines NAT type when only relayed probe succeeded.
// This helper reduces cyclomatic complexity in DetermineNATType.
func (ptm *PeerTestManager) determineNATFromRelayedOnly(result *TestResult) NATType {
	if result.PortConsistent {
		// Port stays same but direct fails = restricted cone
		return NATRestricted
	}
	// Port changes = symmetric NAT
	return NATSymmetric
}

// GetListener returns the listener reference (for testing).
func (ptm *PeerTestManager) GetListener() ListenerRef {
	return ptm.listener
}

// GetTestsMap returns the raw tests map under lock (for testing).
func (ptm *PeerTestManager) GetTestsMap() map[uint32]*PeerTest {
	ptm.mutex.RLock()
	defer ptm.mutex.RUnlock()
	result := make(map[uint32]*PeerTest, len(ptm.tests))
	for k, v := range ptm.tests {
		result[k] = v
	}
	return result
}

// GetResultsMap returns the raw results map under lock (for testing).
func (ptm *PeerTestManager) GetResultsMap() map[string]*TestResult {
	ptm.mutex.RLock()
	defer ptm.mutex.RUnlock()
	result := make(map[string]*TestResult, len(ptm.results))
	for k, v := range ptm.results {
		result[k] = v
	}
	return result
}

// SetTestAliceAddr sets AliceAddr on the test with the given nonce (for testing).
func (ptm *PeerTestManager) SetTestAliceAddr(nonce uint32, addr *net.UDPAddr) {
	ptm.mutex.Lock()
	defer ptm.mutex.Unlock()
	if test, exists := ptm.tests[nonce]; exists {
		test.AliceAddr = addr
	}
}

// SetRawResult stores a result directly in the results map (for testing).
func (ptm *PeerTestManager) SetRawResult(key string, result *TestResult) {
	ptm.mutex.Lock()
	defer ptm.mutex.Unlock()
	ptm.results[key] = result
}

// SetTestStartTime sets StartTime on the test with the given nonce (for testing).
func (ptm *PeerTestManager) SetTestStartTime(nonce uint32, t time.Time) {
	ptm.mutex.Lock()
	defer ptm.mutex.Unlock()
	if test, exists := ptm.tests[nonce]; exists {
		test.StartTime = t
	}
}

// NewPeerTestManagerWithFields creates a PeerTestManager with pre-populated fields (for testing).
func NewPeerTestManagerWithFields(listener ListenerRef, tests map[uint32]*PeerTest, results map[string]*TestResult) *PeerTestManager {
	ptm := &PeerTestManager{
		listener: listener,
		tests:    tests,
		results:  results,
		stopCh:   make(chan struct{}),
	}
	return ptm
}
