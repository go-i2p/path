package ssu2path

import (
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/go-i2p/crypto/ed25519"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// PATH-001: close-of-closed-channel panic in HandlePathChallenge
// ---------------------------------------------------------------------------

// TestPathValidator_DuplicateChallengeAfterDoneClosedNoPanic reproduces PATH-001.
// A challenge whose done channel is already closed but which is still present in
// the map (the validated-but-not-yet-deleted window) must not panic when a
// duplicate Path Challenge overwrites it. The pre-fix code closed old.done
// unconditionally; the idempotent closeDone helper makes the second close a no-op.
func TestPathValidator_DuplicateChallengeAfterDoneClosedNoPanic(t *testing.T) {
	conn := &mockPathValidationConn{remoteAddr: &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1}}
	pv := NewPathValidator(conn)
	defer pv.Stop()

	challengeData := []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04}
	key := string(challengeData)

	// Seed the map with a challenge whose done is already closed, simulating the
	// window where HandlePathResponse closed done (ChallengeValidated) but
	// ValidatePath has not yet deleted the entry.
	pv.mutex.Lock()
	seed := &PathChallenge{
		ChallengeData: challengeData,
		NewAddr:       &net.UDPAddr{IP: net.ParseIP("10.0.0.2"), Port: 2},
		Timestamp:     time.Now(),
		State:         ChallengeValidated,
		done:          make(chan struct{}),
	}
	close(seed.done)
	seed.doneClosed = true
	pv.challenges[key] = seed
	pv.mutex.Unlock()

	block := EncodePathChallenge(challengeData)
	require.NotNil(t, block)

	// The duplicate challenge must overwrite without panicking.
	assert.NotPanics(t, func() {
		err := pv.HandlePathChallenge(block, &net.UDPAddr{IP: net.ParseIP("10.0.0.3"), Port: 3})
		require.NoError(t, err)
	})

	// The entry must now be the freshly-recorded ChallengeReceived challenge.
	pv.mutex.RLock()
	cur, ok := pv.challenges[key]
	pv.mutex.RUnlock()
	require.True(t, ok)
	assert.Equal(t, ChallengeReceived, cur.State)
}

// TestPathValidator_CloseDoneIsIdempotent directly exercises the helper.
func TestPathValidator_CloseDoneIsIdempotent(t *testing.T) {
	ch := &PathChallenge{done: make(chan struct{})}
	assert.NotPanics(t, func() {
		ch.closeDone()
		ch.closeDone()
		ch.closeDone()
	})
	// Channel is closed exactly once (a second close would have panicked).
	select {
	case <-ch.done:
	default:
		t.Fatal("done channel should be closed")
	}
	assert.True(t, ch.doneClosed)
}

// ---------------------------------------------------------------------------
// PATH-002: resolver + verify run outside hpc.mutex
// ---------------------------------------------------------------------------

// TestHolePunchCoordinator_ReentrantResolverNoDeadlock reproduces PATH-002. A
// caller-supplied resolver that re-enters the coordinator (GetAttempt) must not
// deadlock, because the resolver now runs without hpc.mutex held.
func TestHolePunchCoordinator_ReentrantResolverNoDeadlock(t *testing.T) {
	manager := NewRelayManager(nil)

	var hpcRef *HolePunchCoordinator
	resolver := func(info HolePunchVerifyInfo) (HolePunchVerifyContext, ed25519.Ed25519PublicKey, bool) {
		// Re-enter the coordinator from inside the resolver. Pre-fix this
		// deadlocked forever because hpc.mutex was held during verification.
		_ = hpcRef.GetAttempt(info.SessionID)
		return HolePunchVerifyContext{BobHash: testBobHash, CharlieHash: testCharlieHash}, testAlicePub, true
	}

	hpc, err := NewHolePunchCoordinator(manager, resolver)
	require.NoError(t, err)
	defer hpc.Stop()
	hpcRef = hpc

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 8887}
	introducerAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.2"), Port: 8888}
	sessionID, err := hpc.InitiateHolePunch(remoteAddr, introducerAddr, 0xABCD1234)
	require.NoError(t, err)

	nonce := uint32(0x11223344)
	timestamp := uint32(time.Now().Unix())
	charlieIP := net.ParseIP("203.0.113.4")
	charliePort := uint16(9999)
	sig, err := SignRelayResponse(testAlicePriv, testBobHash, nonce, timestamp, 2, charliePort, charlieIP)
	require.NoError(t, err)
	block := &RelayResponseBlock{
		Nonce: nonce, Timestamp: timestamp, Version: 2,
		CharliePort: charliePort, CharlieIP: charlieIP, Signature: sig,
	}
	fromAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.3"), Port: 8889}

	done := make(chan error, 1)
	go func() { done <- hpc.HandleHolePunch(sessionID, fromAddr, block) }()

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("HandleHolePunch deadlocked: reentrant resolver blocked on hpc.mutex")
	}
}

// ---------------------------------------------------------------------------
// PATH-003: managers deep-copy caller *net.UDPAddr
// ---------------------------------------------------------------------------

func TestRelayManager_AllocateRelayTagCopiesAddr(t *testing.T) {
	rm := NewRelayManager(nil)
	defer rm.Stop()

	addr := &net.UDPAddr{IP: net.ParseIP("203.0.113.50"), Port: 5000}
	tag, err := rm.AllocateRelayTag(addr)
	require.NoError(t, err)

	// Mutate the caller's address after the call.
	addr.Port = 9999
	addr.IP[0] = 10

	got := rm.GetRelayTag(tag)
	require.NotNil(t, got)
	require.NotNil(t, got.ForAddr)
	assert.Equal(t, 5000, got.ForAddr.Port, "stored ForAddr must not track caller mutation")
	assert.True(t, got.ForAddr.IP.Equal(net.ParseIP("203.0.113.50").To4()),
		"stored ForAddr IP must not track caller mutation, got %v", got.ForAddr.IP)
}

func TestRelayManager_AddPendingSessionCopiesAddr(t *testing.T) {
	rm := NewRelayManager(nil)
	defer rm.Stop()

	remote := &net.UDPAddr{IP: net.ParseIP("203.0.113.60"), Port: 6000}
	intro := &net.UDPAddr{IP: net.ParseIP("203.0.113.61"), Port: 6001}
	require.NoError(t, rm.AddPendingSession(0x1234, remote, intro, 0x99))

	remote.Port = 1
	intro.Port = 2

	ps := rm.GetPendingSession(0x1234)
	require.NotNil(t, ps)
	assert.Equal(t, 6000, ps.RemoteAddr.Port)
	assert.Equal(t, 6001, ps.IntroducerAddr.Port)
}

// TestRelayManager_RelayTagAddrRace runs a listener-style loop that reuses one
// *net.UDPAddr (mutating it between reads) concurrently with ValidateRelayTag
// reads. Under -race this fails if the manager stored the pointer by alias.
func TestRelayManager_RelayTagAddrRace(t *testing.T) {
	rm := NewRelayManager(nil)
	defer rm.Stop()

	reused := &net.UDPAddr{IP: net.ParseIP("203.0.113.70"), Port: 7000}
	tag, err := rm.AllocateRelayTag(reused)
	require.NoError(t, err)

	var wg sync.WaitGroup
	stop := make(chan struct{})

	wg.Add(1)
	go func() { // listener reusing the same addr buffer
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				reused.Port = 7000
				reused.IP[0] = 203
			}
		}
	}()

	wg.Add(1)
	go func() { // concurrent reader
		defer wg.Done()
		for i := 0; i < 2000; i++ {
			_ = rm.GetRelayTag(tag)
		}
	}()

	time.Sleep(20 * time.Millisecond)
	close(stop)
	wg.Wait()
}

// ---------------------------------------------------------------------------
// PATH-004: CompleteTest stores a clone of the caller's *TestResult
// ---------------------------------------------------------------------------

func TestPeerTestManager_CompleteTestStoresClone(t *testing.T) {
	ptm := NewPeerTestManager(nil)
	defer ptm.Stop()

	nonce, err := ptm.InitiatePeerTest(&net.UDPAddr{IP: net.ParseIP("203.0.113.80"), Port: 8000})
	require.NoError(t, err)

	alice := &net.UDPAddr{IP: net.ParseIP("203.0.113.81"), Port: 8001}
	require.NoError(t, ptm.SetAliceAddr(nonce, alice))

	ext := &net.UDPAddr{IP: net.ParseIP("203.0.113.82"), Port: 8002}
	result := &TestResult{
		NATType:      NATNone,
		Reachable:    true,
		ExternalAddr: ext,
		ExternalPort: 8002,
	}
	require.NoError(t, ptm.CompleteTest(nonce, result))

	// Mutate the caller's result (and its nested ExternalAddr) after the call.
	result.Reachable = false
	result.ExternalPort = 1
	ext.Port = 2

	got := ptm.GetResult(alice)
	require.NotNil(t, got)
	assert.True(t, got.Reachable, "cached result must not track caller mutation")
	assert.Equal(t, uint16(8002), got.ExternalPort)
	require.NotNil(t, got.ExternalAddr)
	assert.Equal(t, 8002, got.ExternalAddr.Port, "cached ExternalAddr must not track caller mutation")
}

// ---------------------------------------------------------------------------
// PATH-005: RelayResponse code>=64 with no signature (i2pd compact reject)
// ---------------------------------------------------------------------------

func TestRelayResponse_CharlieRejectionSiglessRoundTrip(t *testing.T) {
	// A code-128 "reject, source and reason unspecified" with NO signature, as
	// i2pd emits. Build the wire bytes directly: flag, code, nonce, ts, ver, csz,
	// endpoint (IPv4: port+4B), then nothing.
	ip := net.ParseIP("203.0.113.90").To4()
	require.NotNil(t, ip)
	data := make([]byte, 0, 18)
	data = append(data, 0x00, 128) // flag, code=128
	data = binary.BigEndian.AppendUint32(data, 0x11223344)
	data = binary.BigEndian.AppendUint32(data, uint32(time.Now().Unix()))
	data = append(data, 2, 6) // ver, csz=6 (IPv4)
	data = binary.BigEndian.AppendUint16(data, 9000)
	data = append(data, ip...)

	block := NewSSU2Block(BlockTypeRelayResponse, data)
	decoded, err := DecodeRelayResponse(block)
	require.NoError(t, err, "sig-less code-128 reject must decode (PATH-005)")
	assert.Equal(t, byte(128), decoded.Code)
	assert.Nil(t, decoded.Signature, "sig-less reject must decode with nil signature")
	assert.True(t, decoded.CharlieIP.Equal(ip))

	// Encoder must emit the compact form when Signature is nil, and it must
	// round-trip back through the decoder.
	resp := &RelayResponseBlock{
		Code: 128, Nonce: 0x11223344, Timestamp: uint32(time.Now().Unix()),
		Version: 2, CharliePort: 9000, CharlieIP: ip, Signature: nil,
	}
	enc, err := EncodeRelayResponse(resp)
	require.NoError(t, err)
	dec2, err := DecodeRelayResponse(enc)
	require.NoError(t, err)
	assert.Equal(t, byte(128), dec2.Code)
	assert.Nil(t, dec2.Signature)
}

func TestRelayResponse_CharlieRejectionTruncatedSigRejected(t *testing.T) {
	ip := net.ParseIP("203.0.113.91").To4()
	data := make([]byte, 0, 20)
	data = append(data, 0x00, 64)
	data = binary.BigEndian.AppendUint32(data, 1)
	data = binary.BigEndian.AppendUint32(data, uint32(time.Now().Unix()))
	data = append(data, 2, 6)
	data = binary.BigEndian.AppendUint16(data, 9001)
	data = append(data, ip...)
	data = append(data, make([]byte, 10)...) // partial signature (not 0, not >=64)

	_, err := DecodeRelayResponse(NewSSU2Block(BlockTypeRelayResponse, data))
	require.Error(t, err, "a truncated (partial) signature must still be rejected")
}

// ---------------------------------------------------------------------------
// PATH-006: PeerTest msgs 2/4 router hash is optional
// ---------------------------------------------------------------------------

// buildPeerTestRaw assembles PeerTest wire bytes with an optional 32-byte router
// hash, so the hash-less variant i2pd emits can be exercised.
func buildPeerTestRaw(msg PeerTestMessageCode, code byte, withHash bool, ip net.IP, hash []byte, sig []byte) []byte {
	var data []byte
	data = append(data, byte(msg), code, 0x00) // msg, code, flag
	if withHash {
		data = append(data, hash...)
	}
	data = append(data, 2) // ver=2
	data = binary.BigEndian.AppendUint32(data, 0xAABBCCDD)
	data = binary.BigEndian.AppendUint32(data, uint32(time.Now().Unix()))
	if v4 := ip.To4(); v4 != nil {
		data = append(data, 6)
		data = binary.BigEndian.AppendUint16(data, 7000)
		data = append(data, v4...)
	} else {
		data = append(data, 18)
		data = binary.BigEndian.AppendUint16(data, 7000)
		data = append(data, ip.To16()...)
	}
	data = append(data, sig...)
	return data
}

func TestPeerTest_HashlessVariantDecodes(t *testing.T) {
	ip := net.ParseIP("203.0.113.95")
	sig := make([]byte, 64)

	// Message 2 (Relay) WITHOUT a router hash — the spec-permitted variant.
	hashless := buildPeerTestRaw(PeerTestRelay, 0, false, ip, nil, sig)
	b2, err := DecodePeerTestBlock(NewSSU2Block(BlockTypePeerTest, hashless))
	require.NoError(t, err, "hash-less message 2 must decode (PATH-006)")
	assert.Nil(t, b2.RouterHash)
	assert.Equal(t, uint32(0xAABBCCDD), b2.Nonce)

	// Message 2 WITH a router hash still decodes and populates it.
	hash := make([]byte, 32)
	hash[0] = 0xAA
	withHash := buildPeerTestRaw(PeerTestRelay, 0, true, ip, hash, sig)
	b2h, err := DecodePeerTestBlock(NewSSU2Block(BlockTypePeerTest, withHash))
	require.NoError(t, err)
	require.NotNil(t, b2h.RouterHash)
	assert.Equal(t, byte(0xAA), b2h.RouterHash[0])
}

func TestPeerTest_HashlessMessage4Decodes(t *testing.T) {
	ip := net.ParseIP("203.0.113.96")
	sig := make([]byte, 64)

	// Message 4 (Result) hash-less, accepted (code 0).
	hashless := buildPeerTestRaw(PeerTestResult, 0, false, ip, nil, sig)
	b4, err := DecodePeerTestBlock(NewSSU2Block(BlockTypePeerTest, hashless))
	require.NoError(t, err, "hash-less message 4 must decode (PATH-006)")
	assert.Nil(t, b4.RouterHash)
}

// ---------------------------------------------------------------------------
// PATH-007: replay suppression + single-use relay tag
// ---------------------------------------------------------------------------

func TestHolePunchCoordinator_ReplayRejected(t *testing.T) {
	hpc := createTestHolePunchCoordinator(t)
	defer hpc.Stop()

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 8887}
	introducerAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.2"), Port: 8888}
	sessionID, err := hpc.InitiateHolePunch(remoteAddr, introducerAddr, 0xABCD1234)
	require.NoError(t, err)

	nonce := uint32(0x11223344)
	timestamp := uint32(time.Now().Unix())
	charlieIP := net.ParseIP("203.0.113.4")
	charliePort := uint16(9999)
	sig, err := SignRelayResponse(testAlicePriv, testBobHash, nonce, timestamp, 2, charliePort, charlieIP)
	require.NoError(t, err)
	block := &RelayResponseBlock{
		Nonce: nonce, Timestamp: timestamp, Version: 2,
		CharliePort: charliePort, CharlieIP: charlieIP, Signature: sig,
	}
	fromAddr := &net.UDPAddr{IP: net.ParseIP("203.0.113.3"), Port: 8889}

	// First delivery accepted.
	require.NoError(t, hpc.HandleHolePunch(sessionID, fromAddr, block))
	// Exact replay (same signature) rejected.
	err = hpc.HandleHolePunch(sessionID, fromAddr, block)
	require.Error(t, err, "replay must be rejected (PATH-007)")
	assert.Contains(t, err.Error(), "replay")
}

func TestRelayManager_RelayTagSingleUse(t *testing.T) {
	rm := NewRelayManager(nil)
	defer rm.Stop()

	addr := &net.UDPAddr{IP: net.ParseIP("203.0.113.99"), Port: 9000}
	tag, err := rm.AllocateRelayTag(addr)
	require.NoError(t, err)

	require.True(t, rm.ValidateRelayTag(tag, addr), "first validation must succeed")
	assert.False(t, rm.ValidateRelayTag(tag, addr), "tag must be consumed after first use (PATH-007)")
}

// ---------------------------------------------------------------------------
// PATH-008: bounded remote-triggered state
// ---------------------------------------------------------------------------

func TestRelayManager_RelayTagsCap(t *testing.T) {
	rm := NewRelayManager(nil)
	defer rm.Stop()
	rm.SetRelayTagsMax(2)

	a1 := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1}
	a2 := &net.UDPAddr{IP: net.ParseIP("10.0.0.2"), Port: 2}
	a3 := &net.UDPAddr{IP: net.ParseIP("10.0.0.3"), Port: 3}

	_, err := rm.AllocateRelayTag(a1)
	require.NoError(t, err)
	_, err = rm.AllocateRelayTag(a2)
	require.NoError(t, err)

	_, err = rm.AllocateRelayTag(a3)
	require.Error(t, err, "third allocation must be rejected at the cap (PATH-008)")
	assert.Contains(t, err.Error(), "limit exceeded")
}

func TestPeerTestManager_TestsCap(t *testing.T) {
	ptm := NewPeerTestManager(nil)
	defer ptm.Stop()
	ptm.SetPeerTestsMax(1)

	alice := &net.UDPAddr{IP: net.ParseIP("10.0.1.1"), Port: 1}
	charlie := &net.UDPAddr{IP: net.ParseIP("10.0.1.2"), Port: 2}

	_, err := ptm.CreateRelayTest(0x1111, alice, charlie)
	require.NoError(t, err)

	_, err = ptm.CreateRelayTest(0x2222, alice, charlie)
	require.Error(t, err, "second test must be rejected at the cap (PATH-008)")
	assert.Contains(t, err.Error(), "limit exceeded")
}

func TestPathValidator_ChallengesCap(t *testing.T) {
	conn := &mockPathValidationConn{remoteAddr: &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1}}
	pv := NewPathValidator(conn)
	defer pv.Stop()
	pv.SetPathChallengesMax(1)

	// First local challenge fills the cap.
	_, err := pv.InitiatePathValidation(&net.UDPAddr{IP: net.ParseIP("10.0.0.2"), Port: 2})
	require.NoError(t, err)

	// Second local challenge is rejected at the cap.
	_, err = pv.InitiatePathValidation(&net.UDPAddr{IP: net.ParseIP("10.0.0.3"), Port: 3})
	require.Error(t, err, "second challenge must be rejected at the cap (PATH-008)")
	assert.Contains(t, err.Error(), "limit exceeded")
}

// TestPathValidator_RemoteChallengeCapDropsNewKey verifies the remote (attacker-
// keyed) path drops NEW challenge keys when full but still responds.
func TestPathValidator_RemoteChallengeCapDropsNewKey(t *testing.T) {
	conn := &mockPathValidationConn{remoteAddr: &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1}}
	pv := NewPathValidator(conn)
	defer pv.Stop()
	pv.SetPathChallengesMax(1)

	// Fill the cap with one challenge.
	_, err := pv.InitiatePathValidation(&net.UDPAddr{IP: net.ParseIP("10.0.0.2"), Port: 2})
	require.NoError(t, err)

	// A remote Path Challenge with a NEW key must not grow the map past the cap.
	newKey := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	require.NoError(t, pv.HandlePathChallenge(EncodePathChallenge(newKey), &net.UDPAddr{IP: net.ParseIP("10.0.0.9"), Port: 9}))

	pv.mutex.RLock()
	n := len(pv.challenges)
	pv.mutex.RUnlock()
	assert.LessOrEqual(t, n, 1, "remote challenge must not exceed the cap (PATH-008)")
}

// ---------------------------------------------------------------------------
// PATH-007: replay cache unit behavior
// ---------------------------------------------------------------------------

func TestReplayCache_BasicAndExpiry(t *testing.T) {
	now := time.Now()
	c := newReplayCache(2*time.Minute, 10)
	c.nowFunc = func() time.Time { return now }

	assert.False(t, c.checkAndRecord("a"), "first sighting is not a replay")
	assert.True(t, c.checkAndRecord("a"), "second sighting within window is a replay")
	assert.False(t, c.checkAndRecord("b"), "different key is not a replay")

	// Advance past the TTL: "a" is no longer a replay.
	now = now.Add(3 * time.Minute)
	assert.False(t, c.checkAndRecord("a"), "after TTL expiry it is not a replay")
}

func TestReplayCache_Bounded(t *testing.T) {
	c := newReplayCache(time.Hour, 3)
	for i := 0; i < 100; i++ {
		c.checkAndRecord(string(rune('a' + i)))
	}
	c.mu.Lock()
	size := len(c.seen)
	c.mu.Unlock()
	assert.LessOrEqual(t, size, 3, "cache must stay bounded by max")
}

func TestReplayCache_Disabled(t *testing.T) {
	c := newReplayCache(time.Hour, 0) // disabled
	assert.False(t, c.checkAndRecord("a"))
	assert.False(t, c.checkAndRecord("a"), "disabled cache never reports a replay")

	c.setMax(5) // re-enable
	assert.False(t, c.checkAndRecord("z"))
	assert.True(t, c.checkAndRecord("z"), "re-enabled cache reports replays")
}
