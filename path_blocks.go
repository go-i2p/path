package ssu2path

import (
	"crypto/rand"
	"encoding/binary"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

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
	// Fill remaining bytes with random padding; failure is non-fatal.
	// On Linux/macOS, rand.Read never fails (reads from getrandom(2) or /dev/urandom);
	// on other systems, zero padding is still a valid MTU probe payload,
	// so the error is intentionally ignored. (L-8 fix: explicit comment added.)
	if probeSize > 8 {
		// L-03 fix: log CSPRNG failures instead of silently ignoring them.
		// Zero padding is still a valid MTU probe payload, so this is non-fatal.
		if _, err := rand.Read(data[8:]); err != nil {
			log.WithFields(logger.Fields{
				"pkg":  "ssu2",
				"func": "EncodePathChallengeWithPadding",
			}).Warn("CSPRNG failed for probe padding; using zero padding")
		}
	}
	return NewSSU2Block(BlockTypePathChallenge, data)
}
