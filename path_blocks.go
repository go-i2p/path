package ssu2path

import (
	"crypto/rand"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// EncodePathChallenge encodes a Path Challenge block (Type 18).
//
// Wire format: [data:arbitrary]
//
// The data is arbitrary and its length is selected by the sender. Per the I2P
// spec, a minimum data size of 8 bytes of random data is recommended but not
// required, and the size should be well under 1280 bytes.
//
// Parameters:
//   - challengeData: arbitrary challenge payload to send
//
// Returns encoded block.
func EncodePathChallenge(challengeData []byte) *SSU2Block {
	return NewSSU2Block(BlockTypePathChallenge, challengeData)
}

// DecodePathChallenge decodes a Path Challenge block.
//
// Parameters:
//   - block: SSU2Block with Type 18
//
// Returns:
//   - []byte: The arbitrary challenge data
//   - error: If decoding fails
func DecodePathChallenge(block *SSU2Block) ([]byte, error) {
	if block == nil {
		return nil, oops.Errorf("block is nil")
	}
	if block.Type != BlockTypePathChallenge {
		return nil, oops.Errorf("invalid block type: expected %d, got %d",
			BlockTypePathChallenge, block.Type)
	}
	return block.Data, nil
}

// EncodePathResponse encodes a Path Response block (Type 19).
//
// Wire format: [data:as received in a Path Challenge]
//
// The data must be identical to what was received in the Path Challenge.
//
// Parameters:
//   - challengeData: the challenge data echoed back from the Path Challenge
//
// Returns encoded block.
func EncodePathResponse(challengeData []byte) *SSU2Block {
	return NewSSU2Block(BlockTypePathResponse, challengeData)
}

// DecodePathResponse decodes a Path Response block.
//
// Parameters:
//   - block: SSU2Block with Type 19
//
// Returns:
//   - []byte: The challenge data (identical to the Path Challenge data)
//   - error: If decoding fails
func DecodePathResponse(block *SSU2Block) ([]byte, error) {
	if block == nil {
		return nil, oops.Errorf("block is nil")
	}
	if block.Type != BlockTypePathResponse {
		return nil, oops.Errorf("invalid block type: expected %d, got %d",
			BlockTypePathResponse, block.Type)
	}
	return block.Data, nil
}

// EncodePathChallengeWithPadding creates a Path Challenge block padded to
// probeSize bytes (total block data length). The challenge data is placed at
// the start; remaining bytes are random padding for MTU probing (G-5).
func EncodePathChallengeWithPadding(challengeData []byte, probeSize int) *SSU2Block {
	if probeSize < len(challengeData) {
		probeSize = len(challengeData)
	}
	data := make([]byte, probeSize)
	copy(data, challengeData)
	// Fill remaining bytes with random padding; failure is non-fatal.
	// On Linux/macOS, rand.Read never fails (reads from getrandom(2) or /dev/urandom);
	// on other systems, zero padding is still a valid MTU probe payload,
	// so the error is intentionally ignored. (L-8 fix: explicit comment added.)
	if probeSize > len(challengeData) {
		// L-03 fix: log CSPRNG failures instead of silently ignoring them.
		// Zero padding is still a valid MTU probe payload, so this is non-fatal.
		if _, err := rand.Read(data[len(challengeData):]); err != nil {
			log.WithFields(logger.Fields{
				"pkg":  "ssu2path",
				"func": "EncodePathChallengeWithPadding",
			}).Warn("CSPRNG failed for probe padding; using zero padding")
		}
	}
	return NewSSU2Block(BlockTypePathChallenge, data)
}
