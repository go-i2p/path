package ssu2path

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEncodeDecodeRelayRequest_IPv4 tests round-trip encoding/decoding for RelayRequest with IPv4.
func TestEncodeDecodeRelayRequest_IPv4(t *testing.T) {
	// Create test signature
	sig := make([]byte, 64)
	_, err := rand.Read(sig)
	require.NoError(t, err)

	req := &RelayRequestBlock{
		Flag:      0,
		Nonce:     0x12345678,
		RelayTag:  0xABCDEF01,
		Timestamp: 1234567890,
		Version:   2,
		AlicePort: 8887,
		AliceIP:   net.ParseIP("203.0.113.45"),
		Signature: sig,
	}

	// Encode
	block, err := EncodeRelayRequest(req)
	require.NoError(t, err)
	require.NotNil(t, block)
	assert.Equal(t, BlockTypeRelayRequest, block.Type)

	// Decode
	decoded, err := DecodeRelayRequest(block)
	require.NoError(t, err)
	require.NotNil(t, decoded)

	// Verify all fields match
	assert.Equal(t, req.Flag, decoded.Flag)
	assert.Equal(t, req.Nonce, decoded.Nonce)
	assert.Equal(t, req.RelayTag, decoded.RelayTag)
	assert.Equal(t, req.Timestamp, decoded.Timestamp)
	assert.Equal(t, req.Version, decoded.Version)
	assert.Equal(t, req.AlicePort, decoded.AlicePort)
	assert.True(t, req.AliceIP.Equal(decoded.AliceIP))
	assert.Equal(t, req.Signature, decoded.Signature)
}

// TestEncodeDecodeRelayRequest_IPv6 tests round-trip encoding/decoding for RelayRequest with IPv6.
func TestEncodeDecodeRelayRequest_IPv6(t *testing.T) {
	sig := make([]byte, 64)
	_, err := rand.Read(sig)
	require.NoError(t, err)

	req := &RelayRequestBlock{
		Flag:      0,
		Nonce:     0x98765432,
		RelayTag:  0x11223344,
		Timestamp: 1234567890,
		Version:   2,
		AlicePort: 9999,
		AliceIP:   net.ParseIP("2001:db8::1"),
		Signature: sig,
	}

	// Encode
	block, err := EncodeRelayRequest(req)
	require.NoError(t, err)
	require.NotNil(t, block)

	// Decode
	decoded, err := DecodeRelayRequest(block)
	require.NoError(t, err)
	require.NotNil(t, decoded)

	// Verify
	assert.Equal(t, req.Nonce, decoded.Nonce)
	assert.Equal(t, req.RelayTag, decoded.RelayTag)
	assert.True(t, req.AliceIP.Equal(decoded.AliceIP))
}

// TestEncodeRelayRequest_NilAliceIP tests BUG-005 fix: nil AliceIP returns error.
func TestEncodeRelayRequest_NilAliceIP(t *testing.T) {
	req := &RelayRequestBlock{
		Flag:      0,
		Nonce:     0x12345678,
		RelayTag:  0xABCDEF01,
		Timestamp: 1234567890,
		Version:   2,
		AlicePort: 8887,
		AliceIP:   nil, // nil IP should error
		Signature: make([]byte, 64),
	}

	block, err := EncodeRelayRequest(req)
	assert.Error(t, err)
	assert.Nil(t, block)
	assert.Contains(t, err.Error(), "AliceIP cannot be nil")
}

// TestEncodeRelayRequest_NilBlock tests nil input validation.
func TestEncodeRelayRequest_NilBlock(t *testing.T) {
	block, err := EncodeRelayRequest(nil)
	assert.Error(t, err)
	assert.Nil(t, block)
}

// TestDecodeRelayRequest_InvalidAddressSize tests decoder rejection of invalid address sizes.
func TestDecodeRelayRequest_InvalidAddressSize(t *testing.T) {
	// Create data with invalid address size (asz=5, not 6 or 18)
	data := make([]byte, 20)
	data[14] = 5 // asz = 5 (invalid)
	block := NewSSU2Block(BlockTypeRelayRequest, data)

	decoded, err := DecodeRelayRequest(block)
	assert.Error(t, err)
	assert.Nil(t, decoded)
	assert.Contains(t, err.Error(), "too short")
}

// TestEncodeDecodeRelayResponse_BobRejection tests Bob rejection (code 1-63, minimal format).
func TestEncodeDecodeRelayResponse_BobRejection(t *testing.T) {
	resp := &RelayResponseBlock{
		Flag:  0,
		Code:  42, // Bob rejection
		Nonce: 0x12345678,
	}

	// Encode
	block, err := EncodeRelayResponse(resp)
	require.NoError(t, err)
	require.NotNil(t, block)
	assert.Equal(t, BlockTypeRelayResponse, block.Type)
	assert.Equal(t, 6, len(block.Data)) // flag(1) + code(1) + nonce(4)

	// Decode
	decoded, err := DecodeRelayResponse(block)
	require.NoError(t, err)
	require.NotNil(t, decoded)

	assert.Equal(t, resp.Flag, decoded.Flag)
	assert.Equal(t, resp.Code, decoded.Code)
	assert.Equal(t, resp.Nonce, decoded.Nonce)
}

// TestEncodeDecodeRelayResponse_AcceptedIPv4 tests accepted response with Charlie's address.
func TestEncodeDecodeRelayResponse_AcceptedIPv4(t *testing.T) {
	sig := make([]byte, 64)
	_, err := rand.Read(sig)
	require.NoError(t, err)

	token := make([]byte, 8)
	_, err = rand.Read(token)
	require.NoError(t, err)

	resp := &RelayResponseBlock{
		Flag:        0,
		Code:        0, // Accepted
		Nonce:       0x12345678,
		Timestamp:   1234567890,
		Version:     2,
		CharliePort: 7777,
		CharlieIP:   net.ParseIP("198.51.100.23"),
		Signature:   sig,
		Token:       token,
	}

	// Encode
	block, err := EncodeRelayResponse(resp)
	require.NoError(t, err)
	require.NotNil(t, block)

	// Decode
	decoded, err := DecodeRelayResponse(block)
	require.NoError(t, err)
	require.NotNil(t, decoded)

	assert.Equal(t, resp.Code, decoded.Code)
	assert.Equal(t, resp.Nonce, decoded.Nonce)
	assert.Equal(t, resp.Timestamp, decoded.Timestamp)
	assert.Equal(t, resp.Version, decoded.Version)
	assert.Equal(t, resp.CharliePort, decoded.CharliePort)
	assert.True(t, resp.CharlieIP.Equal(decoded.CharlieIP))
	assert.Equal(t, resp.Signature, decoded.Signature)
	assert.Equal(t, resp.Token, decoded.Token)
}

// TestEncodeDecodeRelayResponse_CharlieRejection tests Charlie rejection (code >= 64).
func TestEncodeDecodeRelayResponse_CharlieRejection(t *testing.T) {
	sig := make([]byte, 64)
	_, err := rand.Read(sig)
	require.NoError(t, err)

	resp := &RelayResponseBlock{
		Flag:        0,
		Code:        64, // Charlie rejection
		Nonce:       0x87654321,
		Timestamp:   1234567890,
		Version:     2,
		CharliePort: 6666,
		CharlieIP:   net.ParseIP("2001:db8::42"),
		Signature:   sig,
	}

	// Encode
	block, err := EncodeRelayResponse(resp)
	require.NoError(t, err)
	require.NotNil(t, block)

	// Decode
	decoded, err := DecodeRelayResponse(block)
	require.NoError(t, err)
	require.NotNil(t, decoded)

	assert.Equal(t, resp.Code, decoded.Code)
	assert.Equal(t, resp.Nonce, decoded.Nonce)
	assert.True(t, resp.CharlieIP.Equal(decoded.CharlieIP))
	assert.Equal(t, resp.Signature, decoded.Signature)
	// No token for Charlie rejection
	assert.Nil(t, decoded.Token)
}

// TestEncodeDecodeRelayIntro_IPv4 tests RelayIntro encoding/decoding.
func TestEncodeDecodeRelayIntro_IPv4(t *testing.T) {
	sig := make([]byte, 64)
	_, err := rand.Read(sig)
	require.NoError(t, err)

	hash := make([]byte, 32)
	_, err = rand.Read(hash)
	require.NoError(t, err)

	intro := &RelayIntroBlock{
		Flag:            0,
		AliceRouterHash: hash,
		Nonce:           0xAABBCCDD,
		AliceRelayTag:   0x11223344,
		Timestamp:       1234567890,
		Version:         2,
		AlicePort:       8888,
		AliceIP:         net.ParseIP("192.0.2.100"),
		Signature:       sig,
	}

	// Encode
	block, err := EncodeRelayIntro(intro)
	require.NoError(t, err)
	require.NotNil(t, block)
	assert.Equal(t, BlockTypeRelayIntro, block.Type)

	// Decode
	decoded, err := DecodeRelayIntro(block)
	require.NoError(t, err)
	require.NotNil(t, decoded)

	assert.Equal(t, intro.Flag, decoded.Flag)
	assert.Equal(t, intro.AliceRouterHash, decoded.AliceRouterHash)
	assert.Equal(t, intro.Nonce, decoded.Nonce)
	assert.Equal(t, intro.AliceRelayTag, decoded.AliceRelayTag)
	assert.Equal(t, intro.Timestamp, decoded.Timestamp)
	assert.Equal(t, intro.Version, decoded.Version)
	assert.Equal(t, intro.AlicePort, decoded.AlicePort)
	assert.True(t, intro.AliceIP.Equal(decoded.AliceIP))
	assert.Equal(t, intro.Signature, decoded.Signature)
}

// TestEncodeRelayIntro_NilAliceIP tests BUG-005 fix for RelayIntro.
func TestEncodeRelayIntro_NilAliceIP(t *testing.T) {
	intro := &RelayIntroBlock{
		Flag:            0,
		AliceRouterHash: make([]byte, 32),
		Nonce:           0xAABBCCDD,
		AliceRelayTag:   0x11223344,
		Timestamp:       1234567890,
		Version:         2,
		AlicePort:       8888,
		AliceIP:         nil, // Should error
		Signature:       make([]byte, 64),
	}

	block, err := EncodeRelayIntro(intro)
	assert.Error(t, err)
	assert.Nil(t, block)
	assert.Contains(t, err.Error(), "AliceIP cannot be nil")
}

// TestEncodeRelayIntro_InvalidHashLength tests router hash validation.
func TestEncodeRelayIntro_InvalidHashLength(t *testing.T) {
	intro := &RelayIntroBlock{
		Flag:            0,
		AliceRouterHash: make([]byte, 16), // Wrong size
		Nonce:           0xAABBCCDD,
		AliceRelayTag:   0x11223344,
		Timestamp:       1234567890,
		Version:         2,
		AlicePort:       8888,
		AliceIP:         net.ParseIP("192.0.2.100"),
		Signature:       make([]byte, 64),
	}

	block, err := EncodeRelayIntro(intro)
	assert.Error(t, err)
	assert.Nil(t, block)
	assert.Contains(t, err.Error(), "must be 32 bytes")
}

// TestEncodeDecodeRelayTagRequest tests empty relay tag request.
func TestEncodeDecodeRelayTagRequest(t *testing.T) {
	req := &RelayTagRequestBlock{}

	// Encode
	block, err := EncodeRelayTagRequest(req)
	require.NoError(t, err)
	require.NotNil(t, block)
	assert.Equal(t, BlockTypeRelayTagRequest, block.Type)
	assert.Equal(t, 0, len(block.Data)) // Empty per spec

	// Decode
	decoded, err := DecodeRelayTagRequest(block)
	require.NoError(t, err)
	require.NotNil(t, decoded)
}

// TestEncodeDecodeRelayTag tests relay tag assignment.
func TestEncodeDecodeRelayTag(t *testing.T) {
	tag := &RelayTagBlock{
		RelayTag: 0xDEADBEEF,
	}

	// Encode
	block, err := EncodeRelayTag(tag)
	require.NoError(t, err)
	require.NotNil(t, block)
	assert.Equal(t, BlockTypeRelayTag, block.Type)
	assert.Equal(t, 4, len(block.Data))

	// Decode
	decoded, err := DecodeRelayTag(block)
	require.NoError(t, err)
	require.NotNil(t, decoded)
	assert.Equal(t, tag.RelayTag, decoded.RelayTag)
}

// TestEncodeRelayTag_ZeroTag tests that zero relay tag is currently accepted.
// Note: Per SSU2 spec, relay tags should be nonzero, but this is not currently enforced.
func TestEncodeRelayTag_ZeroTag(t *testing.T) {
	tag := &RelayTagBlock{
		RelayTag: 0,
	}

	// Currently accepts zero tag (spec says nonzero, but not enforced)
	block, err := EncodeRelayTag(tag)
	assert.NoError(t, err)
	assert.NotNil(t, block)
}

// TestDecodeRelayTag_InvalidSize tests decoder validation of tag size.
func TestDecodeRelayTag_InvalidSize(t *testing.T) {
	// Wrong size data
	data := make([]byte, 3)
	block := NewSSU2Block(BlockTypeRelayTag, data)

	decoded, err := DecodeRelayTag(block)
	assert.Error(t, err)
	assert.Nil(t, decoded)
	assert.Contains(t, err.Error(), "too short")
}

// TestRelayBlocks_Ed25519Signature_Integration tests relay blocks with real Ed25519 signatures.
func TestRelayBlocks_Ed25519Signature_Integration(t *testing.T) {
	// Generate Ed25519 key pair
	pubKey, privKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	// Create relay request
	req := &RelayRequestBlock{
		Flag:      0,
		Nonce:     0x12345678,
		RelayTag:  0xABCDEF01,
		Timestamp: 1234567890,
		Version:   2,
		AlicePort: 8887,
		AliceIP:   net.ParseIP("203.0.113.45"),
	}

	// Sign it (simplified - in real use, would sign structured data)
	message := []byte("test message")
	req.Signature = ed25519.Sign(privKey, message)

	// Encode and decode
	block, err := EncodeRelayRequest(req)
	require.NoError(t, err)

	decoded, err := DecodeRelayRequest(block)
	require.NoError(t, err)

	// Verify signature survived round-trip
	assert.True(t, ed25519.Verify(pubKey, message, decoded.Signature))
}
