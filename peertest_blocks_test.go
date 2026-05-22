package path

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPeerTestMessageCode_String tests the String method for message codes.
func TestPeerTestMessageCode_String(t *testing.T) {
	tests := []struct {
		code     PeerTestMessageCode
		expected string
	}{
		{PeerTestRequest, "Request"},
		{PeerTestRelay, "Relay"},
		{PeerTestResponse, "Response"},
		{PeerTestResult, "Result"},
		{PeerTestProbe, "Probe"},
		{PeerTestReply, "Reply"},
		{PeerTestConfirmation, "Confirmation"},
		{PeerTestMessageCode(99), "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.code.String())
		})
	}
}

// helper to build a valid PeerTestBlock for a given message code.
func makePeerTestBlock(msg PeerTestMessageCode) *PeerTestBlock {
	b := &PeerTestBlock{
		MessageCode: msg,
		Code:        0,
		Flag:        0,
		Version:     2,
		Nonce:       0x12345678,
		Timestamp:   1700000000,
		AlicePort:   9000,
		AliceIP:     net.IPv4(192, 168, 1, 1).To4(),
		Signature:   make([]byte, 64),
	}
	if b.hasRouterHash() {
		h := generateRandomHash()
		b.RouterHash = &h
	}
	return b
}

// TestEncodePeerTestBlock_AllMessages tests encoding each message type.
func TestEncodePeerTestBlock_AllMessages(t *testing.T) {
	for msg := PeerTestRequest; msg <= PeerTestConfirmation; msg++ {
		t.Run(msg.String(), func(t *testing.T) {
			block := makePeerTestBlock(msg)
			encoded, err := EncodePeerTestBlock(block)
			require.NoError(t, err)
			require.NotNil(t, encoded)
			assert.Equal(t, BlockTypePeerTest, encoded.Type)

			d := encoded.Data
			assert.Equal(t, uint8(msg), d[0])
			assert.Equal(t, block.Code, d[1])
			assert.Equal(t, block.Flag, d[2])

			off := 3
			if block.hasRouterHash() {
				hBytes := block.RouterHash.Bytes()
				assert.Equal(t, hBytes[:], d[off:off+32])
				off += 32
			}
			assert.Equal(t, block.Version, d[off])
			off++
			assert.Equal(t, block.Nonce, binary.BigEndian.Uint32(d[off:off+4]))
			off += 4
			assert.Equal(t, block.Timestamp, binary.BigEndian.Uint32(d[off:off+4]))
			off += 4
			assert.Equal(t, uint8(6), d[off]) // asz for IPv4
			off++
			assert.Equal(t, block.AlicePort, binary.BigEndian.Uint16(d[off:off+2]))
			off += 2
			assert.Equal(t, block.AliceIP, d[off:off+4])
			off += 4
			assert.Equal(t, block.Signature, d[off:])
		})
	}
}

// TestEncodePeerTestBlock_IPv6 tests encoding with IPv6 address.
func TestEncodePeerTestBlock_IPv6(t *testing.T) {
	block := makePeerTestBlock(PeerTestRequest)
	block.AliceIP = net.ParseIP("2001:db8::1").To16()
	encoded, err := EncodePeerTestBlock(block)
	require.NoError(t, err)

	// asz should be 18 for IPv6
	off := 3 + 1 + 4 + 4 // msg+code+flag + ver+nonce+ts
	assert.Equal(t, uint8(18), encoded.Data[off])
}

// TestEncodePeerTestBlock_NilBlock tests error for nil input.
func TestEncodePeerTestBlock_NilBlock(t *testing.T) {
	_, err := EncodePeerTestBlock(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "PeerTestBlock is nil")
}

// TestEncodePeerTestBlock_InvalidMessageCode tests error for bad code.
func TestEncodePeerTestBlock_InvalidMessageCode(t *testing.T) {
	block := makePeerTestBlock(PeerTestRequest)
	block.MessageCode = 99
	_, err := EncodePeerTestBlock(block)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid message code")
}

// TestEncodePeerTestBlock_InvalidIP tests error for bad IP length.
func TestEncodePeerTestBlock_InvalidIP(t *testing.T) {
	block := makePeerTestBlock(PeerTestRequest)
	block.AliceIP = []byte{1, 2, 3} // invalid
	_, err := EncodePeerTestBlock(block)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid AliceIP length")
}

// TestEncodePeerTestBlock_MissingHash tests error for msg 2 without hash.
func TestEncodePeerTestBlock_MissingHash(t *testing.T) {
	block := makePeerTestBlock(PeerTestRelay)
	block.RouterHash = nil
	_, err := EncodePeerTestBlock(block)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "RouterHash must be set for message")
}

// TestDecodePeerTestBlock_Msg1 tests decoding a message 1 (no hash).
func TestDecodePeerTestBlock_Msg1(t *testing.T) {
	block := makePeerTestBlock(PeerTestRequest)
	encoded, err := EncodePeerTestBlock(block)
	require.NoError(t, err)

	decoded, err := DecodePeerTestBlock(encoded)
	require.NoError(t, err)
	assert.Equal(t, PeerTestRequest, decoded.MessageCode)
	assert.Equal(t, block.Nonce, decoded.Nonce)
	assert.Equal(t, block.Timestamp, decoded.Timestamp)
	assert.Equal(t, block.AlicePort, decoded.AlicePort)
	assert.Equal(t, block.AliceIP, decoded.AliceIP)
	assert.Nil(t, decoded.RouterHash)
}

// TestDecodePeerTestBlock_Msg2 tests decoding message 2 (with hash).
func TestDecodePeerTestBlock_Msg2(t *testing.T) {
	block := makePeerTestBlock(PeerTestRelay)
	encoded, err := EncodePeerTestBlock(block)
	require.NoError(t, err)

	decoded, err := DecodePeerTestBlock(encoded)
	require.NoError(t, err)
	assert.Equal(t, PeerTestRelay, decoded.MessageCode)
	assert.Equal(t, block.RouterHash, decoded.RouterHash)
	assert.Equal(t, block.Nonce, decoded.Nonce)
}

// TestDecodePeerTestBlock_NilBlock tests error for nil input.
func TestDecodePeerTestBlock_NilBlock(t *testing.T) {
	_, err := DecodePeerTestBlock(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "block is nil")
}

// TestDecodePeerTestBlock_WrongBlockType tests error for wrong type.
func TestDecodePeerTestBlock_WrongBlockType(t *testing.T) {
	ssu2Block := &SSU2Block{Type: BlockTypeRelayRequest, Data: make([]byte, 20)}
	_, err := DecodePeerTestBlock(ssu2Block)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid block type")
}

// TestDecodePeerTestBlock_TooShort tests error for short data.
func TestDecodePeerTestBlock_TooShort(t *testing.T) {
	ssu2Block := &SSU2Block{Type: BlockTypePeerTest, Data: make([]byte, 5)}
	_, err := DecodePeerTestBlock(ssu2Block)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}

// TestDecodePeerTestBlock_InvalidMessageCode tests error for bad code.
func TestDecodePeerTestBlock_InvalidMessageCode(t *testing.T) {
	data := make([]byte, 19)
	data[0] = 99
	data[12] = 6 // asz
	ssu2Block := NewSSU2Block(BlockTypePeerTest, data)
	_, err := DecodePeerTestBlock(ssu2Block)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid message code")
}

// TestDecodePeerTestBlock_InvalidAsz tests error for bad asz value.
func TestDecodePeerTestBlock_InvalidAsz(t *testing.T) {
	// Build a valid msg 1 then corrupt the asz byte
	block := makePeerTestBlock(PeerTestRequest)
	encoded, err := EncodePeerTestBlock(block)
	require.NoError(t, err)

	// asz is at offset 3 + 1 + 4 + 4 = 12 within data
	encoded.Data[12] = 10 // invalid asz
	_, err = DecodePeerTestBlock(encoded)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid asz")
}

// TestEncodeDecode_RoundTrip tests round-trip for all message types.
func TestEncodeDecode_RoundTrip(t *testing.T) {
	for msg := PeerTestRequest; msg <= PeerTestConfirmation; msg++ {
		t.Run(msg.String(), func(t *testing.T) {
			block := makePeerTestBlock(msg)
			if msg == PeerTestResult {
				block.Code = 1
			}

			encoded, err := EncodePeerTestBlock(block)
			require.NoError(t, err)

			decoded, err := DecodePeerTestBlock(encoded)
			require.NoError(t, err)

			assert.Equal(t, block.MessageCode, decoded.MessageCode)
			assert.Equal(t, block.Code, decoded.Code)
			assert.Equal(t, block.Flag, decoded.Flag)
			assert.Equal(t, block.Version, decoded.Version)
			assert.Equal(t, block.Nonce, decoded.Nonce)
			assert.Equal(t, block.Timestamp, decoded.Timestamp)
			assert.Equal(t, block.AlicePort, decoded.AlicePort)
			assert.Equal(t, block.AliceIP, decoded.AliceIP)

			if block.hasRouterHash() {
				assert.Equal(t, block.RouterHash, decoded.RouterHash)
			} else {
				assert.Nil(t, decoded.RouterHash)
			}

			assert.Equal(t, block.Signature, decoded.Signature)
		})
	}
}

// TestEncodePeerTestBlock_NoSignature tests encoding without signature.
func TestEncodePeerTestBlock_NoSignature(t *testing.T) {
	block := makePeerTestBlock(PeerTestProbe)
	block.Signature = nil
	encoded, err := EncodePeerTestBlock(block)
	require.NoError(t, err)

	decoded, err := DecodePeerTestBlock(encoded)
	require.NoError(t, err)
	assert.Nil(t, decoded.Signature)
	assert.Equal(t, block.Nonce, decoded.Nonce)
}
