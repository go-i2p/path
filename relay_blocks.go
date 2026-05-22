package path

import (
	"encoding/binary"
	"net"

	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// Relay block-related structures and encoding/decoding functions for SSU2 protocol.
//
// SSU2 relay mechanism uses five block types:
// - Type 7: RelayRequest - Request relay service from introducer
// - Type 8: RelayResponse - Response to relay request
// - Type 9: RelayIntro - Introduction from Bob to Charlie
// - Type 15: RelayTagRequest - Request allocation of relay tag
// - Type 16: RelayTag - Relay tag assignment
//
// Design rationale:
// - Uses standard library encoding for wire format compatibility
// - Validates all field sizes per SSU2 specification
// - Defensive copies prevent mutation of shared data
// - Error handling provides context for debugging

// RelayRequestBlock represents a relay request (Type 7).
// Alice sends this to Bob to request relay through to Charlie.
//
// Wire format per SSU2 spec:
//
//	[Flag:1][Nonce:4][RelayTag:4][Timestamp:4][Ver:1][Asz:1][AlicePort:2][AliceIP:asz-2][Signature:varies]
type RelayRequestBlock struct {
	// Flag is a 1-byte flag field (unused, set to 0)
	Flag uint8

	// Nonce uniquely identifies this relay request (4 bytes)
	Nonce uint32

	// RelayTag is the itag from Charlie's RI (4 bytes)
	RelayTag uint32

	// Timestamp is Unix timestamp in seconds (4 bytes)
	Timestamp uint32

	// Version is the SSU version for the introduction (1=SSU1, 2=SSU2)
	Version uint8

	// AlicePort is Alice's port number (2 bytes, big endian)
	AlicePort uint16

	// AliceIP is Alice's IP address (4 bytes IPv4 or 16 bytes IPv6)
	AliceIP net.IP

	// Signature is the variable-length signature (64 bytes for Ed25519)
	Signature []byte
}

// RelayResponseBlock represents a relay response (Type 8).
// Bob sends this to Alice after processing relay request.
//
// Wire format per SSU2 spec:
//
//	[Flag:1][Code:1][Nonce:4]
//
// When Code == 0 (accepted by Charlie), additional fields follow:
//
//	[Timestamp:4][Ver:1][Csz:1][CharliePort:2][CharlieIP:csz-2][Signature:varies][Token:8]
//
// When Code >= 64 (rejected by Charlie), additional fields follow:
//
//	[Timestamp:4][Ver:1][Csz:1][CharliePort:2][CharlieIP:csz-2][Signature:varies]
//
// When Code 1-63 (rejected by Bob), no additional fields.
type RelayResponseBlock struct {
	// Flag is a 1-byte flag field (unused, set to 0)
	Flag uint8

	// Code indicates success or failure reason (1 byte)
	// 0 = accepted, 1-63 = rejected by Bob, 64+ = rejected by Charlie
	Code uint8

	// Nonce matches the nonce from RelayRequest (4 bytes)
	Nonce uint32

	// Timestamp is Unix timestamp in seconds (4 bytes).
	// Present when Code == 0 or Code >= 64.
	Timestamp uint32

	// Version is the SSU version (1 byte).
	// Present when Code == 0 or Code >= 64.
	Version uint8

	// CharliePort is Charlie's port number (2 bytes).
	// Present when Code == 0 or Code >= 64 with csz > 0.
	CharliePort uint16

	// CharlieIP is Charlie's IP address.
	// Present when Code == 0 or Code >= 64 with csz > 0.
	CharlieIP net.IP

	// Signature is the variable-length signature (typically 64 bytes for Ed25519).
	// Present when Code == 0 or Code >= 64.
	Signature []byte

	// Token is the 8-byte session request token from Charlie.
	// Only present when Code == 0 (accepted).
	Token []byte
}

// RelayIntroBlock represents a relay introduction (Type 9).
// Bob sends this to Charlie to introduce Alice.
//
// Wire format per SSU2 spec:
//
//	[flag:1][AliceRouterHash:32][nonce:4][relay_tag:4][timestamp:4]
//	[ver:1][asz:1][AlicePort:2][AliceIP:asz-2][signature:varies]
type RelayIntroBlock struct {
	// Flag is a 1-byte flag field (unused, set to 0)
	Flag uint8

	// AliceRouterHash is Alice's 32-byte router identity hash
	AliceRouterHash []byte

	// Nonce uniquely identifies this relay request (4 bytes, forwarded from Alice)
	Nonce uint32

	// AliceRelayTag is the itag from Charlie's RI (4 bytes)
	AliceRelayTag uint32

	// Timestamp is when the intro was created (4 bytes, seconds since epoch)
	Timestamp uint32

	// Version is the SSU version for the introduction (1=SSU1, 2=SSU2)
	Version uint8

	// AlicePort is Alice's port number (2 bytes, big endian)
	AlicePort uint16

	// AliceIP is Alice's IP address (4 bytes IPv4 or 16 bytes IPv6)
	AliceIP net.IP

	// Signature is the variable-length signature (64 bytes for Ed25519)
	Signature []byte
}

// RelayTagRequestBlock represents a relay tag request (Type 15).
// Per spec §Relay Tag Request Block, the data portion is empty (size=0).
type RelayTagRequestBlock struct{}

// RelayTagBlock represents a relay tag assignment (Type 16).
// Per spec: relay tag is 4 bytes, big-endian, nonzero.
type RelayTagBlock struct {
	// RelayTag is the assigned tag value (4 bytes)
	RelayTag uint32
}

// EncodeRelayRequest encodes a RelayRequest block to wire format.
//
// Wire format per SSU2 spec:
// resolveIPBytes returns the wire-format IP bytes and address-size field
// for the given IP address. Returns an error for invalid addresses.
func resolveIPBytes(ip net.IP) ([]byte, uint8, error) {
	if ip4 := ip.To4(); ip4 != nil {
		return ip4, 6, nil // port(2) + IPv4(4)
	}
	if ip6 := ip.To16(); ip6 != nil {
		return ip6, 18, nil // port(2) + IPv6(16)
	}
	return nil, 0, oops.Errorf("invalid IP address")
}

// [Flag:1][Nonce:4][RelayTag:4][Timestamp:4][Ver:1][Asz:1][AlicePort:2][AliceIP:asz-2][Signature:varies]
func EncodeRelayRequest(req *RelayRequestBlock) (*SSU2Block, error) {
	if req == nil {
		return nil, oops.Errorf("RelayRequestBlock is nil")
	}
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "EncodeRelayRequest", "nonce": req.Nonce, "relayTag": req.RelayTag}).Debug("Encoding relay request block")

	ipBytes, asz, err := resolveIPBytes(req.AliceIP)
	if err != nil {
		return nil, err
	}

	// flag(1) + nonce(4) + relay_tag(4) + timestamp(4) + ver(1) + asz(1) + port(2) + ip + signature
	dataSize := 1 + 4 + 4 + 4 + 1 + 1 + 2 + len(ipBytes) + len(req.Signature)
	data := make([]byte, dataSize)

	data[0] = req.Flag
	binary.BigEndian.PutUint32(data[1:5], req.Nonce)
	binary.BigEndian.PutUint32(data[5:9], req.RelayTag)
	binary.BigEndian.PutUint32(data[9:13], req.Timestamp)
	data[13] = req.Version
	data[14] = asz
	binary.BigEndian.PutUint16(data[15:17], req.AlicePort)
	copy(data[17:17+len(ipBytes)], ipBytes)
	copy(data[17+len(ipBytes):], req.Signature)

	return NewSSU2Block(BlockTypeRelayRequest, data), nil
}

// DecodeRelayRequest decodes a RelayRequest block from wire format.
//
// Wire format: [Flag:1][Nonce:4][RelayTag:4][Timestamp:4][Ver:1][Asz:1][AlicePort:2][AliceIP:asz-2][Signature:varies]
func DecodeRelayRequest(block *SSU2Block) (*RelayRequestBlock, error) {
	if block == nil {
		return nil, oops.Errorf("block is nil")
	}

	if block.Type != BlockTypeRelayRequest {
		return nil, oops.Errorf("invalid block type: expected %d, got %d", BlockTypeRelayRequest, block.Type)
	}
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "DecodeRelayRequest", "dataLen": len(block.Data)}).Debug("Decoding relay request block")

	data := block.Data
	// Minimum: flag(1)+nonce(4)+relay_tag(4)+timestamp(4)+ver(1)+asz(1)+port(2)+ip(4) = 21
	if len(data) < 21 {
		return nil, oops.Errorf("RelayRequest block too short: %d bytes (minimum 21)", len(data))
	}

	flag := data[0]
	nonce := binary.BigEndian.Uint32(data[1:5])
	relayTag := binary.BigEndian.Uint32(data[5:9])
	timestamp := binary.BigEndian.Uint32(data[9:13])
	ver := data[13]
	asz := data[14]
	port := binary.BigEndian.Uint16(data[15:17])

	if asz != 6 && asz != 18 {
		return nil, oops.Errorf("invalid asz: %d (expected 6 or 18)", asz)
	}

	ipLen := int(asz) - 2
	if len(data) < 17+ipLen {
		return nil, oops.Errorf("RelayRequest block too short for IP: need %d, have %d", 17+ipLen, len(data))
	}

	ip := make([]byte, ipLen)
	copy(ip, data[17:17+ipLen])

	var sig []byte
	if len(data) > 17+ipLen {
		sig = make([]byte, len(data)-(17+ipLen))
		copy(sig, data[17+ipLen:])
	}

	return &RelayRequestBlock{
		Flag:      flag,
		Nonce:     nonce,
		RelayTag:  relayTag,
		Timestamp: timestamp,
		Version:   ver,
		AlicePort: port,
		AliceIP:   net.IP(ip),
		Signature: sig,
	}, nil
}

// EncodeRelayResponse encodes a RelayResponse block to wire format.
//
// Wire format per SSU2 spec:
//
//	[Flag:1][Code:1][Nonce:4][...]
//
// For Code 0 (accepted): includes Timestamp, Ver, Csz, CharliePort, CharlieIP, Signature, Token.
// For Code >= 64 (Charlie rejection): includes Timestamp, Ver, Csz, CharliePort, CharlieIP, Signature.
// For Code 1-63 (Bob rejection): only Flag, Code, Nonce.
func EncodeRelayResponse(resp *RelayResponseBlock) (*SSU2Block, error) {
	if resp == nil {
		return nil, oops.Errorf("RelayResponseBlock is nil")
	}
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "EncodeRelayResponse", "code": resp.Code, "nonce": resp.Nonce}).Debug("Encoding relay response block")

	if resp.Code == 0 {
		return encodeRelayResponseAccepted(resp)
	} else if resp.Code >= 64 {
		return encodeRelayResponseCharlieRejection(resp)
	}
	// Bob rejection (code 1-63): flag(1) + code(1) + nonce(4)
	data := make([]byte, 6)
	data[0] = resp.Flag
	data[1] = resp.Code
	binary.BigEndian.PutUint32(data[2:6], resp.Nonce)
	return NewSSU2Block(BlockTypeRelayResponse, data), nil
}

// encodeRelayResponseHeader writes the common 12-byte header shared by accepted
// and Charlie-rejection relay response encodings.
func encodeRelayResponseHeader(data []byte, resp *RelayResponseBlock, csz byte) {
	data[0] = resp.Flag
	data[1] = resp.Code
	binary.BigEndian.PutUint32(data[2:6], resp.Nonce)
	binary.BigEndian.PutUint32(data[6:10], resp.Timestamp)
	data[10] = resp.Version
	data[11] = csz
}

func encodeRelayResponseAccepted(resp *RelayResponseBlock) (*SSU2Block, error) {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "encodeRelayResponseAccepted", "nonce": resp.Nonce}).Debug("Encoding accepted relay response")
	ipBytes, csz, err := normalizeIP(resp.CharlieIP)
	if err != nil || csz == 0 {
		return nil, oops.Errorf("invalid CharlieIP for accepted response")
	}
	if len(resp.Token) != 8 {
		return nil, oops.Errorf("token must be 8 bytes for accepted response, got %d", len(resp.Token))
	}
	// flag(1)+code(1)+nonce(4)+ts(4)+ver(1)+csz(1)+port(2)+ip+sig+token(8)
	dataSize := 1 + 1 + 4 + 4 + 1 + 1 + 2 + len(ipBytes) + len(resp.Signature) + 8
	data := make([]byte, dataSize)
	encodeRelayResponseHeader(data, resp, csz)
	binary.BigEndian.PutUint16(data[12:14], resp.CharliePort)
	copy(data[14:14+len(ipBytes)], ipBytes)
	off := 14 + len(ipBytes)
	copy(data[off:off+len(resp.Signature)], resp.Signature)
	off += len(resp.Signature)
	copy(data[off:off+8], resp.Token)
	return NewSSU2Block(BlockTypeRelayResponse, data), nil
}

func encodeRelayResponseCharlieRejection(resp *RelayResponseBlock) (*SSU2Block, error) {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "encodeRelayResponseCharlieRejection", "code": resp.Code, "nonce": resp.Nonce}).Debug("Encoding Charlie rejection response")
	ipBytes, csz, _ := normalizeIP(resp.CharlieIP)
	// flag(1)+code(1)+nonce(4)+ts(4)+ver(1)+csz(1)+[port(2)+ip]+sig
	dataSize := 1 + 1 + 4 + 4 + 1 + 1 + len(resp.Signature)
	if csz > 0 {
		dataSize += 2 + len(ipBytes)
	}
	data := make([]byte, dataSize)
	encodeRelayResponseHeader(data, resp, csz)
	off := 12
	if csz > 0 {
		binary.BigEndian.PutUint16(data[off:off+2], resp.CharliePort)
		copy(data[off+2:off+2+len(ipBytes)], ipBytes)
		off += 2 + len(ipBytes)
	}
	copy(data[off:], resp.Signature)
	return NewSSU2Block(BlockTypeRelayResponse, data), nil
}

// DecodeRelayResponse decodes a RelayResponse block from wire format.
//
// Wire format: [Flag:1][Code:1][Nonce:4][...]
func DecodeRelayResponse(block *SSU2Block) (*RelayResponseBlock, error) {
	if block == nil {
		return nil, oops.Errorf("block is nil")
	}

	if block.Type != BlockTypeRelayResponse {
		return nil, oops.Errorf("invalid block type: expected %d, got %d", BlockTypeRelayResponse, block.Type)
	}
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "DecodeRelayResponse", "dataLen": len(block.Data)}).Debug("Decoding relay response block")

	data := block.Data
	if len(data) < 6 {
		return nil, oops.Errorf("RelayResponse block too short: %d bytes (minimum 6)", len(data))
	}

	resp := &RelayResponseBlock{
		Flag:  data[0],
		Code:  data[1],
		Nonce: binary.BigEndian.Uint32(data[2:6]),
	}

	if resp.Code == 0 && len(data) > 6 {
		return decodeRelayResponseAccepted(resp, data)
	} else if resp.Code >= 64 && len(data) > 6 {
		return decodeRelayResponseCharlieRejection(resp, data)
	}
	return resp, nil
}

// decodeRelayResponseHeader parses the common header fields (timestamp,
// version, Charlie endpoint) shared by accepted and rejection responses.
// Returns the byte offset past the endpoint, or an error.
func decodeRelayResponseHeader(resp *RelayResponseBlock, data []byte, label string) (int, error) {
	if len(data) < 12 {
		return 0, oops.Errorf("%s RelayResponse too short: %d bytes", label, len(data))
	}
	resp.Timestamp = binary.BigEndian.Uint32(data[6:10])
	resp.Version = data[10]
	csz := data[11]
	if csz != 0 && csz != 6 && csz != 18 {
		return 0, oops.Errorf("invalid csz: %d (expected 0, 6, or 18)", csz)
	}
	off := 12
	if csz > 0 {
		if len(data) < off+int(csz) {
			return 0, oops.Errorf("%s too short for endpoint: need %d, have %d", label, off+int(csz), len(data))
		}
		resp.CharliePort = binary.BigEndian.Uint16(data[off : off+2])
		ipLen := int(csz) - 2
		ip := make([]byte, ipLen)
		copy(ip, data[off+2:off+2+ipLen])
		resp.CharlieIP = net.IP(ip)
		off += int(csz)
	}
	return off, nil
}

func decodeRelayResponseAccepted(resp *RelayResponseBlock, data []byte) (*RelayResponseBlock, error) {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "decodeRelayResponseAccepted", "nonce": resp.Nonce, "dataLen": len(data)}).Debug("Decoding accepted relay response")
	off, err := decodeRelayResponseHeader(resp, data, "accepted")
	if err != nil {
		return nil, err
	}
	// Remaining: signature + token(8)
	remaining := len(data) - off
	if remaining < 8 {
		return nil, oops.Errorf("accepted RelayResponse too short for token: %d remaining bytes", remaining)
	}
	sigLen := remaining - 8
	if sigLen > 0 {
		resp.Signature = make([]byte, sigLen)
		copy(resp.Signature, data[off:off+sigLen])
		off += sigLen
	}
	resp.Token = make([]byte, 8)
	copy(resp.Token, data[off:off+8])
	return resp, nil
}

func decodeRelayResponseCharlieRejection(resp *RelayResponseBlock, data []byte) (*RelayResponseBlock, error) {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "decodeRelayResponseCharlieRejection", "nonce": resp.Nonce, "dataLen": len(data)}).Debug("Decoding Charlie rejection response")
	off, err := decodeRelayResponseHeader(resp, data, "Charlie rejection")
	if err != nil {
		return nil, err
	}
	if len(data) > off {
		resp.Signature = make([]byte, len(data)-off)
		copy(resp.Signature, data[off:])
	}
	return resp, nil
}

// EncodeRelayIntro encodes a RelayIntro block to wire format.
//
// Wire format per SSU2 spec:
//
//	[flag:1][AliceRouterHash:32][nonce:4][relay_tag:4][timestamp:4]
//	[ver:1][asz:1][AlicePort:2][AliceIP:asz-2][signature:varies]
func EncodeRelayIntro(intro *RelayIntroBlock) (*SSU2Block, error) {
	if intro == nil {
		return nil, oops.Errorf("RelayIntroBlock is nil")
	}

	if len(intro.AliceRouterHash) != 32 {
		return nil, oops.Errorf("AliceRouterHash must be 32 bytes, got %d", len(intro.AliceRouterHash))
	}
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "EncodeRelayIntro", "nonce": intro.Nonce, "relayTag": intro.AliceRelayTag}).Debug("Encoding relay intro block")

	ipBytes, asz, err := resolveIPBytes(intro.AliceIP)
	if err != nil {
		return nil, err
	}

	// flag(1) + hash(32) + nonce(4) + relay_tag(4) + timestamp(4) + ver(1) + asz(1) + port(2) + ip + signature
	dataSize := 1 + 32 + 4 + 4 + 4 + 1 + 1 + 2 + len(ipBytes) + len(intro.Signature)
	data := make([]byte, dataSize)

	data[0] = intro.Flag
	copy(data[1:33], intro.AliceRouterHash)
	binary.BigEndian.PutUint32(data[33:37], intro.Nonce)
	binary.BigEndian.PutUint32(data[37:41], intro.AliceRelayTag)
	binary.BigEndian.PutUint32(data[41:45], intro.Timestamp)
	data[45] = intro.Version
	data[46] = asz
	binary.BigEndian.PutUint16(data[47:49], intro.AlicePort)
	copy(data[49:49+len(ipBytes)], ipBytes)
	if len(intro.Signature) > 0 {
		copy(data[49+len(ipBytes):], intro.Signature)
	}

	return NewSSU2Block(BlockTypeRelayIntro, data), nil
}

// DecodeRelayIntro decodes a RelayIntro block from wire format.
//
// Wire format per SSU2 spec:
//
//	[flag:1][AliceRouterHash:32][nonce:4][relay_tag:4][timestamp:4]
//	[ver:1][asz:1][AlicePort:2][AliceIP:asz-2][signature:varies]
func DecodeRelayIntro(block *SSU2Block) (*RelayIntroBlock, error) {
	if block == nil {
		return nil, oops.Errorf("block is nil")
	}

	if block.Type != BlockTypeRelayIntro {
		return nil, oops.Errorf("invalid block type: expected %d, got %d", BlockTypeRelayIntro, block.Type)
	}
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "DecodeRelayIntro", "dataLen": len(block.Data)}).Debug("Decoding relay intro block")

	data := block.Data
	// Minimum: flag(1)+hash(32)+nonce(4)+tag(4)+timestamp(4)+ver(1)+asz(1)+port(2)+ip(4) = 53
	if len(data) < 53 {
		return nil, oops.Errorf("RelayIntro block too short: %d bytes (minimum 53)", len(data))
	}

	flag := data[0]
	routerHash := make([]byte, 32)
	copy(routerHash, data[1:33])
	nonce := binary.BigEndian.Uint32(data[33:37])
	relayTag := binary.BigEndian.Uint32(data[37:41])
	timestamp := binary.BigEndian.Uint32(data[41:45])
	ver := data[45]
	asz := data[46]
	port := binary.BigEndian.Uint16(data[47:49])

	if asz != 6 && asz != 18 {
		return nil, oops.Errorf("invalid asz: %d (expected 6 or 18)", asz)
	}

	ipLen := int(asz) - 2
	if len(data) < 49+ipLen {
		return nil, oops.Errorf("RelayIntro block too short for IP: need %d, have %d", 49+ipLen, len(data))
	}

	ip := make([]byte, ipLen)
	copy(ip, data[49:49+ipLen])

	var sig []byte
	if len(data) > 49+ipLen {
		sig = make([]byte, len(data)-(49+ipLen))
		copy(sig, data[49+ipLen:])
	}

	return &RelayIntroBlock{
		Flag:            flag,
		AliceRouterHash: routerHash,
		Nonce:           nonce,
		AliceRelayTag:   relayTag,
		Timestamp:       timestamp,
		Version:         ver,
		AlicePort:       port,
		AliceIP:         net.IP(ip),
		Signature:       sig,
	}, nil
}

// EncodeRelayTagRequest encodes a RelayTagRequest block to wire format.
// Per spec §Relay Tag Request Block: size=0 (empty data portion).
func EncodeRelayTagRequest(req *RelayTagRequestBlock) (*SSU2Block, error) {
	if req == nil {
		return nil, oops.Errorf("RelayTagRequestBlock is nil")
	}

	return NewSSU2Block(BlockTypeRelayTagRequest, nil), nil
}

// DecodeRelayTagRequest decodes a RelayTagRequest block from wire format.
// Per spec the data portion is empty (size=0). Non-empty data is accepted
// for backward compatibility with older implementations but is ignored.
func DecodeRelayTagRequest(block *SSU2Block) (*RelayTagRequestBlock, error) {
	if block == nil {
		return nil, oops.Errorf("block is nil")
	}

	if block.Type != BlockTypeRelayTagRequest {
		return nil, oops.Errorf("invalid block type: expected %d, got %d", BlockTypeRelayTagRequest, block.Type)
	}
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "DecodeRelayTagRequest"}).Debug("Decoding relay tag request block")

	return &RelayTagRequestBlock{}, nil
}

// EncodeRelayTag encodes a RelayTag block to wire format.
// Per spec: [RelayTag:4] (4 bytes, big-endian, nonzero)
//
// Parameters:
//   - tag: RelayTag data to encode
//
// Returns:
//   - *SSU2Block: Encoded block ready for transmission
//   - error: If validation fails
func EncodeRelayTag(tag *RelayTagBlock) (*SSU2Block, error) {
	if tag == nil {
		return nil, oops.Errorf("RelayTagBlock is nil")
	}
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "EncodeRelayTag", "relayTag": tag.RelayTag}).Debug("Encoding relay tag block")

	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data[0:4], tag.RelayTag)

	return NewSSU2Block(BlockTypeRelayTag, data), nil
}

// DecodeRelayTag decodes a RelayTag block from wire format.
// Per spec: 4 bytes minimum (relay tag only).
//
// Parameters:
//   - block: SSU2Block with Type 16
//
// Returns:
//   - *RelayTagBlock: Decoded relay tag
//   - error: If decoding fails or validation fails
func DecodeRelayTag(block *SSU2Block) (*RelayTagBlock, error) {
	if block == nil {
		return nil, oops.Errorf("block is nil")
	}

	if block.Type != BlockTypeRelayTag {
		return nil, oops.Errorf("invalid block type: expected %d, got %d", BlockTypeRelayTag, block.Type)
	}
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "DecodeRelayTag", "dataLen": len(block.Data)}).Debug("Decoding relay tag block")

	data := block.Data
	if len(data) < 4 {
		return nil, oops.Errorf("RelayTag block too short: %d bytes (minimum 4)", len(data))
	}

	relayTag := binary.BigEndian.Uint32(data[0:4])

	return &RelayTagBlock{
		RelayTag: relayTag,
	}, nil
}
