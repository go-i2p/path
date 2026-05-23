package ssu2path

import (
	"crypto/ed25519"
	"net"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// Relay signature prologues per SSU2 spec §Relay Request and §Relay Response.
const (
	// RelayRequestPrologue is prepended to signed data for relay requests.
	// 16 bytes, not null-terminated.
	RelayRequestPrologue = "RelayRequestData"

	// RelayAgreementPrologue is prepended to signed data for relay responses.
	// 16 bytes, not null-terminated.
	RelayAgreementPrologue = "RelayAgreementOK"
)

// BuildRelayRequestSignedData constructs the data to be signed for a relay request.
//
// Per SSU2 spec §Relay Request, the signed data is:
//   - prologue: 16 bytes "RelayRequestData"
//   - bhash: Bob's 32-byte router hash
//   - chash: Charlie's 32-byte router hash
//   - nonce: 4 bytes
//   - relay tag: 4 bytes
//   - timestamp: 4 bytes
//   - ver: 1 byte
//   - asz: 1 byte (6 for IPv4, 18 for IPv6)
//   - AlicePort: 2 bytes
//   - AliceIP: (asz-2) bytes
func BuildRelayRequestSignedData(
	bobHash, charlieHash data.Hash,
	nonce, relayTag, timestamp uint32,
	version uint8,
	alicePort uint16,
	aliceIP net.IP,
) ([]byte, error) {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "BuildRelayRequestSignedData", "nonce": nonce, "relayTag": relayTag}).Debug("Building relay request signed data")
	addrSuffix, err := buildAddrSuffix(aliceIP, alicePort)
	if err != nil {
		return nil, oops.Wrapf(err, "invalid aliceIP")
	}
	return buildSignatureData(
		[]byte(RelayRequestPrologue),
		bobHash[:],
		charlieHash[:],
		uint32Bytes(nonce),
		uint32Bytes(relayTag),
		uint32Bytes(timestamp),
		[]byte{version},
		addrSuffix,
	), nil
}

// SignRelayRequest signs a relay request using Alice's Ed25519 private key.
func SignRelayRequest(
	privateKey ed25519.PrivateKey,
	bobHash, charlieHash data.Hash,
	nonce, relayTag, timestamp uint32,
	version uint8,
	alicePort uint16,
	aliceIP net.IP,
) ([]byte, error) {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "SignRelayRequest", "nonce": nonce, "relayTag": relayTag}).Debug("Signing relay request")
	data, err := BuildRelayRequestSignedData(bobHash, charlieHash, nonce, relayTag, timestamp, version, alicePort, aliceIP)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to build relay request signed data")
	}
	return signData(privateKey, data), nil
}

// VerifyRelayRequestSignature verifies a relay request signature using Alice's Ed25519 public key.
func VerifyRelayRequestSignature(
	publicKey ed25519.PublicKey,
	signature []byte,
	bobHash, charlieHash data.Hash,
	nonce, relayTag, timestamp uint32,
	version uint8,
	alicePort uint16,
	aliceIP net.IP,
) (bool, error) {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "VerifyRelayRequestSignature", "nonce": nonce, "signatureLen": len(signature)}).Debug("Verifying relay request signature")
	data, err := BuildRelayRequestSignedData(bobHash, charlieHash, nonce, relayTag, timestamp, version, alicePort, aliceIP)
	if err != nil {
		return false, oops.Wrapf(err, "failed to build relay request signed data for verification")
	}
	return verifyData(publicKey, data, signature), nil
}

// BuildRelayResponseSignedData constructs the data to be signed for a relay response.
//
// Per SSU2 spec §Relay Response, the signed data is:
//   - prologue: 16 bytes "RelayAgreementOK"
//   - bhash: Bob's 32-byte router hash
//   - nonce: 4 bytes
//   - timestamp: 4 bytes
//   - ver: 1 byte
//   - csz: 1 byte (0, 6, or 18)
//   - CharliePort: 2 bytes (not present if csz is 0)
//   - CharlieIP: (csz-2) bytes (not present if csz is 0)
func BuildRelayResponseSignedData(
	bobHash data.Hash,
	nonce, timestamp uint32,
	version uint8,
	charliePort uint16,
	charlieIP net.IP,
) ([]byte, error) {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "BuildRelayResponseSignedData", "nonce": nonce}).Debug("Building relay response signed data")
	ipBytes, csz, err := normalizeIP(charlieIP)
	if err != nil {
		return nil, oops.Wrapf(err, "invalid charlieIP")
	}

	fields := [][]byte{
		[]byte(RelayAgreementPrologue),
		bobHash[:],
		uint32Bytes(nonce),
		uint32Bytes(timestamp),
		{version},
		{csz},
	}
	if csz > 0 {
		fields = append(fields, uint16Bytes(charliePort), ipBytes)
	}
	return buildSignatureData(fields...), nil
}

// SignRelayResponse signs a relay response using the signer's Ed25519 private key.
// For accepted responses (code 0), Charlie signs. For Bob rejections (code 1-63), Bob signs.
func SignRelayResponse(
	privateKey ed25519.PrivateKey,
	bobHash data.Hash,
	nonce, timestamp uint32,
	version uint8,
	charliePort uint16,
	charlieIP net.IP,
) ([]byte, error) {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "SignRelayResponse", "nonce": nonce}).Debug("Signing relay response")
	data, err := BuildRelayResponseSignedData(bobHash, nonce, timestamp, version, charliePort, charlieIP)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to build relay response signed data")
	}
	return signData(privateKey, data), nil
}

// VerifyRelayResponseSignature verifies a relay response signature.
// For accepted responses (code 0), use Charlie's public key.
// For Bob rejections (code 1-63), use Bob's public key.
func VerifyRelayResponseSignature(
	publicKey ed25519.PublicKey,
	signature []byte,
	bobHash data.Hash,
	nonce, timestamp uint32,
	version uint8,
	charliePort uint16,
	charlieIP net.IP,
) (bool, error) {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "VerifyRelayResponseSignature", "nonce": nonce, "signatureLen": len(signature)}).Debug("Verifying relay response signature")
	data, err := BuildRelayResponseSignedData(bobHash, nonce, timestamp, version, charliePort, charlieIP)
	if err != nil {
		return false, oops.Wrapf(err, "failed to build relay response signed data for verification")
	}
	return verifyData(publicKey, data, signature), nil
}
