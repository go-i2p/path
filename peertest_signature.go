package ssu2path

import (
	"crypto/ed25519"
	"net"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// PeerTestPrologue is prepended to signed data for peer test messages.
// 16 bytes, not null-terminated, per SSU2 spec §Peer Test.
const PeerTestPrologue = "PeerTestValidate"

// BuildPeerTestSignedData constructs the data to be signed for a peer test message.
//
// Per SSU2 spec §Peer Test, the signed data is:
//   - prologue: 16 bytes "PeerTestValidate"
//   - bhash: Bob's 32-byte router hash
//   - ahash: Alice's 32-byte router hash (only for messages 3 and 4)
//   - ver: 1 byte
//   - nonce: 4 bytes
//   - timestamp: 4 bytes
//   - asz: 1 byte (6 or 18)
//   - AlicePort: 2 bytes
//   - AliceIP: (asz-2) bytes
//
// Set aliceHash to nil for messages 1 and 2.
func BuildPeerTestSignedData(
	bobHash data.Hash,
	aliceHash *data.Hash,
	version uint8,
	nonce, timestamp uint32,
	alicePort uint16,
	aliceIP net.IP,
) ([]byte, error) {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "BuildPeerTestSignedData", "nonce": nonce, "version": version, "hasAliceHash": aliceHash != nil}).Debug("Constructing signed data for peer test")
	addrSuffix, err := buildAddrSuffix(aliceIP, alicePort)
	if err != nil {
		return nil, oops.Wrapf(err, "invalid aliceIP")
	}

	fields := [][]byte{
		[]byte(PeerTestPrologue),
		bobHash[:],
	}
	if aliceHash != nil {
		fields = append(fields, aliceHash[:])
	}
	fields = append(
		fields,
		[]byte{version},
		uint32Bytes(nonce),
		uint32Bytes(timestamp),
		addrSuffix,
	)
	return buildSignatureData(fields...), nil
}

// SignPeerTest signs peer test data using the signer's Ed25519 private key.
// For messages 1/2, aliceHash should be nil. For messages 3/4, aliceHash must be provided.
func SignPeerTest(
	privateKey ed25519.PrivateKey,
	bobHash data.Hash, aliceHash *data.Hash,
	version uint8,
	nonce, timestamp uint32,
	alicePort uint16,
	aliceIP net.IP,
) ([]byte, error) {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "SignPeerTest", "nonce": nonce}).Debug("Signing peer test message")
	data, err := BuildPeerTestSignedData(bobHash, aliceHash, version, nonce, timestamp, alicePort, aliceIP)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to build peer test signed data")
	}
	return signData(privateKey, data), nil
}

// VerifyPeerTestSignature verifies a peer test signature.
// For messages 1/2, aliceHash should be nil. For messages 3/4, aliceHash must be provided.
func VerifyPeerTestSignature(
	publicKey ed25519.PublicKey,
	signature []byte,
	bobHash data.Hash, aliceHash *data.Hash,
	version uint8,
	nonce, timestamp uint32,
	alicePort uint16,
	aliceIP net.IP,
) (bool, error) {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "VerifyPeerTestSignature", "nonce": nonce, "sigLen": len(signature)}).Debug("Verifying peer test signature")
	data, err := BuildPeerTestSignedData(bobHash, aliceHash, version, nonce, timestamp, alicePort, aliceIP)
	if err != nil {
		return false, oops.Wrapf(err, "failed to build peer test signed data for verification")
	}
	return verifyData(publicKey, data, signature), nil
}
