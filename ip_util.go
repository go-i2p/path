package path

import (
	"crypto/ed25519"
	"encoding/binary"
	"net"

	"github.com/samber/oops"
)

// normalizeIP converts the given IP into its compact byte form and returns
// the corresponding address-size field value per SSU2 spec (6 for IPv4, 18
// for IPv6). A nil IP is valid and returns (nil, 0, nil).
func normalizeIP(ip net.IP) (ipBytes []byte, asz uint8, err error) {
	if ip == nil {
		return nil, 0, nil
	}
	if v4 := ip.To4(); v4 != nil {
		return v4, 6, nil
	}
	if v6 := ip.To16(); v6 != nil {
		return v6, 18, nil
	}
	return nil, 0, oops.Errorf("invalid IP address")
}

// buildSignatureData concatenates byte slices into a single signed-data buffer.
func buildSignatureData(fields ...[]byte) []byte {
	total := 0
	for _, f := range fields {
		total += len(f)
	}
	buf := make([]byte, 0, total)
	for _, f := range fields {
		buf = append(buf, f...)
	}
	return buf
}

// uint32Bytes returns a 4-byte big-endian encoding of v.
func uint32Bytes(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

// uint16Bytes returns a 2-byte big-endian encoding of v.
func uint16Bytes(v uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return b
}

// buildAddrSuffix builds the asz+port+ip suffix used in relay/peertest signatures.
func buildAddrSuffix(ip net.IP, port uint16) ([]byte, error) {
	ipBytes, asz, err := normalizeIP(ip)
	if err != nil {
		return nil, err
	}
	return buildSignatureData([]byte{asz}, uint16Bytes(port), ipBytes), nil
}

// signData signs the provided data with the given Ed25519 private key.
func signData(privateKey ed25519.PrivateKey, data []byte) []byte {
	return ed25519.Sign(privateKey, data)
}

// verifyData verifies an Ed25519 signature over the provided data.
func verifyData(publicKey ed25519.PublicKey, data, signature []byte) bool {
	return ed25519.Verify(publicKey, data, signature)
}
