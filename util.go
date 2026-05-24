package ssu2path

import (
	"crypto/ed25519"
	"encoding/binary"
	"net"
	"time"

	"github.com/samber/oops"
)

// HolePunchSessionTimeout is the maximum lifetime of a pending hole-punch
// session. Shared by HolePunchCoordinator and RelayManager cleanup loops so
// both sides age out sessions at the same rate.
// L-04 fix: single definition replaces the two duplicated 30*time.Second literals.
const HolePunchSessionTimeout = 30 * time.Second

// normalizeIP converts the given IP into its compact byte form and returns
// the corresponding address-size field value per SSU2 spec (6 for IPv4, 18
// for IPv6).
//
// Return value contract (BUG-L08):
//   - ip == nil: returns (nil, 0, nil) — valid case for optional addresses
//   - ip is IPv4: returns (4-byte slice, 6, nil)
//   - ip is IPv6: returns (16-byte slice, 18, nil)
//   - ip is non-nil but invalid: returns (nil, 0, error)
//
// Callers MUST check asz == 0 to distinguish nil input from invalid IP.
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
// L-6 fix: returns an error when ip is nil to prevent a 3-byte truncated suffix
// that would cause remote signature verification to fail silently.
func buildAddrSuffix(ip net.IP, port uint16) ([]byte, error) {
	if ip == nil {
		return nil, oops.Errorf("IP address must not be nil for signature construction")
	}
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

// addrEqual reports whether two *net.UDPAddr values refer to the same endpoint.
// M-01 fix: uses net.IP.Equal instead of String comparison so that an IPv4
// address (203.0.113.1) and its IPv4-in-IPv6 form (::ffff:203.0.113.1) are
// treated as equal, consistent with Go's net.IP.Equal semantics.
// Both a and b may be nil; nil == nil is true, nil != non-nil.
func addrEqual(a, b *net.UDPAddr) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return a.Port == b.Port && a.IP.Equal(b.IP)
}
