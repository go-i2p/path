package ssu2path

import (
	"crypto/ed25519"
	"encoding/binary"
	"net"

	"github.com/samber/oops"
)

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

// isLocalAddress reports whether ip is assigned to a local network interface.
// Used by DetermineNATType to distinguish NATNone from NATCone.
func isLocalAddress(ip net.IP) bool {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var localIP net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				localIP = v.IP
			case *net.IPAddr:
				localIP = v.IP
			}
			if localIP != nil && localIP.Equal(ip) {
				return true
			}
		}
	}
	return false
}
