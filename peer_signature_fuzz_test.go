package ssu2path

import (
	"crypto/sha256"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/crypto/ed25519"
)

// deterministicPeerKeys derives a reproducible Ed25519 keypair from a fixed
// seed. Using a deterministic seed (rather than GenerateEd25519KeyPair) keeps
// the sign/verify round-trip reproducible across fuzz runs and CI reruns.
func deterministicPeerKeys(t *testing.T, seed string) (ed25519.Ed25519PublicKey, ed25519.Ed25519PrivateKey) {
	t.Helper()
	h := sha256.Sum256([]byte(seed))
	// The 32-byte value is a valid Ed25519 seed.
	priv, err := ed25519.NewEd25519PrivateKeyFromSeed(h[:])
	if err != nil {
		t.Fatalf("derive private key: %v", err)
	}
	signingPub, err := priv.Public()
	if err != nil {
		t.Fatalf("derive public key: %v", err)
	}
	pub, err := ed25519.NewEd25519PublicKey(signingPub.Bytes())
	if err != nil {
		t.Fatalf("build Ed25519 public key: %v", err)
	}
	return pub, priv
}

// decodePeerTestArgs parses a fuzz stream into the arguments of the peer-test
// signing helpers. It is permissive: aliceHash may be nil (messages 1/2) or set
// (messages 3/4), and aliceIP may be any byte slice (valid v4/v6 or garbage),
// so buildAddrSuffix's error path is reachable. Reads are bounds-guarded so the
// parser never panics on short input.
func decodePeerTestArgs(b []byte) (
	bobHash data.Hash,
	aliceHash *data.Hash,
	version uint8,
	nonce, timestamp uint32,
	alicePort uint16,
	aliceIP net.IP,
) {
	// Cursor-based slicing avoids binary.Reader's buffering semantics and keeps
	// every read explicitly bounds-checked.
	pos := 0
	take := func(n int) []byte {
		if pos >= len(b) {
			return nil
		}
		end := pos + n
		if end > len(b) {
			end = len(b)
		}
		seg := b[pos:end]
		pos = end
		return seg
	}

	// Bob hash: 32 bytes (missing bytes stay zero).
	var bb [32]byte
	copy(bb[:], take(32))
	bobHash = data.NewHash(bb)

	// Alice hash present flag + optional 32 bytes.
	flag := take(1)
	if len(flag) > 0 && flag[0]&1 == 1 {
		var ab [32]byte
		copy(ab[:], take(32))
		ah := data.NewHash(ab)
		aliceHash = &ah
	}

	if v := take(1); len(v) > 0 {
		version = v[0]
	}
	if v := take(4); len(v) == 4 {
		nonce = binary.BigEndian.Uint32(v)
	}
	if v := take(4); len(v) == 4 {
		timestamp = binary.BigEndian.Uint32(v)
	}
	if v := take(2); len(v) == 2 {
		alicePort = binary.BigEndian.Uint16(v)
	}

	// Remaining bytes become the IP. A 4- or 16-byte tail yields a valid
	// address; any other length exercises the normalizeIP error path.
	if rest := take(len(b) - pos); len(rest) > 0 {
		aliceIP = net.IP(append([]byte(nil), rest...))
	}
	return bobHash, aliceHash, version, nonce, timestamp, alicePort, aliceIP
}

// FuzzPeerTestSignature fuzzes the peer-test sign/verify helpers. The seed
// corpus covers messages 1/2 (nil aliceHash) and 3/4 (set aliceHash), IPv4 and
// IPv6 addresses, and invalid IP lengths. The fuzz body asserts the core
// security invariant: a freshly produced signature always verifies, and a
// tampered signature never verifies, for any decoded argument set.
func FuzzPeerTestSignature(f *testing.F) {
	// Seed: message 1/2 (nil aliceHash), IPv4, current timestamp.
	seed := func(alice bool, ip []byte) []byte {
		b := make([]byte, 32) // bob hash
		if alice {
			b = append(b, 0x01)
			b = append(b, make([]byte, 32)...)
		} else {
			b = append(b, 0x00)
		}
		b = append(b, 0x02)                   // version
		b = append(b, 0x11, 0x22, 0x33, 0x44) // nonce
		// timestamp: "now" so checkTimestampSkew passes on the happy path.
		ts := uint32(time.Now().Unix())
		b = append(b, byte(ts>>24), byte(ts>>16), byte(ts>>8), byte(ts))
		b = append(b, 0x22, 0xb7) // port 8887
		b = append(b, ip...)
		return b
	}
	f.Add(seed(false, net.ParseIP("203.0.113.45").To4()))
	f.Add(seed(true, net.ParseIP("203.0.113.45").To4()))
	f.Add(seed(true, net.ParseIP("2001:db8::1").To16()))
	f.Add(seed(false, net.ParseIP("2001:db8::1").To16()))
	// Seed: invalid IP length (3 bytes) -> buildAddrSuffix error path.
	f.Add(seed(false, []byte{1, 2, 3}))
	// Seed: empty input.
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, b []byte) {
		pub, priv := deterministicPeerKeys(t, "ssu2path-peer-test-fuzz-key")
		bobHash, aliceHash, version, nonce, timestamp, alicePort, aliceIP := decodePeerTestArgs(b)

		// BuildPeerTestSignedData and SignPeerTest must agree on the signed
		// bytes, and either both succeed or both fail together.
		built, buildErr := BuildPeerTestSignedData(bobHash, aliceHash, version, nonce, timestamp, alicePort, aliceIP)
		sig, signErr := SignPeerTest(priv, bobHash, aliceHash, version, nonce, timestamp, alicePort, aliceIP)

		if (buildErr == nil) != (signErr == nil) {
			t.Fatalf("BuildPeerTestSignedData err=%v but SignPeerTest err=%v", buildErr, signErr)
		}
		if buildErr != nil {
			// Invalid arguments (e.g. bad IP): verification must also reject.
			ok, verr := VerifyPeerTestSignature(pub, sig, bobHash, aliceHash, version, nonce, timestamp, alicePort, aliceIP)
			if ok {
				t.Fatal("VerifyPeerTestSignature returned true for invalid arguments")
			}
			_ = verr
			return
		}

		// Signed data must be deterministic: re-building yields identical bytes.
		built2, err2 := BuildPeerTestSignedData(bobHash, aliceHash, version, nonce, timestamp, alicePort, aliceIP)
		if err2 != nil || string(built) != string(built2) {
			t.Fatal("BuildPeerTestSignedData is not deterministic")
		}

		// A fresh signature must verify (with a current timestamp so the skew
		// check passes). We re-sign with a current timestamp to isolate the
		// signature invariant from the timestamp-skew guard.
		now := uint32(time.Now().Unix())
		freshSig, ferr := SignPeerTest(priv, bobHash, aliceHash, version, nonce, now, alicePort, aliceIP)
		if ferr != nil {
			t.Fatalf("SignPeerTest failed after successful build: %v", ferr)
		}
		ok, verr := VerifyPeerTestSignature(pub, freshSig, bobHash, aliceHash, version, nonce, now, alicePort, aliceIP)
		if verr != nil {
			t.Fatalf("VerifyPeerTestSignature returned unexpected error: %v", verr)
		}
		if !ok {
			t.Fatal("valid signature failed to verify")
		}

		// Tampering with the signature must make verification fail. Flip the
		// last byte; Ed25519 is strongly unforgeable so this must not verify.
		if len(freshSig) > 0 {
			tampered := append([]byte(nil), freshSig...)
			tampered[len(tampered)-1] ^= 0x01
			tok, _ := VerifyPeerTestSignature(pub, tampered, bobHash, aliceHash, version, nonce, now, alicePort, aliceIP)
			if tok {
				t.Fatal("tampered signature verified")
			}
		}

		// A different public key must not verify the signature.
		otherPub, _ := deterministicPeerKeys(t, "ssu2path-peer-test-fuzz-other")
		ook, _ := VerifyPeerTestSignature(otherPub, freshSig, bobHash, aliceHash, version, nonce, now, alicePort, aliceIP)
		if ook {
			t.Fatal("signature verified under wrong public key")
		}
	})
}
