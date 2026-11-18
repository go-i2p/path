package ssu2path

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// decodeIntroducer turns a fuzz byte stream into a RegisteredIntroducer. It is
// deliberately permissive: it produces both valid and invalid field lengths so
// the fuzzer reaches every branch of validateIntroducer. It never panics on
// short input because every read is bounds-guarded. Each field is driven by its
// own byte so a single well-formed input can satisfy all validation rules at
// once (reaching the happy-path add/copy/select paths).
func decodeIntroducer(f *testing.F, b []byte) *RegisteredIntroducer {
	_ = f
	info := &RegisteredIntroducer{}

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

	// Address family marker: 0 -> nil, 1 -> IPv4, 2 -> IPv6.
	fam := take(1)
	var family uint8
	if len(fam) > 0 {
		family = fam[0]
	}
	portBytes := take(2)
	var port uint16
	if len(portBytes) == 2 {
		port = binary.BigEndian.Uint16(portBytes)
	}
	switch family % 3 {
	case 0:
		// nil address: exercises the INVALID_ADDRESS validation branch.
		info.Addr = nil
	case 1:
		ip := make(net.IP, 4)
		copy(ip, take(4))
		info.Addr = &net.UDPAddr{IP: ip, Port: int(port)}
	default:
		ip := make(net.IP, 16)
		copy(ip, take(16))
		info.Addr = &net.UDPAddr{IP: ip, Port: int(port)}
	}

	// Router hash: a dedicated byte selects the length (0..40) so the
	// "must be exactly 32 bytes" branch and the happy path are both reachable.
	hb := take(1)
	hashLen := 32
	if len(hb) > 0 {
		hashLen = int(hb[0]) % 41
	}
	info.RouterHash = make([]byte, hashLen)
	copy(info.RouterHash, take(40))

	// Static and intro keys: a dedicated byte selects 43/44/45 around the
	// required 44.
	kb := take(1)
	keyLen := 44
	if len(kb) > 0 {
		keyLen = 43 + (int(kb[0]) % 3)
	}
	info.StaticKey = make([]byte, keyLen)
	copy(info.StaticKey, take(45))
	info.IntroKey = make([]byte, keyLen)
	copy(info.IntroKey, take(45))

	tagBytes := take(4)
	if len(tagBytes) == 4 {
		info.RelayTag = binary.BigEndian.Uint32(tagBytes)
	}

	// Seed timestamps so findOldestIndex / SelectBestIntroducers see ordering.
	info.AddedAt = time.Unix(int64(port), 0)
	info.LastSeen = time.Unix(int64(info.RelayTag), 0)
	return info
}

// FuzzIntroducerRegistry fuzzes the full introducer registry lifecycle. The
// seed corpus covers the validation matrix (nil addr, wrong hash/key lengths,
// zero relay tag) and the happy path; the fuzz body asserts the registry never
// panics and preserves its structural invariants regardless of input.
func FuzzIntroducerRegistry(f *testing.F) {
	// Seed layout (see decodeIntroducer):
	//   [family][port:2][ip:4|16][hashLenSel][hash:40][keyLenSel][static:45][intro:45][tag:4]
	// A "valid" introducer needs family!=0 (non-nil addr), hashLenSel%41==32,
	// keyLenSel%3==1 (=>44), and a non-zero tag.
	valid := func() []byte {
		b := []byte{0x01, 0x22, 0xb7} // family=1 (IPv4), port 8887
		b = append(b, 192, 168, 0, 1) // IPv4
		b = append(b, 32)             // hashLenSel -> 32
		b = append(b, make([]byte, 40)...)
		b = append(b, 1) // keyLenSel -> 44
		b = append(b, make([]byte, 45)...)
		b = append(b, make([]byte, 45)...)
		b = append(b, 0x00, 0x00, 0x00, 0x01) // relay tag = 1
		return b
	}()
	f.Add(valid)
	// Seed: nil address (family=0).
	f.Add([]byte{0x00, 0x00, 0x00})
	// Seed: zero relay tag (family=2 IPv6 path, otherwise valid).
	zeroTag := []byte{0x02, 0x00, 0x00}
	zeroTag = append(zeroTag, make([]byte, 16)...)
	zeroTag = append(zeroTag, 32)
	zeroTag = append(zeroTag, make([]byte, 40)...)
	zeroTag = append(zeroTag, 1)
	zeroTag = append(zeroTag, make([]byte, 45)...)
	zeroTag = append(zeroTag, make([]byte, 45)...)
	zeroTag = append(zeroTag, 0x00, 0x00, 0x00, 0x00) // tag = 0
	f.Add(zeroTag)
	// Seed: short hash (wrong length branch).
	f.Add([]byte{0x01, 0x00, 0x01, 10, 10, 10, 10, 5})
	// Seed: empty input.
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, b []byte) {
		// maxCount window: 0..5, exercising the <=0 default and the >3 clamp.
		maxCount := 0
		if len(b) > 0 {
			maxCount = int(b[0]) % 6
		}
		ir := NewIntroducerRegistry(maxCount)

		// maxCount <= 0 defaults to 3; > 3 clamps to 3.
		want := maxCount
		if want <= 0 {
			want = 3
		}
		if want > 3 {
			want = 3
		}
		if got := ir.GetMaxCount(); got != want {
			t.Fatalf("GetMaxCount()=%d, want %d (input maxCount=%d)", got, want, maxCount)
		}

		// Build three introducers from the stream. The first is decoded
		// directly; the next two are address-variants of it (distinct ports)
		// so that when the first is valid all three are valid and distinct,
		// filling the registry to capacity and exercising the replace-oldest
		// (findOldestIndex) and defensive-copy paths.
		base := decodeIntroducer(f, b)
		infos := []*RegisteredIntroducer{base}
		for _, p := range []uint16{1, 2} {
			v := *base
			if base.Addr != nil {
				ac := *base.Addr
				ac.Port = int(p)
				v.Addr = &ac
			}
			infos = append(infos, &v)
		}
		for _, info := range infos {
			// Errors are expected for invalid inputs; we only require no panic.
			_ = ir.AddIntroducer(info)
		}

		count := ir.GetCount()
		if count > ir.GetMaxCount() {
			t.Fatalf("GetCount()=%d exceeds GetMaxCount()=%d", count, ir.GetMaxCount())
		}

		got := ir.GetIntroducers()
		if len(got) != count {
			t.Fatalf("len(GetIntroducers())=%d != GetCount()=%d", len(got), count)
		}

		// Defensive copy: mutating the returned slice's elements must not
		// change what the registry reports on a subsequent read.
		if len(got) > 0 && got[0] != nil && len(got[0].RouterHash) > 0 {
			got[0].RouterHash[0] ^= 0xff
			again := ir.GetIntroducers()
			if len(again) > 0 && again[0] != nil && len(again[0].RouterHash) > 0 {
				if again[0].RouterHash[0] == got[0].RouterHash[0] {
					t.Fatal("GetIntroducers returned an aliased RouterHash (defensive copy broken)")
				}
			}
		}

		// SelectBestIntroducers must never return more than requested or more
		// than are registered, and must return nil for non-positive counts.
		for _, n := range []int{-1, 0, 1, 2, 5, count, count + 1} {
			sel := ir.SelectBestIntroducers(n)
			if n <= 0 && sel != nil {
				t.Fatalf("SelectBestIntroducers(%d) returned non-nil for non-positive count", n)
			}
			if n > 0 && len(sel) > n {
				t.Fatalf("SelectBestIntroducers(%d) returned %d > requested", n, len(sel))
			}
			if n > 0 && len(sel) > count {
				t.Fatalf("SelectBestIntroducers(%d) returned %d > registered %d", n, len(sel), count)
			}
		}

		// UpdateLastSeen and RemoveIntroducer must tolerate nil and any addr.
		ir.UpdateLastSeen(nil)
		if len(infos) > 0 && infos[0] != nil {
			ir.UpdateLastSeen(infos[0].Addr)
		}
		ir.RemoveIntroducer(nil)
		if len(infos) > 1 && infos[1] != nil {
			ir.RemoveIntroducer(infos[1].Addr)
		}
		if after := ir.GetCount(); after > ir.GetMaxCount() {
			t.Fatalf("GetCount()=%d exceeds max after removals", after)
		}
	})
}
