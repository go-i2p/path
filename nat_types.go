package ssu2path

import (
	"net"
	"time"
)

// NATType represents the type of NAT detected.
//
// The SSU2 specification (Peer Test section) defines four peer-test *result*
// states per address type: UNKNOWN, OK, FIREWALLED, and SYMNAT. This type is a
// finer-grained NAT *classification* that refines those results for callers:
//
//   - NATUnknown        <- UNKNOWN (insufficient messages received)
//   - NATNone           <- OK, no NAT (public IP; external == internal)
//   - NATCone           <- OK, full cone (directly reachable from any peer)
//   - NATRestricted     <- OK, restricted cone (reachable from tested peers)
//   - NATPortRestricted <- OK, port-restricted cone (reachable from tested peers)
//   - NATSymmetric      <- SYMNAT (external address depends on destination)
//
// FIREWALLED (OK result but the peer cannot be reached directly) is represented
// by the Reachable/DirectProbeSuccess/RelayedProbeSuccess fields on TestResult
// rather than as a distinct NATType, since a firewalled peer may still have a
// determinable cone/symmetric classification.
type NATType int

const (
	// NATUnknown indicates NAT type is not yet determined
	NATUnknown NATType = iota

	// NATNone indicates no NAT (public IP)
	NATNone

	// NATCone indicates full cone NAT
	NATCone

	// NATRestricted indicates restricted cone NAT
	NATRestricted

	// NATPortRestricted indicates port-restricted cone NAT
	NATPortRestricted

	// NATSymmetric indicates symmetric NAT
	NATSymmetric
)

// String returns human-readable NAT type name.
func (n NATType) String() string {
	switch n {
	case NATUnknown:
		return "Unknown"
	case NATNone:
		return "None"
	case NATCone:
		return "Full Cone"
	case NATRestricted:
		return "Restricted Cone"
	case NATPortRestricted:
		return "Port-Restricted Cone"
	case NATSymmetric:
		return "Symmetric"
	default:
		return "Unknown"
	}
}

// TestResult stores the results of a completed peer test.
type TestResult struct {
	// NATType is the determined NAT type
	NATType NATType

	// ExternalAddr is the detected external address
	ExternalAddr *net.UDPAddr

	// ExternalPort is the detected external port
	ExternalPort uint16

	// Reachable indicates if peer is directly reachable
	Reachable bool

	// TestTime is when the test completed
	TestTime time.Time

	// DirectProbeSuccess indicates if Charlie → Alice direct probe succeeded
	DirectProbeSuccess bool

	// RelayedProbeSuccess indicates if Charlie → Alice via Bob succeeded
	RelayedProbeSuccess bool

	// PortConsistent indicates if external port is consistent
	PortConsistent bool

	// IPConsistent indicates if external IP is consistent
	IPConsistent bool
}
