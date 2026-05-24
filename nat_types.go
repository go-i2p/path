package ssu2path

import (
	"net"
	"time"
)

// NATType represents the type of NAT detected.
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
