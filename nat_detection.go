package ssu2path

import (
	"net"
	"time"

	"github.com/samber/oops"
)

// NAT detection helper functions for peer testing protocol.
//
// These functions provide utilities for:
// - Port and IP consistency checking across multiple observations
// - External address extraction and validation
// - Probe result analysis for NAT type determination
//
// Design rationale:
// - Helper functions separate concerns from PeerTestManager
// - Stateless functions enable easy testing and reuse
// - Defensive validation prevents nil pointer errors
// - Clear naming indicates purpose (IsPortConsistent, IsIPConsistent, etc.)

// IsPortConsistent checks if two addresses use the same port.
// This is used to determine if NAT preserves port mappings.
//
// Returns true if both addresses exist and have the same port,
// false otherwise (including nil addresses).
func IsPortConsistent(addr1, addr2 *net.UDPAddr) bool {
	if addr1 == nil || addr2 == nil {
		return false
	}
	return addr1.Port == addr2.Port
}

// IsIPConsistent checks if two addresses use the same IP.
// This is used to detect multiple NATs or proxies in the path.
//
// Returns true if both addresses exist and have equal IPs,
// false otherwise (including nil addresses).
func IsIPConsistent(addr1, addr2 *net.UDPAddr) bool {
	if addr1 == nil || addr2 == nil {
		return false
	}
	return addr1.IP.Equal(addr2.IP)
}

// IsAddressConsistent checks if two addresses are completely equal.
// This combines IP and port consistency checking.
//
// Returns true if both addresses exist and are equal,
// false otherwise (including nil addresses).
func IsAddressConsistent(addr1, addr2 *net.UDPAddr) bool {
	if addr1 == nil || addr2 == nil {
		return false
	}
	return addr1.IP.Equal(addr2.IP) && addr1.Port == addr2.Port
}

// ExtractExternalAddress gets the external address from a test result.
// Returns the ExternalAddr field, or nil if result is nil.
//
// This is a convenience function for safe access to external address.
func ExtractExternalAddress(result *TestResult) *net.UDPAddr {
	if result == nil {
		return nil
	}
	return result.ExternalAddr
}

// ExtractExternalPort gets the external port from a test result.
// Returns the ExternalPort field, or 0 if result is nil.
//
// This is a convenience function for safe access to external port.
func ExtractExternalPort(result *TestResult) uint16 {
	if result == nil {
		return 0
	}
	return result.ExternalPort
}

// IsDirectlyReachable checks if a peer is directly reachable
// based on test results.
//
// A peer is considered directly reachable if the direct probe
// succeeded, indicating no restrictive NAT/firewall blocking
// incoming connections.
//
// Returns true if result exists and direct probe succeeded.
func IsDirectlyReachable(result *TestResult) bool {
	if result == nil {
		return false
	}
	return result.DirectProbeSuccess
}

// IsReachableViaRelay checks if a peer is reachable via relay
// based on test results.
//
// A peer is reachable via relay if the relayed probe succeeded,
// indicating the relay mechanism can establish connectivity.
//
// Returns true if result exists and relayed probe succeeded.
func IsReachableViaRelay(result *TestResult) bool {
	if result == nil {
		return false
	}
	return result.RelayedProbeSuccess
}

// HasPublicIP checks if the NAT type indicates a public IP.
// No NAT or full cone NAT typically indicates public accessibility.
//
// Returns true if NAT type is NATNone or NATCone.
func HasPublicIP(natType NATType) bool {
	return natType == NATNone || natType == NATCone
}

// RequiresRelay checks if the NAT type requires relay assistance
// for incoming connections.
//
// Symmetric and port-restricted NATs typically require relay
// or hole punching for peer-to-peer connectivity.
//
// Returns true if NAT type is symmetric or port-restricted.
func RequiresRelay(natType NATType) bool {
	return natType == NATSymmetric || natType == NATPortRestricted
}

// IsSymmetricNAT checks if the NAT type is symmetric.
// Symmetric NAT is the most restrictive type, requiring
// sophisticated traversal techniques.
//
// Returns true if NAT type is NATSymmetric.
func IsSymmetricNAT(natType NATType) bool {
	return natType == NATSymmetric
}

// AnalyzeProbeResults analyzes probe outcomes and address consistency
// to build a TestResult summary.
//
// This helper consolidates probe data into a structured result
// for NAT type determination.
//
// Parameters:
//   - directSuccess: Whether direct probe (Charlie → Alice) succeeded
//   - relayedSuccess: Whether relayed probe succeeded
//   - addr1: First observed external address
//   - addr2: Second observed external address
//
// Returns a TestResult with consistency flags set.
func AnalyzeProbeResults(directSuccess, relayedSuccess bool, addr1, addr2 *net.UDPAddr) *TestResult {
	result := &TestResult{
		DirectProbeSuccess:  directSuccess,
		RelayedProbeSuccess: relayedSuccess,
	}

	// BUG-004 fix: Only set consistency flags and external address if at least one probe succeeded
	// This ensures ValidateTestResult contract is satisfied
	if directSuccess || relayedSuccess {
		result.PortConsistent = IsPortConsistent(addr1, addr2)
		result.IPConsistent = IsIPConsistent(addr1, addr2)

		// Set external address from first non-nil address
		// M-05 fix: deep copy to prevent caller from mutating shared state.
		if addr1 != nil {
			a := *addr1
			result.ExternalAddr = &a
			result.ExternalPort = uint16(addr1.Port)
		} else if addr2 != nil {
			a := *addr2
			result.ExternalAddr = &a
			result.ExternalPort = uint16(addr2.Port)
		}
	}

	// FIX-6.1: Set reachability based on probe success.
	// WARNING: A single probe is insufficient for robust reachability determination.
	// Callers MUST implement retry/aggregation logic before marking a node as
	// unreachable based on a single failed probe. Single dropped UDP packets are
	// common on lossy paths and do not indicate true unreachability.
	// Example: Re-probe on first failure; only mark unreachable after N failures.
	result.Reachable = directSuccess

	// BUG-L09 fix: Initialize TestTime to current time
	result.TestTime = time.Now()

	return result
}

// ValidateTestResult checks if a TestResult has valid data.
//
// A valid result must have:
// - At least one probe attempted (direct or relayed)
// - External address if any probe succeeded
// - Consistency flags properly set
//
// Returns error if result is invalid, nil otherwise.
func ValidateTestResult(result *TestResult) error {
	if result == nil {
		return oops.
			Code("NIL_RESULT").
			In("nat_detection").
			With("reason", "test result is nil").
			Errorf("test result cannot be nil")
	}

	// At least one probe must have been attempted
	if !result.DirectProbeSuccess && !result.RelayedProbeSuccess {
		// Both probes failed — result is valid but NAT detection is inconclusive.
		// Ensure consistency flags are cleared to avoid misleading callers.
		if result.PortConsistent || result.IPConsistent {
			return oops.
				Code("INCONSISTENT_FLAGS").
				In("nat_detection").
				Errorf("consistency flags must be false when both probes fail")
		}
	}

	// If any probe succeeded, we should have an external address
	if (result.DirectProbeSuccess || result.RelayedProbeSuccess) && result.ExternalAddr == nil {
		return oops.
			Code("MISSING_EXTERNAL_ADDR").
			In("nat_detection").
			With("direct_success", result.DirectProbeSuccess).
			With("relayed_success", result.RelayedProbeSuccess).
			Errorf("successful probe requires external address")
	}

	return nil
}

// CompareNATTypes determines if one NAT type is more restrictive
// than another.
//
// Returns:
//   - -1 if nat1 is less restrictive than nat2
//   - 0 if equal restrictiveness
//   - +1 if nat1 is more restrictive than nat2
//
// Restrictiveness order (least to most):
// NATNone < NATCone < NATRestricted < NATPortRestricted < NATSymmetric
// NATUnknown is incomparable (returns 0)
func CompareNATTypes(nat1, nat2 NATType) int {
	// Define restrictiveness scores
	getScore := func(natType NATType) int {
		switch natType {
		case NATNone:
			return 0
		case NATCone:
			return 1
		case NATRestricted:
			return 2
		case NATPortRestricted:
			return 3
		case NATSymmetric:
			return 4
		case NATUnknown:
			return -1 // Incomparable
		default:
			return -1
		}
	}

	score1 := getScore(nat1)
	score2 := getScore(nat2)

	// Unknown types are incomparable
	if score1 == -1 || score2 == -1 {
		return 0
	}

	if score1 < score2 {
		return -1
	} else if score1 > score2 {
		return 1
	}
	return 0
}

// SelectBestNATType chooses the less restrictive NAT type
// from two options.
//
// This is useful when multiple test results suggest different
// NAT types - we prefer the less restrictive interpretation
// to enable more connectivity options.
//
// Returns the less restrictive NAT type, or nat1 if equal.
// BUG-012 fix: If one type is NATUnknown, prefer the known type.
func SelectBestNATType(nat1, nat2 NATType) NATType {
	// Handle unknown types specially
	if nat1 == NATUnknown && nat2 != NATUnknown {
		return nat2 // Prefer the known type
	}
	if nat2 == NATUnknown && nat1 != NATUnknown {
		return nat1 // Prefer the known type
	}

	comparison := CompareNATTypes(nat1, nat2)
	if comparison <= 0 {
		return nat1 // nat1 is less or equal restrictive
	}
	return nat2 // nat2 is less restrictive
}

// SelectWorstNATType chooses the more restrictive NAT type
// from two options.
//
// This is useful for conservative NAT detection - assuming
// the worst case ensures relay mechanisms are properly engaged.
//
// Returns the more restrictive NAT type, or nat1 if equal.
// BUG-012 fix: If one type is NATUnknown, prefer the known type.
func SelectWorstNATType(nat1, nat2 NATType) NATType {
	// Handle unknown types specially
	if nat1 == NATUnknown && nat2 != NATUnknown {
		return nat2 // Prefer the known type
	}
	if nat2 == NATUnknown && nat1 != NATUnknown {
		return nat1 // Prefer the known type
	}

	comparison := CompareNATTypes(nat1, nat2)
	if comparison >= 0 {
		return nat1 // nat1 is more or equal restrictive
	}
	return nat2 // nat2 is more restrictive
}

// IsValidSourcePort checks if a UDP address has a valid (non-reserved) source port.
//
// Port 0 is reserved by IANA and must not appear in peer test messages.
// Accepting port 0 could allow crafted packets to bypass connectivity checks
// or cause subtle failures in NAT traversal logic.
//
// Returns true if addr is non-nil and port is in the range [1, 65535].
func IsValidSourcePort(addr *net.UDPAddr) bool {
	if addr == nil {
		return false
	}
	return addr.Port > 0
}

// DescribeNATCapabilities returns a human-readable description
// of what connectivity is possible with the given NAT type.
//
// This helps users understand the implications of their NAT type.
func DescribeNATCapabilities(natType NATType) string {
	switch natType {
	case NATNone:
		return "Public IP - accepts incoming connections directly"
	case NATCone:
		return "Full cone NAT - accepts incoming from any source after outgoing"
	case NATRestricted:
		return "Restricted cone NAT - accepts incoming only from contacted IPs"
	case NATPortRestricted:
		return "Port-restricted NAT - accepts incoming only from contacted IP:port pairs"
	case NATSymmetric:
		return "Symmetric NAT - requires relay or hole punching for incoming"
	case NATUnknown:
		return "Unknown NAT type - detection incomplete or failed"
	default:
		return "Unrecognized NAT type"
	}
}

// isLocalAddress reports whether ip is assigned to a local network interface.
// Used by DetermineNATType to distinguish NATNone from NATCone.
//
// L-7 fix: check pure-computation predicates first (loopback, private, link-local)
// to avoid the net.Interfaces() syscall in the common case. Only fall back to
// interface enumeration for addresses that pass those checks (uncommon in NAT context).
func isLocalAddress(ip net.IP) bool {
	if ip == nil {
		return false
	}
	// Fast path: pure computation, no syscalls.
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return true
	}
	// Slow path: check whether the IP is assigned to a local interface.
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

// DetermineNATType analyzes test results to determine NAT type.
//
// Logic per I2P specification:
//   - Both probes succeed + consistent port/IP = No NAT or Full Cone
//   - Direct fails + relayed succeeds = Symmetric or Port-Restricted
//   - Port inconsistent = Symmetric NAT
//   - IP inconsistent = Multiple NATs or proxy
//
// Parameters:
//   - result: Test result with probe outcomes
//
// Returns determined NAT type.
func DetermineNATType(result *TestResult) NATType {
	if result == nil {
		return NATUnknown
	}

	// Both probes succeeded
	if result.DirectProbeSuccess && result.RelayedProbeSuccess {
		return determineNATFromBothProbes(result)
	}

	// Only relayed probe succeeded
	if !result.DirectProbeSuccess && result.RelayedProbeSuccess {
		return determineNATFromRelayedOnly(result)
	}

	// Neither probe succeeded
	if !result.DirectProbeSuccess && !result.RelayedProbeSuccess {
		return NATUnknown
	}

	// FIX-6.2: Direct succeeded, relay failed.
	// Relay failure can occur for reasons unrelated to NAT (relay outage, network partition).
	// Direct probe success indicates the peer is reachable, at least from this vantage point.
	// Return NATNone conservatively: direct reachability implies either public IP or full-cone NAT.
	// Callers should re-probe with a different relay if they need to distinguish NATNone vs NATCone.
	return NATNone
}

// determineNATFromBothProbes determines NAT type when both direct and relayed probes succeeded.
// This helper reduces cyclomatic complexity in DetermineNATType.
// FIX-6.3: Improved heuristics for NATNone vs NATCone distinction.
func determineNATFromBothProbes(result *TestResult) NATType {
	if result.PortConsistent && result.IPConsistent {
		// FIX-6.3: Check whether the observed external address is actually local.
		// isLocalAddress uses fast predicates first (loopback, private, link-local),
		// then falls back to interface enumeration only for public-looking addresses.
		// However, hosts with 1:1 NAT or cloud floating IPs have public IP not assigned
		// to a local interface, causing misclassification as NATCone.
		// Strategy: Prefer conservative NATNone unless we're sure it's a full-cone NAT.
		// If the address is clearly not local (fails isLocalAddress check but probe succeeded),
		// it's likely a public IP behind 1:1 NAT. Return NATNone in ambiguous cases.
		if result.ExternalAddr != nil {
			if isLocalAddress(result.ExternalAddr.IP) {
				// Address is explicitly assigned to a local interface -> NATNone
				return NATNone
			}
			// FIX-6.3: Ambiguous case - address not found on local interface.
			// Could be public IP (NATNone), full-cone NAT (NATCone), or 1:1 NAT.
			// Conservative approach: prefer NATNone to enable direct peer connectivity.
			// Higher-level policy can add secondary checks (e.g., check if address is
			// in known public IP space) if finer distinction is needed.
			return NATNone
		}
		// No external address (shouldn't happen, but be defensive)
		return NATCone
	}
	if !result.PortConsistent {
		// Port changes = symmetric or port-restricted
		return NATPortRestricted
	}
	if !result.IPConsistent {
		// IP changes = multiple NATs or proxies
		return NATRestricted
	}
	return NATUnknown
}

// determineNATFromRelayedOnly determines NAT type when only relayed probe succeeded.
// This helper reduces cyclomatic complexity in DetermineNATType.
func determineNATFromRelayedOnly(result *TestResult) NATType {
	if result.PortConsistent {
		// Port stays same but direct fails = restricted cone
		return NATRestricted
	}
	// Port changes = symmetric NAT
	return NATSymmetric
}
