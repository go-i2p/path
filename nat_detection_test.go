package path

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestIsPortConsistent tests port consistency checking.
func TestIsPortConsistent(t *testing.T) {
	addr1 := &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 8887}
	addr2 := &net.UDPAddr{IP: net.ParseIP("203.0.113.2"), Port: 8887}
	addr3 := &net.UDPAddr{IP: net.ParseIP("203.0.113.3"), Port: 9999}

	// Same port, different IPs
	assert.True(t, IsPortConsistent(addr1, addr2))

	// Different ports
	assert.False(t, IsPortConsistent(addr1, addr3))

	// Nil addresses
	assert.False(t, IsPortConsistent(nil, addr1))
	assert.False(t, IsPortConsistent(addr1, nil))
	assert.False(t, IsPortConsistent(nil, nil))
}

// TestIsIPConsistent tests IP consistency checking.
func TestIsIPConsistent(t *testing.T) {
	addr1 := &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 8887}
	addr2 := &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 9999}
	addr3 := &net.UDPAddr{IP: net.ParseIP("203.0.113.2"), Port: 8887}

	// Same IP, different ports
	assert.True(t, IsIPConsistent(addr1, addr2))

	// Different IPs
	assert.False(t, IsIPConsistent(addr1, addr3))

	// Nil addresses
	assert.False(t, IsIPConsistent(nil, addr1))
	assert.False(t, IsIPConsistent(addr1, nil))
	assert.False(t, IsIPConsistent(nil, nil))
}

// TestIsAddressConsistent tests full address consistency.
func TestIsAddressConsistent(t *testing.T) {
	addr1 := &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 8887}
	addr2 := &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 8887}
	addr3 := &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 9999}
	addr4 := &net.UDPAddr{IP: net.ParseIP("203.0.113.2"), Port: 8887}

	// Completely equal
	assert.True(t, IsAddressConsistent(addr1, addr2))

	// Same IP, different port
	assert.False(t, IsAddressConsistent(addr1, addr3))

	// Different IP, same port
	assert.False(t, IsAddressConsistent(addr1, addr4))

	// Nil addresses
	assert.False(t, IsAddressConsistent(nil, addr1))
	assert.False(t, IsAddressConsistent(addr1, nil))
	assert.False(t, IsAddressConsistent(nil, nil))
}

// TestExtractExternalAddress tests external address extraction.
func TestExtractExternalAddress(t *testing.T) {
	addr := &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 8887}
	result := &TestResult{ExternalAddr: addr}

	extracted := ExtractExternalAddress(result)
	assert.Equal(t, addr, extracted)

	// Nil result
	assert.Nil(t, ExtractExternalAddress(nil))
}

// TestExtractExternalPort tests external port extraction.
func TestExtractExternalPort(t *testing.T) {
	result := &TestResult{ExternalPort: 8887}

	port := ExtractExternalPort(result)
	assert.Equal(t, uint16(8887), port)

	// Nil result
	assert.Equal(t, uint16(0), ExtractExternalPort(nil))
}

// TestAnalyzeProbeResults_BothSucceed tests when both probes succeed.
func TestAnalyzeProbeResults_BothSucceed(t *testing.T) {
	addr1 := &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 8887}
	addr2 := &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 8887}

	result := AnalyzeProbeResults(true, true, addr1, addr2)

	assert.NotNil(t, result)
	assert.True(t, result.DirectProbeSuccess)
	assert.True(t, result.RelayedProbeSuccess)
	assert.True(t, result.PortConsistent)
	assert.True(t, result.IPConsistent)
	assert.True(t, result.Reachable)
	assert.Equal(t, addr1, result.ExternalAddr)
	assert.Equal(t, uint16(8887), result.ExternalPort)
}

// TestAnalyzeProbeResults_BothFail tests BUG-004 fix: flags cleared when both fail.
func TestAnalyzeProbeResults_BothFail(t *testing.T) {
	addr1 := &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 8887}
	addr2 := &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 8887}

	result := AnalyzeProbeResults(false, false, addr1, addr2)

	assert.NotNil(t, result)
	assert.False(t, result.DirectProbeSuccess)
	assert.False(t, result.RelayedProbeSuccess)
	// BUG-004 fix: Consistency flags should be false when both probes fail
	assert.False(t, result.PortConsistent)
	assert.False(t, result.IPConsistent)
	assert.False(t, result.Reachable)
	// BUG-013 fix: ExternalAddr should not be set when both probes fail
	assert.Nil(t, result.ExternalAddr)
}

// TestAnalyzeProbeResults_DirectOnly tests when only direct probe succeeds.
func TestAnalyzeProbeResults_DirectOnly(t *testing.T) {
	addr1 := &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 8887}
	addr2 := &net.UDPAddr{IP: net.ParseIP("203.0.113.2"), Port: 9999}

	result := AnalyzeProbeResults(true, false, addr1, addr2)

	assert.NotNil(t, result)
	assert.True(t, result.DirectProbeSuccess)
	assert.False(t, result.RelayedProbeSuccess)
	assert.False(t, result.PortConsistent)
	assert.False(t, result.IPConsistent)
	assert.True(t, result.Reachable)
	assert.Equal(t, addr1, result.ExternalAddr)
}

// TestAnalyzeProbeResults_RelayedOnly tests when only relayed probe succeeds.
func TestAnalyzeProbeResults_RelayedOnly(t *testing.T) {
	addr1 := &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 8887}
	addr2 := &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 9999}

	result := AnalyzeProbeResults(false, true, addr1, addr2)

	assert.NotNil(t, result)
	assert.False(t, result.DirectProbeSuccess)
	assert.True(t, result.RelayedProbeSuccess)
	assert.False(t, result.PortConsistent)
	assert.True(t, result.IPConsistent)
	assert.False(t, result.Reachable)
	assert.Equal(t, addr1, result.ExternalAddr)
}

// TestAnalyzeProbeResults_InconsistentPort tests inconsistent port detection.
func TestAnalyzeProbeResults_InconsistentPort(t *testing.T) {
	addr1 := &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 8887}
	addr2 := &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 9999}

	result := AnalyzeProbeResults(true, true, addr1, addr2)

	assert.False(t, result.PortConsistent)
	assert.True(t, result.IPConsistent)
}

// TestAnalyzeProbeResults_InconsistentIP tests inconsistent IP detection.
func TestAnalyzeProbeResults_InconsistentIP(t *testing.T) {
	addr1 := &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 8887}
	addr2 := &net.UDPAddr{IP: net.ParseIP("203.0.113.2"), Port: 8887}

	result := AnalyzeProbeResults(true, true, addr1, addr2)

	assert.True(t, result.PortConsistent)
	assert.False(t, result.IPConsistent)
}

// TestValidateTestResult_Valid tests validation of valid results.
func TestValidateTestResult_Valid(t *testing.T) {
	addr := &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 8887}
	result := &TestResult{
		DirectProbeSuccess:  true,
		RelayedProbeSuccess: false,
		ExternalAddr:        addr,
		PortConsistent:      true,
		IPConsistent:        true,
	}

	err := ValidateTestResult(result)
	assert.NoError(t, err)
}

// TestValidateTestResult_NilResult tests validation rejects nil.
func TestValidateTestResult_NilResult(t *testing.T) {
	err := ValidateTestResult(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be nil")
}

// TestValidateTestResult_BothFailedWithFlags tests BUG-004 validation.
func TestValidateTestResult_BothFailedWithFlags(t *testing.T) {
	// Both probes failed but consistency flags are set - invalid
	result := &TestResult{
		DirectProbeSuccess:  false,
		RelayedProbeSuccess: false,
		PortConsistent:      true, // Invalid
		IPConsistent:        false,
	}

	err := ValidateTestResult(result)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "consistency flags must be false")
}

// TestValidateTestResult_SuccessWithoutAddress tests missing external address.
func TestValidateTestResult_SuccessWithoutAddress(t *testing.T) {
	// Probe succeeded but no external address - invalid
	result := &TestResult{
		DirectProbeSuccess:  true,
		RelayedProbeSuccess: false,
		ExternalAddr:        nil, // Invalid
	}

	err := ValidateTestResult(result)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "successful probe requires external address")
}

// TestCompareNATTypes tests NAT type comparison.
func TestCompareNATTypes(t *testing.T) {
	// Less restrictive
	assert.Equal(t, -1, CompareNATTypes(NATNone, NATCone))
	assert.Equal(t, -1, CompareNATTypes(NATCone, NATRestricted))
	assert.Equal(t, -1, CompareNATTypes(NATRestricted, NATPortRestricted))
	assert.Equal(t, -1, CompareNATTypes(NATPortRestricted, NATSymmetric))

	// More restrictive
	assert.Equal(t, 1, CompareNATTypes(NATSymmetric, NATPortRestricted))
	assert.Equal(t, 1, CompareNATTypes(NATPortRestricted, NATRestricted))

	// Equal
	assert.Equal(t, 0, CompareNATTypes(NATCone, NATCone))

	// Unknown (incomparable)
	assert.Equal(t, 0, CompareNATTypes(NATUnknown, NATCone))
	assert.Equal(t, 0, CompareNATTypes(NATSymmetric, NATUnknown))
}

// TestSelectBestNATType tests BUG-012 fix: prefer known types over Unknown.
func TestSelectBestNATType(t *testing.T) {
	// Less restrictive wins
	assert.Equal(t, NATNone, SelectBestNATType(NATNone, NATCone))
	assert.Equal(t, NATCone, SelectBestNATType(NATSymmetric, NATCone))

	// Equal - returns first
	assert.Equal(t, NATCone, SelectBestNATType(NATCone, NATCone))

	// BUG-012 fix: Prefer known type over Unknown
	assert.Equal(t, NATCone, SelectBestNATType(NATUnknown, NATCone))
	assert.Equal(t, NATSymmetric, SelectBestNATType(NATSymmetric, NATUnknown))
	assert.Equal(t, NATUnknown, SelectBestNATType(NATUnknown, NATUnknown))
}

// TestSelectWorstNATType tests worst NAT type selection.
func TestSelectWorstNATType(t *testing.T) {
	// More restrictive wins
	assert.Equal(t, NATSymmetric, SelectWorstNATType(NATSymmetric, NATCone))
	assert.Equal(t, NATPortRestricted, SelectWorstNATType(NATCone, NATPortRestricted))

	// Equal - returns first
	assert.Equal(t, NATRestricted, SelectWorstNATType(NATRestricted, NATRestricted))

	// BUG-012 fix: Prefer known type over Unknown
	assert.Equal(t, NATCone, SelectWorstNATType(NATUnknown, NATCone))
	assert.Equal(t, NATSymmetric, SelectWorstNATType(NATSymmetric, NATUnknown))
}

// TestDescribeNATCapabilities tests NAT capability descriptions.
func TestDescribeNATCapabilities(t *testing.T) {
	desc := DescribeNATCapabilities(NATNone)
	assert.Contains(t, desc, "Public IP")

	desc = DescribeNATCapabilities(NATCone)
	assert.Contains(t, desc, "Full cone NAT")

	desc = DescribeNATCapabilities(NATRestricted)
	assert.Contains(t, desc, "Restricted cone NAT")

	desc = DescribeNATCapabilities(NATPortRestricted)
	assert.Contains(t, desc, "Port-restricted NAT")

	desc = DescribeNATCapabilities(NATSymmetric)
	assert.Contains(t, desc, "Symmetric NAT")

	desc = DescribeNATCapabilities(NATUnknown)
	assert.Contains(t, desc, "Unknown")
}

// TestHasPublicIP tests public IP detection.
func TestHasPublicIP(t *testing.T) {
	assert.True(t, HasPublicIP(NATNone))
	assert.True(t, HasPublicIP(NATCone))
	assert.False(t, HasPublicIP(NATRestricted))
	assert.False(t, HasPublicIP(NATSymmetric))
}

// TestRequiresRelay tests relay requirement detection.
func TestRequiresRelay(t *testing.T) {
	assert.False(t, RequiresRelay(NATNone))
	assert.False(t, RequiresRelay(NATCone))
	assert.True(t, RequiresRelay(NATPortRestricted))
	assert.True(t, RequiresRelay(NATSymmetric))
}

// TestIsSymmetricNAT tests symmetric NAT detection.
func TestIsSymmetricNAT(t *testing.T) {
	assert.False(t, IsSymmetricNAT(NATNone))
	assert.False(t, IsSymmetricNAT(NATCone))
	assert.False(t, IsSymmetricNAT(NATRestricted))
	assert.True(t, IsSymmetricNAT(NATSymmetric))
}

// TestIsDirectlyReachable tests direct reachability checking.
func TestIsDirectlyReachable(t *testing.T) {
	result := &TestResult{DirectProbeSuccess: true}
	assert.True(t, IsDirectlyReachable(result))

	result.DirectProbeSuccess = false
	assert.False(t, IsDirectlyReachable(result))

	assert.False(t, IsDirectlyReachable(nil))
}

// TestIsReachableViaRelay tests relay reachability checking.
func TestIsReachableViaRelay(t *testing.T) {
	result := &TestResult{RelayedProbeSuccess: true}
	assert.True(t, IsReachableViaRelay(result))

	result.RelayedProbeSuccess = false
	assert.False(t, IsReachableViaRelay(result))

	assert.False(t, IsReachableViaRelay(nil))
}
