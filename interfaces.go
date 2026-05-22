package path

import "net"

// ListenerRef is an opaque reference to an SSU2Listener.
// It is stored by path types but not directly called.
type ListenerRef interface{}

// TokenCacheAccessor provides address-based token invalidation.
// Implemented by *ssu2.TokenCache.
type TokenCacheAccessor interface {
	InvalidateAddress(addr *net.UDPAddr)
}

// CongestionControllerAccessor provides congestion reset.
// Implemented by *ssu2/reliability.CongestionController.
type CongestionControllerAccessor interface {
	Reset()
}
