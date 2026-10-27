# go-i2p/path

SSU2 path management for the I2P network in Go. This package (`ssu2path`) implements NAT traversal, relay coordination, path validation, and peer testing for I2P's SSU2 (Secure Semi-reliable UDP v2) transport protocol.

---

## Requirements

- Go 1.26.1 or later
- `github.com/go-i2p/go-noise` (for the SSU2 wire types; a local `replace` directive is available in `go.mod` for development against a local checkout)
- `github.com/go-i2p/crypto` (for Ed25519 signatures)

All Ed25519 signing and verification is delegated to `github.com/go-i2p/crypto/ed25519` rather than the standard library, so this package never imports `crypto/ed25519` directly. Nonces, relay tags, and challenge data are generated with `github.com/go-i2p/crypto/rand` as the SSU2 spec requires.

Because `crypto/ed25519` pulls in `filippo.io/edwards25519`, that module is a required indirect dependency. Verify changes the way a consumer sees them, with the shared `go.work` disabled:

```bash
GOWORK=off go mod tidy && GOWORK=off go build ./... && GOWORK=off go test ./...
```

`.github/workflows/go-test.yaml` runs exactly this, and also checks `go mod tidy -diff`, `go vet`, and `gofmt`. A workspace-only check can hide a missing transitive requirement, which is how the published module came to fail `go build` for proxy consumers.

---

## Installation

```bash
go get github.com/go-i2p/path
```

---

## Usage

### HolePunchCoordinator

Coordinates UDP hole punching with state tracking, retries, and signature verification. A `PendingSessionRegistry` (e.g. `*RelayManager`) and a `HolePunchContextResolver` (resolves the Noise session context for signature verification) must be provided at construction.

```go
coordinator, err := ssu2path.NewHolePunchCoordinator(relayManager, resolveContext)
defer coordinator.Stop() // REQUIRED — stops the background cleanup goroutine

sessionID, err := coordinator.InitiateHolePunch(remoteAddr, introducerAddr, relayTag)
```

### RelayManager

Manages relay tag allocation, introducer registration, and pending sessions for NAT traversal.

```go
manager := ssu2path.NewRelayManager(listener)
defer manager.Stop() // REQUIRED

tag, err := manager.AllocateRelayTag(peerAddr)
err = manager.AddPendingSession(sessionID, remoteAddr, introducerAddr, relayTag)
```

### PeerTestManager

Tracks peer test state (nonce, role, deadline, result) for the SSU2 seven-message peer test protocol. The wire protocol itself (sending/receiving messages 1–7) is driven by the router, which observes the actual messages and feeds outcomes back through this manager.

```go
ptm := ssu2path.NewPeerTestManager(listener)
defer ptm.Stop() // REQUIRED

nonce, err := ptm.InitiatePeerTest(bobAddr)
result := ptm.GetResult(remoteAddr)
```

### PathValidator

Validates connection migration to a new UDP path using Path Challenge (Type 18) and Path Response (Type 19) blocks.

```go
validator := ssu2path.NewPathValidator(conn)
defer validator.Stop() // REQUIRED

// Optional: wire in token invalidation and congestion control
validator.SetTokenCache(tokenCache)
validator.SetCongestionController(congestionController)

challengeData, err := validator.InitiatePathValidation(newAddr)
```

The connection is supplied through `PathValidationConn`, whose `SendToAddress`
takes a **list** of blocks to be sent together in one Data packet:

```go
type PathValidationConn interface {
	SendToAddress(blocks []*SSU2Block, addr *net.UDPAddr, wantACK bool) error
	GetRemoteAddr() *net.UDPAddr
	SetRemoteAddr(addr *net.UDPAddr) error
}
```

Per ssu2.md §"Initiating Path Validation", a Path Challenge is "a data packet
containing a Path Challenge block, an Address block (containing the new
IP/port), and, typically, an ACK block", so `SendPathChallenge` and
`SendPathResponse` send two blocks — the challenge/response plus the Address
block — in a single packet. Without the Address block a conformant peer never
learns the new IP/port from the challenge and so cannot validate it or initiate
peer testing of it (§"Responding to Path Challenge").

The ACK is the connection's responsibility, because it is derived from receive
state that `PathValidator` cannot see. The `wantACK` argument says whether an
ACK may be added: `true` for challenges and responses, `false` for PMTU probes,
whose datagram size must be exact (§"PMTU Discovery"). A connection with nothing
to acknowledge sends no ACK, which remains spec-conformant.

Per the SSU2 spec, path validation is defined only for the data phase of a
session — migration is not permitted during the handshake. If the connection
passed to `NewPathValidator` implements the optional `HandshakePhase`
interface (`InHandshake() bool`), `InitiatePathValidation` returns an error
while a handshake is in progress.

The spec also requires the congestion window to be reduced to the minimum
while a path validation is in flight and restored only after the validation
completes. If the congestion controller passed to `SetCongestionController`
implements the optional `CongestionCapSetter` interface
(`SetCongestionCap(cwnd int)` / `ClearCongestionCap()`), the validator sets
the cap on the first in-flight validation and clears it when the last one
completes.

### IntroducerRegistry

Maintains up to three introducers (per I2P specification) for RouterInfo publication.

```go
registry := ssu2path.NewIntroducerRegistry(3)
err := registry.AddIntroducer(&ssu2path.RegisteredIntroducer{
	Addr:       addr,
	RouterHash: routerHash,
	StaticKey:  staticKey,
	IntroKey:   introKey,
	RelayTag:   relayTag,
})
introducers := registry.GetIntroducers()
```

### NAT Detection Helpers

Stateless utilities for analyzing peer test results:

```go
if ssu2path.IsPortConsistent(addr1, addr2) { /* NAT preserves port */ }
if ssu2path.IsIPConsistent(addr1, addr2)   { /* same external IP */ }
if ssu2path.IsDirectlyReachable(result)    { /* no restrictive NAT */ }
if ssu2path.IsReachableViaRelay(result)    { /* relay path works */ }

external := ssu2path.ExtractExternalAddress(result)
port     := ssu2path.ExtractExternalPort(result)
```

### Path Challenge / Response Blocks

Challenge data is arbitrary bytes (the spec recommends at least 8 bytes of
random data); the Path Response echoes the challenge data verbatim.

```go
challengeBlock := ssu2path.EncodePathChallenge(challengeData)
responseBlock  := ssu2path.EncodePathResponse(challengeData)

data, err := ssu2path.DecodePathChallenge(block)
data, err = ssu2path.DecodePathResponse(block)
```

---

## Features

- **UDP Hole Punching** — `HolePunchCoordinator` manages hole punch attempts with a state machine (Requested → Sent → Waiting → Success/Failed), up to 3 retries, and mandatory Ed25519 signature verification per SSU2 spec
- **Relay Management** — `RelayManager` allocates cryptographically random relay tags, expires each introducer when its relay tag expires (falling back to `DefaultRelayTagLifetime` for a tag it does not know), and manages pending sessions across concurrent goroutines
- **NAT Type Detection** — Classifies NAT as None, Full Cone, Restricted Cone, Port-Restricted Cone, or Symmetric based on probe results (a supplementary classifier; the authoritative reachability result is derived by the router from the seven-message protocol)
- **Peer Test State Tracking** — `PeerTestManager` tracks state for the SSU2 seven-message peer test protocol (Alice ↔ Bob ↔ Charlie); the wire protocol is driven by the router
- **Path Validation** — `PathValidator` safely migrates connections to new UDP paths using cryptographic challenge/response, sending the Path Challenge or Path Response together with an Address block for the new IP/port in a single Data packet (per spec), and asking the connection to add an ACK except on PMTU probes. Includes optional token cache invalidation, congestion window reset, and congestion cap management. Migration is rejected during the handshake (per spec) when the connection implements `HandshakePhase`
- **Introducer Registry** — Keeps up to 3 fresh introducers sorted by last-seen time for RouterInfo publication
- **Wire Format Codecs** — Encode/decode for relay blocks (Types 7, 8, 9, 15, 16), peer test blocks (Type 10, messages 1–7), and path blocks (Types 18, 19)
- **Thread Safety** — All public methods on all managers are safe for concurrent use
- **Resource Safety** — Background cleanup goroutines require explicit `Stop()` calls; `Stop()` is idempotent on all types

---

## Resource Management

Three types start background goroutines that **must** be stopped explicitly:

| Type | Cleanup Interval |
|---|---|
| `HolePunchCoordinator` | 30 seconds |
| `PeerTestManager` | 60 seconds |
| `RelayManager` | Timer-based |

Always pair construction with a deferred `Stop()`:

```go
mgr := ssu2path.NewRelayManager(listener)
defer mgr.Stop()
```

---

## License

MIT License — Copyright (c) 2026 I2P For Go
