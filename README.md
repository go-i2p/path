# go-i2p/path

SSU2 path management for the I2P network in Go. This package (`ssu2path`) implements NAT traversal, relay coordination, path validation, and peer testing for I2P's SSU2 (Secure Semi-reliable UDP v2) transport protocol.

---

## Requirements

- Go 1.26.1 or later
- `github.com/go-i2p/go-noise` (local replace directive required — see `go.mod`)

---

## Installation

```bash
go get github.com/go-i2p/path
```

Because the module uses a `replace` directive for `github.com/go-i2p/go-noise`, clone both repositories under the same parent directory:

```bash
git clone https://github.com/go-i2p/go-noise
git clone https://github.com/go-i2p/path
cd path
go build ./...
```

---

## Usage

### HolePunchCoordinator

Coordinates UDP hole punching with state tracking, retries, and signature verification. A `PendingSessionRegistry` (e.g. `*RelayManager`) must be provided at construction.

```go
coordinator := ssu2path.NewHolePunchCoordinator(relayManager, verifyFn)
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

Implements the seven-message NAT testing protocol to determine NAT type and external reachability.

```go
ptm := ssu2path.NewPeerTestManager(listener)
defer ptm.Stop() // REQUIRED

nonce, err := ptm.InitiatePeerTest(bobAddr)
result := ptm.GetResult(remoteAddr)
```

### PathValidator

Validates connection migration to a new UDP path using Path Challenge (Type 18) and Path Response (Type 19) blocks.

```go
validator := ssu2path.NewPathValidator(conn, tokenCache, congestionController)
defer validator.Stop() // REQUIRED

err := validator.InitiatePathValidation(newAddr)
```

### IntroducerRegistry

Maintains up to three introducers (per I2P specification) for RouterInfo publication.

```go
registry := ssu2path.NewIntroducerRegistry(3)
err := registry.AddIntroducer(addr, routerHash, staticKey, introKey, relayTag)
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

```go
challengeBlock := ssu2path.EncodePathChallenge(challengeID)
responseBlock  := ssu2path.EncodePathResponse(challengeID)

id, err := ssu2path.DecodePathChallenge(block)
id, err  = ssu2path.DecodePathResponse(block)
```

---

## Features

- **UDP Hole Punching** — `HolePunchCoordinator` manages hole punch attempts with a state machine (Requested → Sent → Waiting → Success/Failed), up to 3 retries, and mandatory Ed25519 signature verification per SSU2 spec
- **Relay Management** — `RelayManager` allocates cryptographically random relay tags, tracks introducers with 1-hour expiry, and manages pending sessions across concurrent goroutines
- **NAT Type Detection** — Classifies NAT as None, Full Cone, Restricted Cone, Port-Restricted Cone, or Symmetric based on probe results
- **Seven-Message Peer Testing** — `PeerTestManager` drives the full SSU2 peer test protocol (Alice ↔ Bob ↔ Charlie) to measure external reachability
- **Path Validation** — `PathValidator` safely migrates connections to new UDP paths using cryptographic challenge/response, with optional token cache invalidation and congestion window reset
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
