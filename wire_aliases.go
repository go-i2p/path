package path

import "github.com/go-i2p/go-noise/ssu2/wire"

// Type aliases from ssu2/wire so path code can reference these types
// without qualifying them with the wire package name.
type (
	SSU2Block  = wire.SSU2Block
	SSU2Packet = wire.SSU2Packet
)

// Block type constants needed by path types
const (
	BlockTypeRelayRequest    = wire.BlockTypeRelayRequest
	BlockTypeRelayResponse   = wire.BlockTypeRelayResponse
	BlockTypeRelayIntro      = wire.BlockTypeRelayIntro
	BlockTypePeerTest        = wire.BlockTypePeerTest
	BlockTypeAddress         = wire.BlockTypeAddress
	BlockTypePathChallenge   = wire.BlockTypePathChallenge
	BlockTypePathResponse    = wire.BlockTypePathResponse
	BlockTypeRelayTag        = wire.BlockTypeRelayTag
	BlockTypeNewToken        = wire.BlockTypeNewToken
	BlockTypeRelayTagRequest = wire.BlockTypeRelayTagRequest
)

// Constructor alias
var NewSSU2Block = wire.NewSSU2Block
