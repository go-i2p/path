package ssu2path

import (
	"github.com/go-i2p/common/data"
	"github.com/go-i2p/crypto/rand"
)

// generateRandomHash creates a random data.Hash for testing.
func generateRandomHash() data.Hash {
	var h data.Hash
	_, _ = rand.Read(h[:])
	return h
}
