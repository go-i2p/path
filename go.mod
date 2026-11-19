module github.com/go-i2p/path

go 1.26.8

//replace github.com/go-i2p/go-noise => ../go-noise

require (
	github.com/go-i2p/common v0.1.70002-0.20261119030747-fdf972457881
	github.com/go-i2p/crypto v0.1.70002-0.20261118201949-96ca77ddd35f
	github.com/go-i2p/go-noise v0.1.70002-0.20261119063924-ba354e7ee867
	github.com/go-i2p/logger v0.1.70001
	github.com/samber/oops v1.23.1
	github.com/stretchr/testify v1.12.1
)

require (
	filippo.io/edwards25519 v1.2.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/go-i2p/elgamal v0.1.70001 // indirect
	github.com/go-i2p/noise v1.1.70001-0.20261118202026-19560feb154e // indirect
	github.com/oklog/ulid/v2 v2.1.2 // indirect
	github.com/samber/lo v1.53.0 // indirect
	github.com/sirupsen/logrus v1.10.2 // indirect
	go.opentelemetry.io/otel v1.46.0 // indirect
	go.opentelemetry.io/otel/trace v1.46.0 // indirect
	go.step.sm/crypto v0.90.0 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
)

retract (
	v0.1.59999
	v0.1.5999
	v0.1.599
)
