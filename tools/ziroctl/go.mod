module github.com/ziro-os/ziroctl

go 1.27.1

require (
	github.com/coreos/go-oidc/v3 v3.21.0
	github.com/google/go-tpm v0.9.8
	github.com/hashicorp/go-hclog v1.6.3
	github.com/hashicorp/raft v1.8.0
	github.com/hashicorp/raft-boltdb/v2 v2.4.2
	github.com/quic-go/quic-go v0.63.0
	github.com/spf13/cobra v1.10.2
	github.com/ziro-os/ziro-os/sdk v0.0.0
	github.com/ziro-os/zirocd v0.0.0
	go.yaml.in/yaml/v3 v3.0.5
	golang.org/x/crypto v0.57.0
	golang.org/x/net v0.59.0
	golang.org/x/oauth2 v0.37.0
	golang.org/x/term v0.46.0
	golang.zx2c4.com/wireguard v0.0.0-20260522210424-ecfc5a8d5446
)

require (
	// Not built into ziroctl, but wireguard-go's go.mod pins a gVisor affected by CVE-2026-96812
	// (fixed in 20260824.0): raise it in the module graph scanners read.
	gvisor.dev/gvisor v0.0.0-20261004063249-f57b8fc79db4 // indirect
	github.com/boltdb/bolt v1.3.1 // indirect
	github.com/fatih/color v1.19.0 // indirect
	github.com/go-jose/go-jose/v4 v4.1.4 // indirect
	github.com/hashicorp/go-immutable-radix v1.3.1 // indirect
	github.com/hashicorp/go-metrics v0.7.0 // indirect
	github.com/hashicorp/go-msgpack/v2 v2.1.5 // indirect
	github.com/hashicorp/golang-lru v1.0.2 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/mattn/go-colorable v0.1.15 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	go.etcd.io/bbolt v1.4.1 // indirect
	golang.org/x/exp v0.0.0-20250711185948-6ae5c78190dc // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	golang.org/x/time v0.15.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
)

replace github.com/ziro-os/ziro-os/sdk => ../../sdk

replace github.com/ziro-os/zirocd => ../zirocd
