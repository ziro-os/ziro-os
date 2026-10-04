module github.com/ziro-os/zirocd

go 1.27.1

replace github.com/ziro-os/ziro-os/sdk => ../../sdk

require (
	github.com/spf13/cobra v1.10.2
	github.com/ziro-os/ziro-os/sdk v0.0.0
	golang.org/x/crypto v0.57.0
	golang.org/x/net v0.59.0
	golang.org/x/sys v0.48.0
	golang.zx2c4.com/wireguard v0.0.0-20260522210424-ecfc5a8d5446
)

require (
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/spf13/pflag v1.0.9 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
)
