module github.com/ziro-os/zirocd

go 1.27.3

replace github.com/ziro-os/ziro-os/sdk => ../../sdk

require (
	github.com/spf13/cobra v1.10.2
	github.com/spf13/pflag v1.1.0
	github.com/ziro-os/ziro-os/sdk v0.3.0
	golang.org/x/crypto v0.59.0
	golang.org/x/net v0.63.0
	golang.org/x/sys v0.50.0
	golang.zx2c4.com/wireguard v0.0.0-20261024220952-b3bc704ef0ee
)

require (
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	go.yaml.in/yaml/v3 v3.0.6 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
)

// wireguard-go's go.mod requires gVisor for its optional netstack TUN, which we never import.
// Replacing it with an empty module keeps gVisor out of the build and the module graph: no gVisor
// code can be linked by accident, and scanners stop reporting advisories for code we don't ship.
replace gvisor.dev/gvisor => ../gvisor-stub
