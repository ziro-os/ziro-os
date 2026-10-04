package daemon

import (
	"context"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"
)

// Roaming: a laptop moving from Wi-Fi to LTE (or a server getting a new address) changes its
// interfaces or default gateway. A 2-second poll notices, and Rebind finds new paths at once
// instead of waiting for timeouts.
// ponytail: polling (cheap: one interface listing); switch to netlink/route-socket events if 2s
// detection ever matters.

// netSignature summarizes what decides this host's paths: its addresses (minus the tunnel) and
// the default gateway.
func netSignature(tunName string) string {
	var parts []string
	ifs, _ := net.Interfaces()
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 || ifc.Name == tunName {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if p, err := netip.ParsePrefix(a.String()); err == nil && p.Addr().IsGlobalUnicast() {
				parts = append(parts, ifc.Name+"="+p.Addr().String())
			}
		}
	}
	sort.Strings(parts)
	if gw, err := defaultGateway(); err == nil {
		parts = append(parts, "gw="+gw.String())
	}
	return strings.Join(parts, ",")
}

// watchNetwork calls onChange whenever the signature changes (not for the first reading).
func watchNetwork(ctx context.Context, tunName string, every time.Duration, onChange func()) {
	last := netSignature(tunName)
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if cur := netSignature(tunName); cur != last {
				last = cur
				onChange()
			}
		}
	}
}
