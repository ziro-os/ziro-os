package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"
)

// Tailnet names (ziro-m1.tailfc781.ts.net) are answered by tailscaled's own resolver at 100.100.100.100
// from the node's peer list. The module joins with --accept-dns=false (Tailscale must not rewrite
// /etc/resolv.conf: smart DNS owns it), so nothing on the host asks that resolver and the names do not
// resolve. Instead of giving the daemon the system resolver, the module adds one narrow rule to smart
// DNS: the tailnet's own suffix goes to 100.100.100.100, everything else is unchanged.
//
// The rule is only ever the tailnet suffix, and only a rule whose single upstream is 100.100.100.100 is
// treated as ours: a forward the operator wrote for the same domain, or any other, is never replaced or
// removed.

// tsResolver is the address tailscaled answers MagicDNS queries on.
const tsResolver = "100.100.100.100"

// tsDNSDomain checks the MagicDNS suffix the control server reports and returns it as a forward domain
// ("" when there is none). The control server chooses it, so a suffix too short to be a tailnet's (a
// top-level or registrable domain such as example.com) is refused: forwarding it would send the host's
// own names to the tailnet resolver. Tailscale's are <tailnet>.ts.net.
func tsDNSDomain(suffix string) (string, error) {
	d := strings.ToLower(strings.Trim(strings.TrimSpace(suffix), "."))
	if d == "" {
		return "", nil
	}
	if !validDomain(d) {
		return "", fmt.Errorf("the MagicDNS suffix %q is not a domain name", suffix)
	}
	if strings.Count(d, ".") < 2 {
		return "", fmt.Errorf("the MagicDNS suffix %q is too short to forward (at least three labels, like mynet.ts.net); add a rule yourself if it is right: ziroctl dns forward add %s %s", d, d, tsResolver)
	}
	return d, nil
}

// tsOwnForward reports whether a smart DNS forward is the one this module manages.
func tsOwnForward(f DNSForward) bool {
	return len(f.Upstreams) == 1 && f.Upstreams[0] == DNSUpstream{Addr: tsResolver}
}

// tsSyncDNS makes smart DNS forward the tailnet suffix domain to MagicDNS, and removes every other rule of
// ours (an earlier tailnet, or all of them when domain is ""). Idempotent; the running resolver picks the
// file up within two seconds.
func tsSyncDNS(domain string) error {
	cfg, err := loadDNSConfig()
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	ours := DNSUpstream{Addr: tsResolver}
	var kept []DNSForward
	var conflict error
	have, changed := false, false
	for _, f := range cfg.Forwards {
		switch {
		case tsOwnForward(f) && domain != "" && fqdn(f.Domain) == fqdn(domain):
			have = true
			kept = append(kept, f)
		case tsOwnForward(f):
			changed = true // an earlier tailnet's rule, or the tailnet is gone
		default:
			if domain != "" && fqdn(f.Domain) == fqdn(domain) {
				conflict = fmt.Errorf("smart DNS already forwards %s elsewhere; left as it is (ziroctl dns forward remove %s to let Tailscale manage it)", domain, domain)
			}
			kept = append(kept, f)
		}
	}
	if domain != "" && !have && conflict == nil {
		kept = append(kept, DNSForward{Domain: domain, Upstreams: []DNSUpstream{ours}})
		changed = true
	}
	if changed {
		cfg.Forwards = kept
		if err := saveDNSConfig(cfg); err != nil {
			return err
		}
	}
	return conflict
}

// tsDNSActive reports whether smart DNS forwards domain to MagicDNS right now.
func tsDNSActive(domain string) bool {
	if domain == "" {
		return false
	}
	cfg, err := loadDNSConfig()
	if err != nil {
		return false
	}
	for _, f := range cfg.Forwards {
		if tsOwnForward(f) && fqdn(f.Domain) == fqdn(domain) {
			return true
		}
	}
	return false
}

// tsApplyDNS points smart DNS at the tailnet for a node that is up, and says what the operator needs to do
// when that cannot work yet. A node that is not joined (or whose control server reports no MagicDNS) leaves
// the rules as they are: they are removed on down, logout and disable.
func tsApplyDNS(st TailscaleStatus) []string {
	if st.State != "Running" || st.MagicDNS == "" {
		return nil
	}
	domain, err := tsDNSDomain(st.MagicDNS)
	if err == nil {
		err = tsSyncDNS(domain)
	}
	var notes []string
	if err != nil {
		notes = append(notes, "tailnet names will not resolve: "+err.Error())
	} else if !dnsEnabled() {
		notes = append(notes, fmt.Sprintf("names under %s resolve once smart DNS is on: ziroctl dns enable", domain))
	}
	return notes
}

// tsStatusOnce is tsStatus with its own short deadline.
func tsStatusOnce() (TailscaleStatus, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return tsStatus(ctx)
}

// tsApplyDNSWhenReady is tsApplyDNS for the module's start hook: tailscaled needs a moment after a
// (re)start before it reports its state, so wait a little for it to settle.
func tsApplyDNSWhenReady(wait time.Duration) {
	absent := 0
	for end := time.Now().Add(wait); ; time.Sleep(time.Second) {
		if tsIsRunning() {
			absent = 0
		} else if absent++; absent >= 3 {
			return // not running: nothing to ask, and no use waiting for it
		}
		st, err := tsStatusOnce()
		if err == nil && st.State != "" && st.State != "Starting" && st.State != "NoState" {
			for _, n := range tsApplyDNS(st) {
				fmt.Fprintf(os.Stderr, "warning: %s\n", n)
			}
			return
		}
		if time.Now().After(end) {
			return
		}
	}
}
