package cmd

import (
	"strings"
	"testing"
)

func TestWgConfParsing(t *testing.T) {
	priv, pub := generateWgKeypair()
	conf := "[Interface]\nAddress = 10.20.0.1/24, fd00::1/64\nListenPort = 51999\nPrivateKey = " + priv +
		"\nPostUp = iptables -A FORWARD -i %i -j ACCEPT\nPostDown = iptables -D FORWARD -i %i -j ACCEPT\n" +
		"\n# Peer: a\n[Peer]\nPublicKey = AAA\nAllowedIPs = 10.20.0.2/32\n" +
		"\n# Peer: b\n[Peer]\nPublicKey = BBB\nAllowedIPs = 10.20.0.3/32\n"

	c := parseWgConf(conf)
	if c.ListenPort != 51999 || len(c.Address) != 2 || c.Address[0] != "10.20.0.1/24" || len(c.PostUp) != 1 || len(c.PostDown) != 1 {
		t.Fatalf("parseWgConf = %+v", c)
	}
	if got, err := wgPublicKey(c.PrivateKey); err != nil || got != pub {
		t.Errorf("wgPublicKey = %q, %v; want %q", got, err, pub)
	}
	if _, err := wgPublicKey("not-a-key"); err == nil {
		t.Error("wgPublicKey accepted garbage")
	}

	out, key, ok := removePeerBlock(conf, "a")
	if !ok || key != "AAA" || strings.Contains(out, "AAA") || strings.Contains(out, "# Peer: a") ||
		!strings.Contains(out, "# Peer: b\n[Peer]\nPublicKey = BBB\nAllowedIPs = 10.20.0.3/32") ||
		!strings.Contains(out, "PrivateKey = "+priv) {
		t.Errorf("removePeerBlock(a) = %q, %q, %v", out, key, ok)
	}
	if ip, err := nextPeerIP(out); err != nil || ip != "10.20.0.2/32" {
		t.Errorf("freed IP not reused: %q, %v", ip, err)
	}
	if _, _, ok := removePeerBlock(conf, "missing"); ok {
		t.Error("removed a missing peer")
	}
	if s := stripWgQuick(conf); strings.Contains(s, "Address") || !strings.Contains(s, "ListenPort") {
		t.Errorf("stripWgQuick wrong: %q", s)
	}
}
