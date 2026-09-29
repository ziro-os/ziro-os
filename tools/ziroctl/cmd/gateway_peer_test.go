package cmd

import (
	"strings"
	"testing"
)

func TestRemotePeers(t *testing.T) {
	st := policyCluster("deny") // api (8080) on a, web on b, other on c
	for i := range st.Nodes {
		st.Nodes[i].WGPubKey, st.Nodes[i].IP = "k"+st.Nodes[i].ID, "192.168.77."+string(rune('1'+i))
	}
	st.Nodes[1].Gateway, st.Nodes[2].Gateway = true, true // hub = b (lowest gateway ID)
	ip, err := allocMeshIP(st, "10.200.0.0/16")
	if err != nil || ip != "10.200.0.4" {
		t.Fatalf("alloc: %s %v", ip, err)
	}
	st.Peers = []RemotePeer{{Name: "alice", PubKey: "kalice", MeshIP: ip}}
	if ip, _ := allocMeshIP(st, "10.200.0.0/16"); ip != "10.200.0.5" {
		t.Fatalf("peer IPs must be reserved, got %s", ip)
	}
	if h := peerHub(st); h == nil || h.ID != "b" {
		t.Fatalf("hub = %+v", h)
	}

	// Non-hub node a routes alice through b; the hub b has alice as an endpoint-less peer.
	_, _, peersA := meshView(st, st.node("a"), "10.200.0.0/16")
	for _, p := range peersA {
		if (p.Node == "b") != (strings.Join(p.Routes, ",") == "10.200.0.4") || p.Node == "peer:alice" {
			t.Fatalf("a's view: %+v", peersA)
		}
	}
	_, _, peersB := meshView(st, st.node("b"), "10.200.0.0/16")
	last := peersB[len(peersB)-1]
	if last.Node != "peer:alice" || last.Endpoint != "" || last.MeshIP != "10.200.0.4" {
		t.Fatalf("hub view: %+v", peersB)
	}

	// Policy: the hub relays; the destination still requires allow_from.
	if p := policyFor(st, "b"); strings.Join(p.Transit, ",") != "10.200.0.4" {
		t.Fatalf("hub transit: %+v", p)
	}
	if p := policyFor(st, "a"); len(p.Transit) != 0 || strings.Contains(strings.Join(p.Rules[0].Sources, ","), "10.200.0.4") {
		t.Fatalf("alice must not reach api yet: %+v", p)
	}
	for _, from := range []string{"peer:alice", "peers"} {
		st.app("api").AllowFrom = []string{"web", from}
		if got := strings.Join(policyFor(st, "a").Rules[0].Sources, ","); got != "10.200.0.2,10.200.0.4" {
			t.Fatalf("%s: sources %s", from, got)
		}
	}
	s, err := buildPolicyScript(policyFor(st, "b"))
	if err != nil || !strings.Contains(s, `iifname "ziro0" oifname "ziro0" ip saddr { 10.200.0.4 } accept`) {
		t.Fatalf("hub transit rule missing (%v):\n%s", err, s)
	}
	if err := validateApp(&ClusteredApp{Name: "x", Image: "i", AllowFrom: []string{"peer:bad name"}}, nil); err == nil {
		t.Fatal("invalid peer name accepted")
	}

	c := peerClientConfig("", "10.200.0.4", "kb", "192.168.77.2:51821", "10.200.0.0/16")
	for _, want := range []string{"Address = 10.200.0.4/32", "PublicKey = kb", "Endpoint = 192.168.77.2:51821", "AllowedIPs = 10.200.0.0/16", "<your private key>"} {
		if !strings.Contains(c, want) {
			t.Fatalf("client config missing %q:\n%s", want, c)
		}
	}
}
