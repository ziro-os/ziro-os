package cmd

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	zr "github.com/ziro-os/ziro-os/sdk/router"
	"github.com/ziro-os/zirocd/relay"
)

func TestMeshPeersConversion(t *testing.T) {
	ps := meshPeers([]MeshPeer{
		{Node: "n2", PubKey: wgKey(2), DiscoKey: wgKey(102), MeshIP: "10.200.0.2", PodCIDR: "10.201.2.0/24",
			Endpoints: []string{"203.0.113.2:51821"}, Relays: []zr.RelayRTT{{Name: "r1", RTT: 9}}, NAT: "easy"},
		{Node: "n3", PubKey: wgKey(3), MeshIP: "10.200.0.3", Endpoint: "198.51.100.3:51821", Routes: []string{"10.200.9.9"}},
	})
	a, b := ps[0], ps[1]
	if a.DiscoKey != wgKey(102) || a.HomeRelay != "r1" || a.NAT != "easy" || len(a.AllowedIPs) != 2 || a.AllowedIPs[1] != "10.201.2.0/24" {
		t.Fatalf("n2: %+v", a)
	}
	if b.Endpoints[0] != "198.51.100.3:51821" || b.AllowedIPs[1] != "10.200.9.9/32" || b.DiscoKey != "" {
		t.Fatalf("n3 (direct-mode peer / remote routes): %+v", b)
	}
}

func TestMeshModeSwitch(t *testing.T) {
	st := &ClusterState{Apps: []ClusteredApp{{Name: "web", Network: "pod"}, {Name: "db"}}}
	if _, err := setMeshMode(st, "anywhere"); err == nil {
		t.Fatal("anywhere without a relay accepted")
	}
	routerOf(st).Relays = []zr.Relay{{Name: "r1"}}
	before := specHash(st.Apps[0])
	if ch, err := setMeshMode(st, "anywhere"); !ch || err != nil || st.MeshMode != "anywhere" {
		t.Fatalf("switch: %v %v", ch, err)
	}
	if st.Apps[0].NetEpoch != 1 || st.Apps[1].NetEpoch != 0 || specHash(st.Apps[0]) == before {
		t.Fatal("pod-network apps must roll (new pod MTU); host-port apps must not")
	}
	if ch, _ := setMeshMode(st, "anywhere"); ch {
		t.Fatal("no-op switch reported a change")
	}
	// Path soft state never makes a Raft commit.
	st.Nodes = []ClusterNode{{ID: "n1"}}
	k1 := hardKey(st)
	st.Nodes[0].MeshEPs, st.Nodes[0].MeshRelays, st.Nodes[0].MeshNAT = []string{"1.2.3.4:5"}, []zr.RelayRTT{{Name: "r1"}}, "hard"
	if string(hardKey(st)) != string(k1) {
		t.Fatal("mesh soft state changed the hard key")
	}
}

// Node certificates open relay sessions for the mesh only: never a master, never a device, and
// the relay forwards between nodes but not between a node and a router device.
func TestNodeCertificatesAndRelay(t *testing.T) {
	clusterDir = t.TempDir()
	st, n := routerTestState(t, zr.ACL{})
	if err := ensureMasterCert(st, "m1", []net.IP{net.ParseIP("127.0.0.1")}); err != nil {
		t.Fatal(err)
	}
	node := func(id string) (*tls.Certificate, string) {
		keyPEM, csr, _ := zr.NewTLSKey()
		crt, kh, err := signNodeCSR(st, string(csr), id)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := tls.X509KeyPair([]byte(crt), keyPEM)
		leaf, _ := x509.ParseCertificate(c.Certificate[0])
		if verifyMaster(leaf, st.CACert) == nil {
			t.Fatal("a node certificate passed as a master")
		}
		cs := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: [][]*x509.Certificate{{leaf}}}
		if _, _, ok := deviceFromTLS(cs); ok {
			t.Fatal("a node certificate passed as a router device")
		}
		if got, _, ok := nodeFromTLS(cs); !ok || got != id {
			t.Fatal("node identity")
		}
		return &c, kh
	}
	c1, kh1 := node("n1")
	c2, kh2 := node("n2")
	dev, khD := relayDevice(t, st, "d1")
	cs := &ClusterState{MeshMode: "anywhere", Nodes: []ClusterNode{
		{ID: "n1", WGPubKey: wgKey(1), CertHash: kh1}, {ID: "n2", WGPubKey: wgKey(2), CertHash: kh2}}}
	routerOf(cs).Members = []zr.Member{{ID: "d1", Network: n.ID, NodeKey: wgKey(3), KeyHash: khD, Authorized: true}}
	if m := relayMembers(cs); len(m.Members) != 3 || m.Members[1].ID != "node:n1" {
		t.Fatalf("relay members: %+v", m.Members)
	}
	cs.MeshMode = ""
	if m := relayMembers(cs); len(m.Members) != 1 {
		t.Fatal("direct mode: nodes must not use relays")
	}
	cs.MeshMode = "anywhere"
	s := relay.New()
	s.SetMembers(relayMemberSet(relayMembers(cs)))
	tc, _ := relayTLS(st.CACert)
	ln, _ := tls.Listen("tcp", "127.0.0.1:0", tc)
	go s.Serve(t.Context(), ln, "127.0.0.1:0")
	ca, _ := parseCertPEM(st.CACert)
	dial := func(c *tls.Certificate) *zr.RelayConn {
		rc, err := zr.DialRelay(t.Context(), zr.Relay{Addr: ln.Addr().String()}, ca, c)
		if err != nil {
			t.Fatal(err)
		}
		return rc
	}
	a, b, d := dial(c1), dial(c2), dial(dev)
	time.Sleep(100 * time.Millisecond)
	kb, kd := keyOf32(wgKey(2)), keyOf32(wgKey(3))
	a.WriteFrame(zr.FrameSend, kb[:], []byte("node-to-node"))
	if got := readRecv(t, b); got != "node-to-node" {
		t.Fatalf("node to node: %q", got)
	}
	a.WriteFrame(zr.FrameSend, kd[:], []byte("node-to-device"))
	if got := readRecv(t, d); got != "" {
		t.Fatalf("a node reached a router device: %q", got)
	}
}

func keyOf32(b64 string) [32]byte {
	raw, _ := base64Std(b64)
	return [32]byte(raw)
}

func readRecv(t *testing.T, rc *zr.RelayConn) string {
	_ = rc.Conn.SetReadDeadline(time.Now().Add(700 * time.Millisecond))
	for {
		typ, _, p, err := rc.ReadFrame()
		if err != nil {
			return ""
		}
		if typ == zr.FrameRecv {
			return string(p)
		}
	}
}

func base64Std(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }

// TestMeshAnywhereHeartbeat drives the real heartbeat handler: path soft state flows from one
// node to its peers, node certificates are issued for relays, and the mode and relays are sent.
func TestMeshAnywhereHeartbeat(t *testing.T) {
	clusterDir = t.TempDir()
	defer func() { clusterDir = "/etc/ziro/cluster" }()
	srv := httptest.NewTLSServer(newClusterServer().handler())
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "https://")
	sum := sha256.Sum256(srv.Certificate().Raw)
	caHash := "sha256:" + hex.EncodeToString(sum[:])
	if err := saveClusterConfig(&ClusterConfig{ClusterID: "c", Role: "master", NodeID: "m1", MasterAddr: addr,
		JoinToken: "jt", NodeToken: "mt", CAHash: caHash}); err != nil {
		t.Fatal(err)
	}
	_ = withState(func(st *ClusterState) error {
		st.NodeTokens["m1"] = hashToken("mt")
		st.Nodes = []ClusterNode{{ID: "m1", Role: "master", LastSeen: time.Now()}}
		routerOf(st).Relays = []zr.Relay{{Name: "r1", Addr: "198.51.100.1:8443", STUN: "198.51.100.1:3478"}}
		st.MeshMode = "anywhere"
		return ensureCA(st)
	})
	join := func(h string) *ClusterConfig {
		var jr joinResponse
		if err := clusterPost(addr, caHash, "/cluster/v1/join", "Bearer jt", joinRequest{Hostname: h}, &jr); err != nil {
			t.Fatal(err)
		}
		return &ClusterConfig{NodeID: jr.NodeID, NodeToken: jr.NodeToken}
	}
	w1, w2 := join("w1"), join("w2")
	_, csr, _ := zr.NewTLSKey()
	req := heartbeatRequest{WGPubKey: wgKey(11), WGPort: meshPort, DiscoKey: wgKey(111), MeshEPs: []string{"203.0.113.11:51821"},
		Relays: []zr.RelayRTT{{Name: "r1", RTT: 12}}, NAT: "hard", NodeCSR: string(csr)}
	var hb1 heartbeatResponse
	if err := clusterPost(addr, caHash, "/cluster/v1/heartbeat", nodeAuth(w1), req, &hb1); err != nil {
		t.Fatal(err)
	}
	crt, err := parseCertPEM(hb1.NodeCert)
	if err != nil || crt.Subject.CommonName != w1.NodeID || crt.Subject.OrganizationalUnit[0] != nodeOU {
		t.Fatalf("node certificate: %v %+v", err, crt)
	}
	if hb1.MeshMode != "anywhere" || len(hb1.Relays) != 1 {
		t.Fatalf("mode/relays: %q %v", hb1.MeshMode, hb1.Relays)
	}
	var hb2 heartbeatResponse
	if err := clusterPost(addr, caHash, "/cluster/v1/heartbeat", nodeAuth(w2), heartbeatRequest{WGPubKey: wgKey(12), WGPort: meshPort}, &hb2); err != nil {
		t.Fatal(err)
	}
	var seen *MeshPeer
	for i := range hb2.Peers {
		if hb2.Peers[i].Node == w1.NodeID {
			seen = &hb2.Peers[i]
		}
	}
	if seen == nil || seen.DiscoKey != wgKey(111) || seen.Endpoints[0] != "203.0.113.11:51821" || seen.NAT != "hard" || seen.Relays[0].Name != "r1" {
		t.Fatalf("w2's view of w1: %+v", seen)
	}
	bad := req
	bad.MeshEPs, bad.NodeCSR = []string{"not-an-endpoint"}, ""
	if err := clusterPost(addr, caHash, "/cluster/v1/heartbeat", nodeAuth(w1), bad, nil); err == nil {
		t.Fatal("an invalid mesh endpoint was accepted")
	}
	st, _ := readState()
	if n := st.node(w1.NodeID); n == nil || n.CertHash == "" || n.DiscoKey != wgKey(111) {
		t.Fatal("node certificate hash / disco key not stored")
	}
}

// relayDevice issues a device certificate for member id, as the router would.
func relayDevice(t *testing.T, st *ClusterState, id string) (*tls.Certificate, string) {
	t.Helper()
	keyPEM, csrPEM, _ := zr.NewTLSKey()
	csr, kh, err := parseCSR(string(csrPEM))
	if err != nil {
		t.Fatal(err)
	}
	crt, err := issueDeviceCert(st, csr, id)
	if err != nil {
		t.Fatal(err)
	}
	c, err := tls.X509KeyPair([]byte(crt), keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return &c, kh
}
