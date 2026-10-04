package cmd

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	zr "github.com/ziro-os/ziro-os/sdk/router"
)

// Soft state merges by device session: the newest session wins, whichever planet holds it.
func TestPlanetSoftMerge(t *testing.T) {
	st := &zr.State{Networks: []zr.Network{{ID: "n1", Name: "office", IPv4: "100.64.0.0/16",
		ACL: zr.ACL{Rules: []zr.Rule{{Src: []string{"*"}, Dst: []string{"*:*"}}}}}}}
	for i, id := range []string{"d1", "d2"} {
		st.Members = append(st.Members, zr.Member{ID: id, Name: id, Network: "n1", IPv4: "100.64.0." + string(rune('1'+i)),
			Authorized: true, KeyHash: "h" + id})
	}
	a, b := newRouterHub(), newRouterHub()
	a.self, b.self = "pa", "pb"
	a.setState(st, 1)
	b.setState(st, 1)
	feed := func(from *routerHub, name string, to *routerHub) *meshSub {
		m, err := from.meshSubscribe()
		if err != nil {
			t.Fatal(err)
		}
		pump := func() {
			for {
				select {
				case raw := <-m.ch:
					var msg meshMessage
					_ = json.Unmarshal(raw, &msg)
					to.mergeRemote(name, msg.Type == "full", msg.Entries)
				default:
					return
				}
			}
		}
		pump()
		t.Cleanup(func() { from.meshUnsubscribe(m) })
		return &meshSub{ch: m.ch, done: m.done}
	}
	ab, ba := feed(a, "pa", b), feed(b, "pb", a)
	pump := func() { // deliver what both planets queued, until quiet
		for range 3 {
			for _, p := range []struct {
				m    *meshSub
				name string
				to   *routerHub
			}{{ab, "pa", b}, {ba, "pb", a}} {
				for done := false; !done; {
					select {
					case raw := <-p.m.ch:
						var msg meshMessage
						_ = json.Unmarshal(raw, &msg)
						p.to.mergeRemote(p.name, msg.Type == "full", msg.Entries)
					default:
						done = true
					}
				}
			}
		}
	}
	peerOf := func(h *routerHub, id string) zr.Peer {
		h.mu.Lock()
		defer h.mu.Unlock()
		return h.peers[id].p
	}

	// d1 connects to planet A: B shows it online with its endpoints.
	a.updateSoft("d1", zr.MapRequest{Endpoints: []string{"192.0.2.1:41641"}, Epoch: 100})
	s1, _ := a.subscribe("d1")
	pump()
	if p := peerOf(b, "d1"); !p.Online || len(p.Endpoints) != 1 || p.Endpoints[0] != "192.0.2.1:41641" {
		t.Fatalf("planet B's view of d1 on A: %+v", p)
	}

	// d1 moves to planet B (newer session): A's stale report can't move it back.
	b.updateSoft("d1", zr.MapRequest{Endpoints: []string{"198.51.100.7:41641"}, Epoch: 200})
	s2, _ := b.subscribe("d1")
	pump()
	a.unsubscribe(s1) // the old stream on A dies late
	a.updateSoft("d1", zr.MapRequest{Endpoints: []string{"192.0.2.1:41641"}, Epoch: 100})
	pump()
	for name, h := range map[string]*routerHub{"A": a, "B": b} {
		if p := peerOf(h, "d1"); !p.Online || p.Endpoints[0] != "198.51.100.7:41641" {
			t.Fatalf("planet %s after the move: %+v", name, p)
		}
	}

	// d1 leaves B: offline everywhere.
	b.unsubscribe(s2)
	pump()
	if p := peerOf(a, "d1"); p.Online {
		t.Fatalf("A still shows d1 online after it left B: %+v", p)
	}

	// Entries for unknown members are dropped; a planet going down takes its devices offline.
	b.mergeRemote("pc", false, []softEntry{{ID: "intruder", routerSoft: routerSoft{Online: true, Epoch: 1}},
		{ID: "d2", routerSoft: routerSoft{Online: true, Epoch: 5}}})
	b.mu.Lock()
	_, bad := b.soft["intruder"]
	b.mu.Unlock()
	if bad || !peerOf(b, "d2").Online {
		t.Fatal("unknown member stored, or d2 on planet C not online")
	}
	b.planetDown("pc")
	if peerOf(b, "d2").Online {
		t.Fatal("d2 still online after its planet went down")
	}
	b.mergeRemote("pc", false, []softEntry{{ID: "d2", routerSoft: routerSoft{Online: true, Epoch: 6}}})
	b.mergeRemote("pc", true, nil) // a snapshot without d2: it left while the stream was down
	if peerOf(b, "d2").Online {
		t.Fatal("d2 online although planet C's snapshot no longer lists it")
	}
}

// Two planets: the follower serves netmaps itself and relays only writes to the leader; a
// device on one planet sees a device on the other through the planet mesh.
func TestPlanetsEndToEnd(t *testing.T) {
	clusterDir = t.TempDir()
	st, n := routerTestState(t, zr.ACL{Rules: []zr.Rule{{Src: []string{"*"}, Dst: []string{"*:*"}}}})
	if err := ensureMasterCert(st, "m1", []net.IP{net.ParseIP("127.0.0.1")}); err != nil {
		t.Fatal(err)
	}
	key := addJoinKey(st, true, time.Now().Add(time.Hour))
	if err := saveStateFiles(clusterDir, st); err != nil {
		t.Fatal(err)
	}
	pool, _ := caPool(st.CACert)
	var ver atomic.Uint64
	start := func(self string, leader bool) (*routerServer, string) {
		hub := newRouterHub()
		hub.self = self
		rt := newRouterServer(hub, st.CACert)
		rt.isLeader = func() bool { return leader }
		rt.sync = func() {
			if cur, err := readState(); err == nil {
				R := routerOf(cur)
				R.Endpoints = []string{"planet-a.example.com:7443", "planet-b.example.com:7443"} // as routerSnapshot fills it
				hub.setState(R, ver.Add(1))
			}
		}
		rt.sync()
		srv := httptest.NewUnstartedServer(rt)
		srv.EnableHTTP2 = true
		srv.TLS = &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: pool,
			GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return loadMasterTLS() }}
		srv.StartTLS()
		t.Cleanup(srv.Close)
		return rt, strings.TrimPrefix(srv.URL, "https://")
	}
	A, addrA := start("pa", true)
	B, addrB := start("pb", false)
	B.leaderURL = func() (string, error) { return addrA, nil }
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var paused atomic.Bool
	go func() { // followers reload from their replica (production: every 250ms)
		for ctx.Err() == nil {
			if !paused.Load() {
				B.sync()
			}
			time.Sleep(50 * time.Millisecond)
		}
	}()
	tc, _ := masterClientTLS(st.CACert)
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: tc, ForceAttemptHTTP2: true}}
	go planetPeer(ctx, hc, A.hub, "pb", addrB)
	go planetPeer(ctx, hc, B.hub, "pa", addrA)

	pin, _ := pemHash(st.CACert)
	ca, err := zr.PinCA(ctx, addrB, pin)
	if err != nil {
		t.Fatal(err)
	}
	join := func(name string, nb byte, ep string, mapEP ...string) *zr.Client {
		req, keyPEM := testDevice(t, name, nb)
		req.Key = key
		c := zr.NewClient([]string{ep}, ca, nil)
		out, err := c.Register(ctx, req) // on B: relayed to the leader
		if err != nil {
			t.Fatalf("register %s via %s: %v", name, ep, err)
		}
		cert, _ := tls.X509KeyPair([]byte(out.Cert), keyPEM)
		if len(mapEP) > 0 {
			c = zr.NewClient(mapEP, ca, nil)
		}
		c.SetCert(&cert)
		return c
	}
	onB, onA := join("laptop", 1, addrB), join("server", 2, addrA)
	_ = n
	for { // B's replica catches up (until then B relays the laptop's requests to the leader)
		B.hub.mu.Lock()
		k := len(B.hub.members)
		B.hub.mu.Unlock()
		if k == 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	msgs := make(chan zr.MapMessage, 64)
	go func() {
		_ = onA.Map(ctx, zr.MapRequest{Endpoints: []string{"192.0.2.2:41641"}, Epoch: 1}, func(m zr.MapMessage) error {
			msgs <- m
			return nil
		})
	}()
	go func() {
		_ = onB.Map(ctx, zr.MapRequest{Endpoints: []string{"192.0.2.1:41641"}, Epoch: 1}, func(zr.MapMessage) error { return nil })
	}()
	want := func(what string, ok func(zr.Peer) bool) {
		t.Helper()
		for {
			select {
			case m := <-msgs:
				if m.Type == "full" && len(m.Planets) == 0 {
					t.Fatalf("full map without the planet list: %+v", m)
				}
				for _, p := range m.Peers {
					if p.Name == "laptop" && ok(p) {
						return
					}
				}
			case <-ctx.Done():
				t.Fatalf("timed out waiting for: %s", what)
			}
		}
	}
	want("laptop (streaming from planet B) online with its endpoint", func(p zr.Peer) bool {
		return p.Online && len(p.Endpoints) == 1 && p.Endpoints[0] == "192.0.2.1:41641"
	})
	// Endpoint updates go to B and reach the device on A through the mesh.
	if err := onB.UpdateEndpoints(ctx, zr.MapRequest{Endpoints: []string{"198.51.100.9:41641"}, Epoch: 1}); err != nil {
		t.Fatal(err)
	}
	want("laptop's new endpoint", func(p zr.Peer) bool { return len(p.Endpoints) == 1 && p.Endpoints[0] == "198.51.100.9:41641" })
	// The leader never held the laptop's stream: B served it.
	if onB.Current() != addrB {
		t.Fatalf("laptop talks to %s, want planet B %s", onB.Current(), addrB)
	}
	A.hub.mu.Lock()
	nA := len(A.hub.subs)
	A.hub.mu.Unlock()
	if nA != 1 {
		t.Fatalf("leader holds %d streams; the follower's device must stream from the follower", nA)
	}
	B.hub.mu.Lock()
	nB := len(B.hub.subs)
	B.hub.mu.Unlock()
	if nB != 1 {
		t.Fatalf("follower holds %d streams, want 1", nB)
	}

	// Nearest planet: a dead endpoint sorts last; a live one becomes the first choice.
	probe := zr.NewClient([]string{"127.0.0.1:1", addrB}, ca, nil)
	if rtts := probe.Nearest(ctx); len(rtts) != 2 || rtts[0].Addr != addrB || rtts[0].RTT == 0 || rtts[1].RTT != 0 || probe.Current() != addrB {
		t.Fatalf("nearest: %+v (current %s)", rtts, probe.Current())
	}

	// A device admitted a moment ago, before B's replica has it: B relays to the leader instead
	// of answering "unauthorized" (which zirocd would take for a revocation).
	paused.Store(true)
	late := join("late", 3, addrA, addrB)
	got := make(chan zr.MapMessage, 1)
	go func() {
		err := late.Map(ctx, zr.MapRequest{Epoch: 1}, func(m zr.MapMessage) error {
			select {
			case got <- m:
			default:
			}
			return nil
		})
		if ctx.Err() == nil {
			t.Errorf("late device's stream: %v", err)
		}
	}()
	select {
	case m := <-got:
		if m.Type != "full" {
			t.Fatalf("late device: %+v", m)
		}
	case <-ctx.Done():
		t.Fatal("late device got no map through the lagging planet")
	}
	paused.Store(false)
}

// Every planet loads router state from its own Raft replica, with the endpoints devices dial.
func TestRouterSnapshotOnFollowers(t *testing.T) {
	imported := &ClusterState{NodeTokens: map[string]string{}, History: map[string][]ClusteredApp{},
		Secrets: map[string]map[string]string{},
		Nodes: []ClusterNode{{ID: "m0", Role: "master", IP: "10.0.0.1"}, {ID: "m1", Role: "master", IP: "10.0.0.2"},
			{ID: "m2", Role: "master", IP: "10.0.0.3"}}}
	routerOf(imported).Networks = []zr.Network{{ID: "n1", Name: "office", IPv4: "100.64.0.0/16"}}
	ms := newTestGroup(t, 3, imported)
	cfg := &ClusterConfig{MasterAddr: "10.0.0.1:7443"}
	for _, m := range ms {
		waitFor(t, m.rs.id+" router state", func() bool {
			R, v := m.rs.routerSnapshot(cfg)
			return R != nil && v == m.rs.stateVersion() && len(R.Networks) == 1 && len(R.Endpoints) == 3
		})
	}
	if err := ms[0].rs.mutate(func(st *ClusterState) error {
		routerOf(st).Networks = append(routerOf(st).Networks, zr.Network{ID: "n2", Name: "lab", IPv4: "100.65.0.0/16"})
		routerOf(st).Endpoints = []string{"router.example.com:7443"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, m := range ms[1:] {
		waitFor(t, m.rs.id+" follows the change", func() bool {
			R, _ := m.rs.routerSnapshot(cfg)
			return R != nil && len(R.Networks) == 2 && len(R.Endpoints) == 1 && R.Endpoints[0] == "router.example.com:7443"
		})
	}
}
