package cmd

import (
	"context"
	"encoding/json"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"time"

	zr "github.com/ziro-os/ziro-os/sdk/router"
)

// The planet mesh: every planet (master) streams the soft state of the devices connected to it
// (endpoints, relays, online) to every other planet, over master mutual TLS, so each planet's
// hub shows every device's current paths. A device that moves to another planet starts a newer
// session (MapRequest.Epoch), and the newest session wins everywhere. Soft state never admits
// anyone: membership comes only from Raft, and entries for unknown members are dropped.

const (
	planetSoftPath = "/router/v1/planets/soft"
	meshBuffer     = 1024             // queued messages per planet stream; overflow: it resyncs
	planetGrace    = 90 * time.Second // a planet unreachable this long: its devices count as offline
	planetPoll     = 15 * time.Second // how often the master list is re-read
)

type meshSub struct {
	ch   chan []byte
	done chan struct{}
}

type softEntry struct {
	ID string `json:"id"`
	routerSoft
}

type meshMessage struct {
	Type    string      `json:"type"` // full, delta, keepalive
	Entries []softEntry `json:"entries,omitempty"`
}

// routerStats is what /api/v1/metrics reports about this planet's router.
type routerStats struct {
	Streams int             `json:"streams"` // devices streaming from this planet
	Online  int             `json:"online"`  // devices online anywhere
	Devices int             `json:"devices"` // authorized devices
	Peers   map[string]bool `json:"peers"`   // other planets: stream up
}

func (h *routerHub) stats() routerStats {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := routerStats{Streams: len(h.subs), Peers: map[string]bool{}}
	for id, m := range h.members {
		if m.Authorized {
			out.Devices++
			if h.onlineLocked(id) {
				out.Online++
			}
		}
	}
	for id, up := range h.peersUp {
		out.Peers[id] = up
	}
	return out
}

func (h *routerHub) setPeerUp(id string, up bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.peersUp == nil {
		h.peersUp = map[string]bool{}
	}
	h.peersUp[id] = up
}

func (h *routerHub) forgetPeer(id string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.peersUp, id)
}

// ownLocked is this planet's entry for device id, if it holds the device's newest session.
func (h *routerHub) ownLocked(id string) (softEntry, bool) {
	s := h.soft[id]
	if s == nil || s.Planet != h.self {
		return softEntry{}, false
	}
	e := softEntry{ID: id, routerSoft: *s}
	_, e.Online = h.subs[id]
	return e, true
}

// announceLocked sends this planet's entry for id to the other planets.
func (h *routerHub) announceLocked(id string) {
	if len(h.mesh) == 0 {
		return
	}
	e, ok := h.ownLocked(id)
	if !ok {
		return
	}
	b, _ := json.Marshal(meshMessage{Type: "delta", Entries: []softEntry{e}})
	for m := range h.mesh {
		select {
		case m.ch <- b:
		default: // too slow: it reconnects and gets a full snapshot
			h.dropMeshLocked(m)
		}
	}
}

func (h *routerHub) dropMeshLocked(m *meshSub) {
	if _, ok := h.mesh[m]; ok {
		delete(h.mesh, m)
		close(m.done)
	}
}

// meshSubscribe opens another planet's stream with a snapshot of this planet's devices queued.
func (h *routerHub) meshSubscribe() (*meshSub, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.loaded {
		return nil, errRouterLoading
	}
	full := meshMessage{Type: "full", Entries: []softEntry{}}
	for id := range h.soft {
		if e, ok := h.ownLocked(id); ok {
			full.Entries = append(full.Entries, e)
		}
	}
	b, _ := json.Marshal(full)
	m := &meshSub{ch: make(chan []byte, meshBuffer), done: make(chan struct{})}
	m.ch <- b
	h.mesh[m] = struct{}{}
	return m, nil
}

func (h *routerHub) meshUnsubscribe(m *meshSub) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.dropMeshLocked(m)
}

// mergeRemote applies what planet reported. A full snapshot also ends, as offline, every session
// of that planet it no longer lists (devices that left while the stream was down).
func (h *routerHub) mergeRemote(planet string, full bool, entries []softEntry) {
	h.mu.Lock()
	defer h.mu.Unlock()
	listed := make(map[string]bool, len(entries))
	for _, e := range entries {
		m := h.members[e.ID]
		if planet == h.self || m == nil || !m.Authorized {
			continue
		}
		listed[e.ID] = true
		cur := h.soft[e.ID]
		if cur != nil && (e.Epoch < cur.Epoch || (e.Epoch == cur.Epoch && cur.Planet != planet)) {
			continue // an older session, or the same one already held elsewhere
		}
		v := e.routerSoft
		v.Planet = planet
		if len(v.Endpoints) > zr.MaxEndpoints {
			v.Endpoints = v.Endpoints[:zr.MaxEndpoints]
		}
		if len(v.Relays) > zr.MaxRelays {
			v.Relays = v.Relays[:zr.MaxRelays]
		}
		h.soft[e.ID] = &v
		h.peerChangedLocked(e.ID, nil)
	}
	if full {
		h.offlineLocked(planet, listed)
	}
}

// planetDown marks every session held by planet offline (it has been unreachable for a while).
func (h *routerHub) planetDown(planet string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.offlineLocked(planet, nil)
}

func (h *routerHub) offlineLocked(planet string, keep map[string]bool) {
	for id, s := range h.soft {
		if s.Planet == planet && s.Online && !keep[id] {
			s.Online = false
			h.peerChangedLocked(id, nil)
		}
	}
}

// servePlanetSoft streams this planet's soft state to another planet (master certificate only).
func (rt *routerServer) servePlanetSoft(w http.ResponseWriter, r *http.Request, who routerIdent) {
	if who.forwarded || !requestFromMaster(r.TLS, rt.caPEM) {
		rt.fail(w, who, r.URL.Path, httpError{http.StatusForbidden, "planets only"})
		return
	}
	m, err := rt.hub.meshSubscribe()
	if err != nil {
		rt.fail(w, who, r.URL.Path, err)
		return
	}
	defer rt.hub.meshUnsubscribe(m)
	streamLines(w, r, m.ch, m.done)
}

// runPlanetMesh keeps one stream open to every other master, following the replicated node list.
func runPlanetMesh(ctx context.Context, hub *routerHub, rs *raftStore, cfg *ClusterConfig, caPEM string) {
	tc, err := masterClientTLS(caPEM)
	if err != nil {
		return
	}
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: tc, ForceAttemptHTTP2: true, IdleConnTimeout: 90 * time.Second}}
	type peer struct {
		addr string
		stop context.CancelFunc
	}
	peers := map[string]peer{}
	var seen uint64
	t := time.NewTicker(planetPoll)
	defer t.Stop()
	for {
		if v := rs.stateVersion(); v != seen {
			if st, _, err := rs.snapshot(); err == nil {
				seen = v
				want := map[string]string{}
				for _, n := range st.Nodes {
					if n.Role == "master" && n.IP != "" && n.ID != rs.id {
						want[n.ID] = net.JoinHostPort(n.IP, clusterPortOf(cfg))
					}
				}
				for id, p := range peers {
					if want[id] != p.addr {
						p.stop()
						delete(peers, id)
						hub.planetDown(id)
						hub.forgetPeer(id)
					}
				}
				for id, addr := range want {
					if _, ok := peers[id]; !ok {
						pctx, stop := context.WithCancel(ctx)
						peers[id] = peer{addr, stop}
						go planetPeer(pctx, hc, hub, id, addr)
					}
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// planetPeer follows one planet's stream, reconnecting with backoff.
func planetPeer(ctx context.Context, hc *http.Client, hub *routerHub, id, addr string) {
	backoff, lastOK := time.Second, time.Now()
	for ctx.Err() == nil {
		hub.setPeerUp(id, false)
		if planetStream(ctx, hc, hub, id, addr) {
			backoff, lastOK = time.Second, time.Now()
		}
		if time.Since(lastOK) > planetGrace {
			hub.planetDown(id)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff + rand.N(backoff)):
		}
		backoff = min(backoff*2, 30*time.Second)
	}
}

// planetStream reads one connection's messages; it reports whether a snapshot arrived.
func planetStream(ctx context.Context, hc *http.Client, hub *routerHub, id, addr string) bool {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	idle := time.AfterFunc(zr.KeepaliveTimeout, cancel)
	defer idle.Stop()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+addr+planetSoftPath, http.NoBody)
	if err != nil {
		return false
	}
	resp, err := hc.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return false
	}
	dec := json.NewDecoder(resp.Body)
	synced := false
	for {
		var m meshMessage
		if err := dec.Decode(&m); err != nil {
			return synced
		}
		idle.Reset(zr.KeepaliveTimeout)
		switch m.Type {
		case "full":
			synced = true
			hub.setPeerUp(id, true)
			hub.mergeRemote(id, true, m.Entries)
		case "delta":
			hub.mergeRemote(id, false, m.Entries)
		}
	}
}
