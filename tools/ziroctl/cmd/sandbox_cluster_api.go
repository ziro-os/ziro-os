package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	sdkapi "github.com/ziro-os/ziro-os/sdk/api"
	"github.com/ziro-os/ziro-os/sdk/schema"
)

// The master's side of sandbox clustering (sandbox_cluster.go): /api/v1/sandboxes on a cluster
// master places, forwards and fans out to the nodes' mesh sandbox APIs.

// sandboxClusterView is what the master's forwarding needs from the cluster state.
type sandboxClusterView struct {
	token string
	nodes []ClusterNode
	st    *ClusterState
}

var (
	sandboxClusterState = func() (*sandboxClusterView, bool) {
		cfg, err := loadClusterConfig()
		if err != nil || cfg.Role != "master" {
			return nil, false
		}
		st, err := readState()
		if err != nil {
			return nil, false
		}
		return &sandboxClusterView{token: st.Secrets[sandboxSecret]["TOKEN"], nodes: st.Nodes, st: st}, true
	}
	sandboxClusterMutate = withState
	sandboxMeshAddr      = func(n *ClusterNode) string { return net.JoinHostPort(n.MeshIP, strconv.Itoa(sandboxMeshPort)) }
	sandboxRouteStore    = func() routeStore { return clusterRouteStore{} }
)

func (v *sandboxClusterView) node(id string) *ClusterNode {
	for i := range v.nodes {
		if v.nodes[i].ID == id {
			return &v.nodes[i]
		}
	}
	return nil
}

func (v *sandboxClusterView) sandboxNodes() []*ClusterNode {
	var out []*ClusterNode
	for i := range v.nodes {
		if n := &v.nodes[i]; hasCap(n, capSandbox) && n.MeshIP != "" {
			out = append(out, n)
		}
	}
	return out
}

// forwardTo proxies a request to a node's mesh sandbox API with the caller's identity.
func (v *sandboxClusterView) forwardTo(w http.ResponseWriter, r *http.Request, n *ClusterNode) {
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme, pr.Out.URL.Host, pr.Out.Host = "http", sandboxMeshAddr(n), "ziro-sandboxd"
			pr.Out.URL.Path = "/v1" + strings.TrimPrefix(pr.In.URL.Path, "/api/v1")
			pr.Out.Header.Set("Authorization", "Bearer "+v.token)
			pr.Out.Header.Set(hdrOwner, apiTokenName(pr.In))
			pr.Out.Header.Set(hdrRole, apiRole(pr.In))
			host := pr.In.Host
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}
			pr.Out.Header.Set(hdrHost, strings.Trim(host, "[]"))
		},
		FlushInterval: -1,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			apiError(w, http.StatusBadGateway, "node "+n.ID+" doesn't answer: "+err.Error())
		},
	}
	proxy.ServeHTTP(w, r)
}

// call sends one buffered request to a node (fan-out and create).
func (v *sandboxClusterView) call(r *http.Request, n *ClusterNode, method, path string, body []byte) (int, []byte, error) {
	req, err := http.NewRequestWithContext(r.Context(), method, "http://"+sandboxMeshAddr(n)+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+v.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(hdrOwner, apiTokenName(r))
	req.Header.Set(hdrRole, apiRole(r))
	req.Header.Set(hdrRequestID, r.Header.Get(hdrRequestID))
	resp, err := sandboxClusterHTTP.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	return resp.StatusCode, b, err
}

var sandboxClusterHTTP = &http.Client{Timeout: 11 * time.Minute} // a create may pull an image

// serveClusterSandboxes answers /api/v1/sandboxes* on a master. It returns false when this
// host isn't a cluster master (the caller serves the local daemon).
func serveClusterSandboxes(w http.ResponseWriter, r *http.Request) bool {
	v, ok := sandboxClusterState()
	if !ok {
		return false
	}
	if v.token == "" {
		apiError(w, http.StatusServiceUnavailable, "no node runs the sandbox module yet (ziroctl module enable sandbox on the nodes)")
		return true
	}
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/sandboxes"), "/")
	switch {
	case rest == "" && r.Method == http.MethodPost:
		v.create(w, r)
	case rest == "":
		v.fanout(w, r, "/v1/sandboxes")
	case rest == "snapshots":
		v.fanout(w, r, "/v1/sandboxes/snapshots")
	case rest == "templates":
		nodes := v.sandboxNodes()
		if len(nodes) == 0 {
			apiReply(w, nil, map[string]schema.SandboxSpec{})
			return true
		}
		v.forwardTo(w, r, nodes[0])
	default:
		v.forSandbox(w, r, strings.SplitN(rest, "/", 2))
	}
	return true
}

// create places a sandbox on a node, forwards the request and records where it runs.
func (v *sandboxClusterView) create(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		apiReply(w, err, nil)
		return
	}
	var spec schema.SandboxSpec
	if err := json.Unmarshal(body, &spec); err != nil {
		apiReply(w, err, nil)
		return
	}
	var only map[string]bool
	switch {
	case strings.HasPrefix(spec.Image, snapshotRepo): // a snapshot lives on the node it was taken on
		only = v.nodesWithSnapshot(r, spec.Image)
	case poolClaimable(spec): // a node with a warm sandbox of the template resumes one instead of starting one
		if warm := v.nodesWithWarm(r, spec.Template); len(warm) > 0 {
			only = warm
		}
	}
	n := pickSandboxNode(v.st, only)
	if n == nil {
		apiError(w, http.StatusServiceUnavailable, "no ready node can run the sandbox (sandbox module, not cordoned, runner)")
		return
	}
	code, out, err := v.call(r, n, http.MethodPost, "/v1/sandboxes", body)
	if err != nil {
		apiError(w, http.StatusBadGateway, "node "+n.ID+": "+err.Error())
		return
	}
	var sb sdkapi.Sandbox
	if code == http.StatusOK && json.Unmarshal(out, &sb) == nil && sb.ID != "" {
		err := sandboxClusterMutate(func(st *ClusterState) error {
			if st.Sandboxes == nil {
				st.Sandboxes = map[string]SandboxPlacement{}
			}
			st.Sandboxes[sb.ID] = SandboxPlacement{Node: n.ID, Owner: sb.Owner, Since: time.Now().UTC()}
			return nil
		})
		if err != nil {
			apiError(w, http.StatusInternalServerError, "sandbox "+sb.ID+" runs on "+n.ID+" but could not be recorded: "+err.Error())
			return
		}
	}
	w.WriteHeader(code)
	_, _ = w.Write(out)
}

// nodesWithWarm asks every sandbox node, in parallel and briefly, for its warm pools and returns
// the nodes with a paused sandbox of the template.
func (v *sandboxClusterView) nodesWithWarm(r *http.Request, template string) map[string]bool {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	rq := r.WithContext(ctx)
	var mu sync.Mutex
	var wg sync.WaitGroup
	warm := map[string]bool{}
	for _, n := range v.sandboxNodes() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			code, out, err := v.call(rq, n, http.MethodGet, "/v1/pools", nil)
			var pools map[string]int
			if err == nil && code == http.StatusOK && json.Unmarshal(out, &pools) == nil && pools[template] > 0 {
				mu.Lock()
				warm[n.ID] = true
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return warm
}

func (v *sandboxClusterView) nodesWithSnapshot(r *http.Request, image string) map[string]bool {
	only := map[string]bool{}
	for _, n := range v.sandboxNodes() {
		for _, s := range v.snapshotsOn(r, n) {
			if s == image {
				only[n.ID] = true
			}
		}
	}
	return only
}

// snapshotsOn lists the snapshot images a node holds that the caller may see.
func (v *sandboxClusterView) snapshotsOn(r *http.Request, n *ClusterNode) []string {
	code, out, err := v.call(r, n, http.MethodGet, "/v1/sandboxes/snapshots", nil)
	var list []sdkapi.SandboxSnapshot
	if err != nil || code != http.StatusOK || json.Unmarshal(out, &list) != nil {
		return nil
	}
	images := make([]string, 0, len(list))
	for _, s := range list {
		if snapshotImageRe.MatchString(s.Image) {
			images = append(images, s.Image)
		}
	}
	return images
}

// fanout sends a list (or snapshot delete) to every sandbox node and merges the answers. path is
// one of the fixed list paths; nothing of the request URL reaches a node's URL but a validated
// snapshot name.
func (v *sandboxClusterView) fanout(w http.ResponseWriter, r *http.Request, path string) {
	if r.Method == http.MethodDelete { // a snapshot: on every node that holds a copy
		want := r.URL.Query().Get("image")
		removed := 0
		for _, n := range v.sandboxNodes() {
			// The name sent to the node is the node's own (from its list, as the caller may
			// see it), never the request's text.
			for _, image := range v.snapshotsOn(r, n) {
				if image != want {
					continue
				}
				q := path + "?" + url.Values{"image": {image}}.Encode()
				if code, _, err := v.call(r, n, http.MethodDelete, q, nil); err == nil && code == http.StatusOK {
					removed++
				}
			}
		}
		if removed == 0 {
			apiReply(w, errNotFound("no such snapshot"), nil)
			return
		}
		// A copy still in flight to another node is removed by the next sync, not replicated.
		_ = sandboxClusterMutate(func(st *ClusterState) error {
			if st.SnapshotTombstones == nil {
				st.SnapshotTombstones = map[string]time.Time{}
			}
			st.SnapshotTombstones[want] = time.Now().UTC()
			return nil
		})
		apiReply(w, nil, APIMessage{Status: "ok", Message: fmt.Sprintf("snapshot removed from %d node(s)", removed)})
		return
	}
	merged := []json.RawMessage{}
	for _, n := range v.sandboxNodes() {
		code, out, err := v.call(r, n, http.MethodGet, path, nil)
		var items []json.RawMessage
		if err == nil && code == http.StatusOK && json.Unmarshal(out, &items) == nil {
			merged = append(merged, items...)
		}
	}
	if path == "/v1/sandboxes/snapshots" {
		apiReply(w, nil, mergeSnapshots(merged))
		return
	}
	if path != "/v1/sandboxes" {
		apiReply(w, nil, merged)
		return
	}
	// The filters apply here, to the merged list: request text never goes into a node's URL.
	var list []sdkapi.Sandbox
	for _, raw := range merged {
		var sb sdkapi.Sandbox
		if json.Unmarshal(raw, &sb) == nil {
			list = append(list, sb)
		}
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Created.Before(list[j].Created) })
	list, err := filterSandboxes(list, r.URL.Query())
	apiReply(w, err, list)
}

// mergeSnapshots lists each snapshot once, with the number of nodes that hold a copy.
func mergeSnapshots(raw []json.RawMessage) []sdkapi.SandboxSnapshot {
	by := map[string]*sdkapi.SandboxSnapshot{}
	for _, r := range raw {
		var s sdkapi.SandboxSnapshot
		if json.Unmarshal(r, &s) != nil || s.Image == "" {
			continue
		}
		if have, ok := by[s.Image]; ok {
			have.Nodes++
			continue
		}
		s.Nodes = 1
		by[s.Image] = &s
	}
	out := make([]sdkapi.SandboxSnapshot, 0, len(by))
	for _, s := range by {
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Image < out[j].Image })
	return out
}

// forSandbox forwards a request about one sandbox to its node, and keeps the cluster's records
// (directory entry, preview routes) in step with what the node did.
func (v *sandboxClusterView) forSandbox(w http.ResponseWriter, r *http.Request, parts []string) {
	// The id used from here on is the directory's own key, never the request's text.
	id, p, ok := "", SandboxPlacement{}, false
	if sandboxIDRe.MatchString(parts[0]) {
		for k, pl := range v.st.Sandboxes {
			if k == parts[0] {
				id, p, ok = k, pl, true
			}
		}
	}
	var n *ClusterNode
	if ok {
		n = v.node(p.Node)
	}
	if !ok || n == nil || (!(apiRoleRank[apiRole(r)] >= apiRoleRank["operator"]) && p.Owner != apiTokenName(r)) {
		apiReply(w, errNotFound("no such sandbox"), nil)
		return
	}
	sub := ""
	if len(parts) == 2 {
		sub = parts[1]
	}
	switch {
	case sub == "" && r.Method == http.MethodDelete:
		rec := &statusCapture{ResponseWriter: w}
		v.forwardTo(rec, r, n)
		if rec.status == http.StatusOK || rec.status == http.StatusNotFound {
			_ = sandboxClusterMutate(func(st *ClusterState) error {
				delete(st.Sandboxes, id)
				dropClusterPreviewRoutes(st, id)
				return nil
			})
		}
	case sub == "previews" && r.Method == http.MethodPost:
		body, _ := io.ReadAll(http.MaxBytesReader(w, r.Body, 4<<10))
		code, out, err := v.call(r, n, http.MethodPost, "/v1/sandboxes/"+id+"/previews", body)
		if err != nil {
			apiError(w, http.StatusBadGateway, err.Error())
			return
		}
		var pv sdkapi.SandboxPreview
		if code == http.StatusOK && json.Unmarshal(out, &pv) == nil {
			if err := v.putPreviewRoute(id, n, pv); err != nil {
				apiError(w, http.StatusBadGateway, "gateway route: "+err.Error())
				return
			}
		}
		w.WriteHeader(code)
		_, _ = w.Write(out)
	case strings.HasPrefix(sub, "previews/") && r.Method == http.MethodDelete:
		rec := &statusCapture{ResponseWriter: w}
		v.forwardTo(rec, r, n)
		if rec.status == http.StatusOK {
			port, _ := strconv.Atoi(strings.TrimPrefix(sub, "previews/"))
			_ = deleteRoute(sandboxRouteStore(), previewRoute(id, port))
		}
	default:
		v.forwardTo(w, r, n)
	}
}

// putPreviewRoute publishes a node's preview on the cluster's gateways.
func (v *sandboxClusterView) putPreviewRoute(id string, n *ClusterNode, pv sdkapi.SandboxPreview) error {
	u, err := url.Parse(pv.URL)
	if err != nil || u.Hostname() == "" {
		return errors.New("the node returned no preview URL")
	}
	cfg, err := loadSandboxConfig()
	if err != nil {
		return err
	}
	r := GatewayRoute{Name: previewRoute(id, pv.Port), Hosts: []string{u.Hostname()}, TLS: v.st.GatewayDomain.TLS(),
		To: []GatewayUpstream{{Address: net.JoinHostPort(n.MeshIP, strconv.Itoa(cfg.PreviewPort))}}, MaxBodyMB: 100, Timeout: "5m"}
	_, err = putRoute(sandboxRouteStore(), r)
	return err
}

// statusCapture records the status of a forwarded answer.
type statusCapture struct {
	http.ResponseWriter
	status int
}

func (s *statusCapture) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusCapture) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

func (s *statusCapture) Unwrap() http.ResponseWriter { return s.ResponseWriter }
