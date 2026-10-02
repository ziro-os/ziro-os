package cmd

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	sdkapi "github.com/ziro-os/ziro-os/sdk/api"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// API routes for containers, the firewall, the cluster and host operations (backups, upgrades,
// audit, tokens, events). Each calls the same operation as the CLI command of the same name.
//
// Deliberately CLI-only (documented in docs/sdk.md): interactive or key-handling commands —
// container run/exec, wireguard peer add (prints a private key), catalog signing, dev, install,
// nfs mount, apps credentials.

var (
	containerRefRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
	imageRefRe     = regexp.MustCompile(`^[a-z0-9][a-z0-9._/:@-]{0,254}$`)
)

// ---- containers ----

func listContainers() ([]map[string]any, error) {
	out, err := runNerdctl("ps", "-a", "--format", "{{json .}}")
	if err != nil {
		return nil, err
	}
	list := []map[string]any{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		var c map[string]any
		if json.Unmarshal([]byte(line), &c) == nil {
			list = append(list, c)
		}
	}
	return list, nil
}

// managedContainerName reports a container an app or the cluster owns (and recreates).
func managedContainerName(ref string) bool { return strings.HasPrefix(ref, "ziro-") }

func registerContainerRoutes(a *apiRouter) {
	a.get("/api/v1/containers", "viewer", func(w http.ResponseWriter, r *http.Request) {
		list, err := listContainers()
		apiReply(w, err, list)
	})
	a.get("/api/v1/containers/{id}", "viewer", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if !containerRefRe.MatchString(id) {
			apiReply(w, errNotFound("no container "+id), nil)
			return
		}
		out, err := runNerdctl("inspect", "--mode=native", id)
		if err != nil {
			apiReply(w, errNotFound("no container "+id), nil)
			return
		}
		var v []any
		if err := json.Unmarshal(out, &v); err != nil || len(v) == 0 {
			apiReply(w, errNotFound("no container "+id), nil)
			return
		}
		apiReply(w, nil, v[0])
	})
	// Logs may hold anything the app prints: operator.
	a.get("/api/v1/containers/{id}/logs", "operator", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if !containerRefRe.MatchString(id) {
			apiReply(w, errNotFound("no container "+id), nil)
			return
		}
		out, err := exec.Command("nerdctl", "logs", "--tail", strconv.Itoa(queryInt(r, "lines", 100, 5000)), id).CombinedOutput()
		if err != nil {
			apiReply(w, fmt.Errorf("%s", strings.TrimSpace(string(out))), nil)
			return
		}
		apiReply(w, nil, map[string]any{"container": id, "lines": strings.Split(strings.TrimRight(string(out), "\n"), "\n")})
	})
	a.post("/api/v1/containers/{id}/{action}", "operator", func(w http.ResponseWriter, r *http.Request) {
		id, action := r.PathValue("id"), r.PathValue("action")
		if !containerRefRe.MatchString(id) || (action != "start" && action != "stop" && action != "restart") {
			apiReply(w, errNotFound("unknown container or action"), nil)
			return
		}
		out, err := runNerdctl(action, id)
		if err != nil {
			err = fmt.Errorf("%s %s: %s", action, id, strings.TrimSpace(string(out)))
		}
		apiReply(w, err, APIMessage{Status: "ok", Message: "container " + id + ": " + action + " done"})
	})
	a.delete("/api/v1/containers/{id}", "operator", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if !containerRefRe.MatchString(id) {
			apiReply(w, errNotFound("no container "+id), nil)
			return
		}
		if managedContainerName(id) {
			apiError(w, http.StatusConflict, id+" belongs to an app or the cluster: remove the app instead")
			return
		}
		_, err := runNerdctl("rm", id) // refuses a running container
		apiReply(w, err, APIMessage{Status: "ok", Message: "container " + id + " removed"})
	})
	a.get("/api/v1/images", "viewer", func(w http.ResponseWriter, r *http.Request) {
		out, err := runNerdctl("images", "--format", "{{json .}}")
		list := []map[string]any{}
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			var m map[string]any
			if json.Unmarshal([]byte(line), &m) == nil {
				list = append(list, m)
			}
		}
		apiReply(w, err, list)
	})
	a.post("/api/v1/images/pull", "operator", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Image string `json:"image"`
		}
		if !decodeBody(w, r, &req) {
			return
		}
		if !imageRefRe.MatchString(req.Image) || strings.Contains(req.Image, "..") {
			apiReply(w, fmt.Errorf("invalid image reference %q", req.Image), nil)
			return
		}
		if err := startJob([]string{"container", "pull", "--", req.Image}, "/var/log/ziro-images.log"); err != nil {
			apiReply(w, err, nil)
			return
		}
		apiAccepted(w, "pulling "+req.Image+"; GET /api/v1/images shows it when done")
	})
}

// ---- firewall and WireGuard ----

// WireGuardPeer and WireGuardIface are `wg show all dump`, without key material beyond public keys.
type WireGuardPeer struct {
	PublicKey     string `json:"public_key"`
	Endpoint      string `json:"endpoint,omitempty"`
	AllowedIPs    string `json:"allowed_ips"`
	LastHandshake int64  `json:"last_handshake"` // unix seconds, 0 = never
	RxBytes       int64  `json:"rx_bytes"`
	TxBytes       int64  `json:"tx_bytes"`
}

type WireGuardIface struct {
	Name       string          `json:"name"`
	PublicKey  string          `json:"public_key"`
	ListenPort int             `json:"listen_port"`
	Peers      []WireGuardPeer `json:"peers"`
}

func parseWGDump(dump string) []WireGuardIface {
	var out []WireGuardIface
	idx := map[string]int{}
	for _, line := range strings.Split(strings.TrimSpace(dump), "\n") {
		f := strings.Split(line, "\t")
		switch len(f) {
		case 5: // interface: name, private-key (dropped), public-key, port, fwmark
			port, _ := strconv.Atoi(f[3])
			idx[f[0]] = len(out)
			out = append(out, WireGuardIface{Name: f[0], PublicKey: f[2], ListenPort: port, Peers: []WireGuardPeer{}})
		case 9: // peer: iface, public-key, preshared-key (dropped), endpoint, allowed-ips, handshake, rx, tx, keepalive
			i, ok := idx[f[0]]
			if !ok {
				continue
			}
			hs, _ := strconv.ParseInt(f[5], 10, 64)
			rx, _ := strconv.ParseInt(f[6], 10, 64)
			tx, _ := strconv.ParseInt(f[7], 10, 64)
			ep := f[3]
			if ep == "(none)" {
				ep = ""
			}
			out[i].Peers = append(out[i].Peers, WireGuardPeer{PublicKey: f[1], Endpoint: ep, AllowedIPs: f[4], LastHandshake: hs, RxBytes: rx, TxBytes: tx})
		}
	}
	return out
}

func wireguardStatus() map[string]any {
	out, _ := exec.Command("wg", "show", "all", "dump").Output()
	ifaces := parseWGDump(string(out))
	if ifaces == nil {
		ifaces = []WireGuardIface{}
	}
	return map[string]any{"active": len(ifaces) > 0, "interfaces": ifaces}
}

// sanitizeComment bounds a rule comment to one printable line.
func sanitizeComment(s string) string { return sanitizeLabel(s, 128) }

func registerFirewallRoutes(a *apiRouter) {
	a.get("/api/v1/firewall", "viewer", func(w http.ResponseWriter, r *http.Request) {
		apiReply(w, nil, loadFirewallConfig())
	})
	type portReq struct {
		Port    string `json:"port"` // 8443, 80/tcp, 51820/udp
		Comment string `json:"comment,omitempty"`
	}
	type targetReq struct {
		Target  string `json:"target"` // IP or CIDR
		Comment string `json:"comment,omitempty"`
	}
	ok := func(msg string) APIMessage { return APIMessage{Status: "ok", Message: msg} }
	a.post("/api/v1/firewall/allow", "admin", func(w http.ResponseWriter, r *http.Request) {
		var req portReq
		if decodeBody(w, r, &req) {
			_, err := firewallAllow(req.Port, sanitizeComment(req.Comment))
			apiReply(w, err, ok("allowed "+req.Port))
		}
	})
	a.post("/api/v1/firewall/deny", "admin", func(w http.ResponseWriter, r *http.Request) {
		var req portReq
		if decodeBody(w, r, &req) {
			apiReply(w, firewallDeny(req.Port), ok("removed "+req.Port))
		}
	})
	a.post("/api/v1/firewall/block", "admin", func(w http.ResponseWriter, r *http.Request) {
		var req targetReq
		if decodeBody(w, r, &req) {
			ip, err := firewallBlock(req.Target, sanitizeComment(req.Comment))
			apiReply(w, err, ok("blocked "+ip))
		}
	})
	a.post("/api/v1/firewall/unblock", "admin", func(w http.ResponseWriter, r *http.Request) {
		var req targetReq
		if decodeBody(w, r, &req) {
			ip, err := firewallUnblock(req.Target)
			apiReply(w, err, ok("unblocked "+ip))
		}
	})
	for _, on := range []bool{true, false} {
		action := map[bool]string{true: "enable", false: "disable"}[on]
		a.post("/api/v1/firewall/"+action, "admin", func(w http.ResponseWriter, r *http.Request) {
			apiReply(w, setFirewallEnabled(on), ok("firewall "+action+"d"))
		})
	}
}

// ---- cluster (on a master) ----

func registerClusterRoutes(a *apiRouter) {
	done := func(msg string) APIMessage { return APIMessage{Status: "ok", Message: msg} }
	a.post("/api/v1/cluster/apps", "admin", func(w http.ResponseWriter, r *http.Request) {
		var app ClusteredApp
		if err := decodeStrict(w, r, &app, 256<<10); err != nil {
			apiReply(w, err, nil)
			return
		}
		apiReply(w, clusterApply(app), done("app "+app.Name+" scheduled; replicas roll over one at a time"))
	})
	a.post("/api/v1/cluster/apps/{name}/scale", "operator", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Replicas *int `json:"replicas"`
		}
		if !decodeBody(w, r, &req) {
			return
		}
		if req.Replicas == nil {
			apiReply(w, fmt.Errorf("replicas is required"), nil)
			return
		}
		apiReply(w, clusterScale(r.PathValue("name"), *req.Replicas), done("scaled"))
	})
	a.post("/api/v1/cluster/apps/{name}/rollback", "operator", func(w http.ResponseWriter, r *http.Request) {
		apiReply(w, clusterRollback(r.PathValue("name")), done("rolling back"))
	})
	a.delete("/api/v1/cluster/apps/{name}", "admin", func(w http.ResponseWriter, r *http.Request) {
		apiReply(w, clusterRemoveApp(r.PathValue("name")), done("removed"))
	})
	a.post("/api/v1/cluster/nodes/{id}/{action}", "operator", func(w http.ResponseWriter, r *http.Request) {
		action := r.PathValue("action")
		if action != "cordon" && action != "uncordon" && action != "drain" {
			apiReply(w, errNotFound("unknown node action "+action), nil)
			return
		}
		apiReply(w, clusterNodeAction(r.PathValue("id"), action), done(action+" done"))
	})
	a.delete("/api/v1/cluster/nodes/{id}", "admin", func(w http.ResponseWriter, r *http.Request) {
		apiReply(w, clusterNodeAction(r.PathValue("id"), "remove"), done("node removed; its token is revoked"))
	})
	// Secrets are write-only: names and keys can be listed, values never leave the master.
	a.get("/api/v1/cluster/secrets", "admin", func(w http.ResponseWriter, r *http.Request) {
		if _, err := requireMaster(); err != nil {
			apiReply(w, err, nil)
			return
		}
		st, err := readState()
		if err != nil {
			apiReply(w, err, nil)
			return
		}
		view := map[string][]string{}
		for name, kv := range st.Secrets {
			keys := []string{}
			for k := range kv {
				keys = append(keys, k)
			}
			view[name] = keys
		}
		apiReply(w, nil, view)
	})
	a.put("/api/v1/cluster/secrets/{name}", "admin", func(w http.ResponseWriter, r *http.Request) {
		var kv map[string]string
		if !decodeBody(w, r, &kv) {
			return
		}
		apiReply(w, clusterSecretSet(r.PathValue("name"), kv), done("secret saved"))
	})
	a.delete("/api/v1/cluster/secrets/{name}", "admin", func(w http.ResponseWriter, r *http.Request) {
		apiReply(w, clusterSecretRm(r.PathValue("name")), done("secret removed"))
	})
}

// ---- host operations: backups, upgrades, audit, tokens, catalogs, events ----

func registerOpsRoutes(a *apiRouter) {
	a.get("/api/v1/backups", "operator", func(w http.ResponseWriter, r *http.Request) {
		apiReply(w, nil, listBackups())
	})
	a.post("/api/v1/backups", "admin", func(w http.ResponseWriter, r *http.Request) {
		if err := startJob([]string{"backup", "create"}, "/var/log/ziro-backup.log"); err != nil {
			apiReply(w, err, nil)
			return
		}
		apiAccepted(w, "backup started; GET /api/v1/backups lists it when done")
	})
	a.post("/api/v1/backups/{name}/restore", "admin", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if strings.ContainsAny(name, "/\\") || !strings.HasSuffix(name, ".tar.gz") || !fileExists(filepath.Join(defaultBackupDir, name)) {
			apiReply(w, errNotFound("no backup "+name), nil)
			return
		}
		if err := startJob([]string{"backup", "restore", "--", filepath.Join(defaultBackupDir, name)}, "/var/log/ziro-backup.log"); err != nil {
			apiReply(w, err, nil)
			return
		}
		apiAccepted(w, "restore of "+name+" started; see /var/log/ziro-backup.log")
	})

	a.get("/api/v1/upgrade", "viewer", func(w http.ResponseWriter, r *http.Request) {
		current := readRelease("/etc/ziro-release")["VERSION"]
		rel, err := fetchRelease(r.Context(), "")
		if err != nil {
			apiReply(w, err, nil)
			return
		}
		latest := strings.TrimPrefix(rel.TagName, "v")
		apiReply(w, nil, map[string]any{"current": current, "latest": latest, "update_available": compareSemver(latest, current) > 0})
	})
	a.post("/api/v1/upgrade", "admin", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Version string `json:"version,omitempty"`
			Reboot  bool   `json:"reboot,omitempty"`
		}
		if !decodeBody(w, r, &req) {
			return
		}
		args := []string{"upgrade", "--yes"}
		if req.Version != "" {
			if !upgradeTagRe.MatchString(req.Version) {
				apiReply(w, fmt.Errorf("invalid version %q", req.Version), nil)
				return
			}
			args = append(args, "--version="+req.Version)
		}
		if req.Reboot {
			args = append(args, "--reboot")
		}
		if err := startJob(args, "/var/log/ziro-upgrade.log"); err != nil {
			apiReply(w, err, nil)
			return
		}
		apiAccepted(w, "upgrade started; see /var/log/ziro-upgrade.log")
	})
	a.post("/api/v1/upgrade/rollback", "admin", func(w http.ResponseWriter, r *http.Request) {
		if err := startJob([]string{"upgrade", "rollback", "--yes"}, "/var/log/ziro-upgrade.log"); err != nil {
			apiReply(w, err, nil)
			return
		}
		apiAccepted(w, "rollback started; reboot to finish")
	})

	// The audit trail shows who did what: admin.
	a.get("/api/v1/audit", "admin", func(w http.ResponseWriter, r *http.Request) {
		apiReply(w, nil, readAuditTail(queryInt(r, "limit", 100, 1000), r.URL.Query().Get("since")))
	})
	a.get("/api/v1/audit/verify", "admin", func(w http.ResponseWriter, r *http.Request) {
		n, head, err := verifyAudit(auditFiles())
		apiReply(w, err, map[string]any{"records": n, "head": head, "intact": err == nil})
	})

	a.get("/api/v1/tokens", "admin", func(w http.ResponseWriter, r *http.Request) {
		apiReply(w, nil, apiTokenViews())
	})
	a.post("/api/v1/tokens", "admin", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Name string `json:"name"`
			Role string `json:"role"`
			TTL  string `json:"ttl,omitempty"` // Go duration; default 90 days, "0" = no expiry
		}
		if !decodeBody(w, r, &req) {
			return
		}
		ttl := 90 * 24 * time.Hour
		if req.TTL != "" {
			d, err := time.ParseDuration(req.TTL)
			if err != nil {
				apiReply(w, fmt.Errorf("ttl: %w", err), nil)
				return
			}
			ttl = d
		}
		tok, t, err := createAPIToken(req.Name, req.Role, ttl)
		apiReply(w, err, sdkapi.Token{Name: t.Name, Role: t.Role, ID: t.ID, Created: t.Created, Expires: t.Expires, Secret: tok})
	})
	a.delete("/api/v1/tokens/{name}", "admin", func(w http.ResponseWriter, r *http.Request) {
		apiReply(w, revokeAPIToken(r.PathValue("name")), APIMessage{Status: "ok", Message: "token revoked"})
	})

	a.get("/api/v1/modules/catalog", "viewer", func(w http.ResponseWriter, r *http.Request) {
		hits, err := searchModules(r.URL.Query().Get("q"))
		apiReply(w, err, hits)
	})
	a.get("/api/v1/modules/catalog/{name}", "viewer", func(w http.ResponseWriter, r *http.Request) {
		all, err := loadManifests()
		if err != nil {
			apiReply(w, err, nil)
			return
		}
		m, ok := installedManifest(all, r.PathValue("name"))
		if !ok {
			apiReply(w, errNotFound("unknown module "+r.PathValue("name")), nil)
			return
		}
		apiReply(w, nil, m)
	})
	a.get("/api/v1/repos", "viewer", func(w http.ResponseWriter, r *http.Request) {
		repos, err := catalogRepos("")
		apiReply(w, err, repos)
	})

	a.get("/api/v1/events", "operator", serveEvents)
}

// readAuditTail returns the last limit records of the current audit file, at or after since
// (RFC 3339, optional).
func readAuditTail(limit int, since string) []auditRecord {
	lines, _ := tailFile(auditPath, limit*4)
	out := []auditRecord{}
	for _, l := range lines {
		var rec auditRecord
		if json.Unmarshal([]byte(l), &rec) != nil || (since != "" && rec.TS < since) {
			continue
		}
		out = append(out, rec)
	}
	return out[max(0, len(out)-limit):]
}

// serveEvents streams every new audit record (each API, CLI and cluster change, and its result)
// as server-sent events: a watch, so clients don't poll. It ends when the client goes away.
func serveEvents(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		apiError(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	// The server's write timeout would cut the stream; this request lifts it.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Time{})
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, ": ziro events\n\n")
	fl.Flush()

	f, err := os.Open(auditPath)
	var off int64
	if err == nil {
		off, _ = f.Seek(0, io.SeekEnd)
		f.Close()
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Hour) // clients reconnect
	defer cancel()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	keepalive := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		f, err := os.Open(auditPath)
		if err != nil {
			continue
		}
		if fi, err := f.Stat(); err == nil && fi.Size() < off {
			off = 0 // rotated
		}
		_, _ = f.Seek(off, io.SeekStart)
		sc := bufio.NewScanner(f)
		sent := false
		for sc.Scan() {
			line := sc.Bytes()
			off += int64(len(line)) + 1
			var rec auditRecord
			if json.Unmarshal(line, &rec) != nil {
				continue
			}
			b, _ := json.Marshal(rec)
			fmt.Fprintf(w, "event: audit\ndata: %s\n\n", b)
			sent = true
		}
		f.Close()
		if keepalive++; sent || keepalive%15 == 0 {
			if !sent {
				fmt.Fprint(w, ": keepalive\n\n")
			}
			fl.Flush()
		}
	}
}
