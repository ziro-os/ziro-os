package cmd

import (
	"encoding/json"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

type apiRoleKey struct{}

// requireRole enforces a per-route minimum role on top of the method-based check in wrapHandler
// (security-sensitive routes need admin even for reads that reveal configuration).
func requireRole(w http.ResponseWriter, r *http.Request, need string) bool {
	role, _ := r.Context().Value(apiRoleKey{}).(string)
	if apiRoleRank[role] >= apiRoleRank[need] {
		return true
	}
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(APIMessage{Status: "error", Message: "Forbidden: requires the " + need + " role"})
	return false
}

func apiAudit(r *http.Request, action, target string, err error) {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	caller, _ := r.Context().Value(apiCallerKey{}).(string)
	_ = auditLog(caller, "api:"+ip, action, target, err)
}

func apiReply(w http.ResponseWriter, err error, ok any) {
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(APIMessage{Status: "error", Message: err.Error()})
		return
	}
	_ = json.NewEncoder(w).Encode(ok)
}

func registerSecurityRoutes(mux *http.ServeMux, wrap func(bool, http.HandlerFunc) http.HandlerFunc) {
	// Protection state and bans. Reading is for any token; banning/unbanning needs admin.
	mux.HandleFunc("/api/v1/security/protect", wrap(false, func(w http.ResponseWriter, r *http.Request) {
		fw := loadFirewallConfig()
		bans, _ := listBans()
		_ = json.NewEncoder(w).Encode(map[string]any{"active": fw.Enabled && !fw.Guard.Disabled && guardActive(),
			"config": fw.Guard.withDefaults(), "bans": len(bans)})
	}))
	mux.HandleFunc("/api/v1/security/bans", wrap(false, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			bans, err := listBans()
			apiReply(w, err, bans)
		case http.MethodPost:
			if !requireRole(w, r, "admin") {
				return
			}
			var req struct {
				IP       string `json:"ip"`
				Duration string `json:"duration"`
			}
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
				apiReply(w, err, nil)
				return
			}
			ip, err := parseBanIP(req.IP)
			d := time.Hour
			if err == nil && req.Duration != "" {
				d, err = time.ParseDuration(req.Duration)
			}
			if err == nil && guardAllowed(ip, loadFirewallConfig().Guard) {
				err = errString(ip.String() + " is allowlisted")
			}
			if err == nil {
				err = banIP(ip, d)
				markOwnBan(ip.String())
			}
			apiAudit(r, "security ban", req.IP, err)
			apiReply(w, err, APIMessage{Status: "ok", Message: "banned " + req.IP + " for " + d.String()})
		default:
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		}
	}))
	mux.HandleFunc("/api/v1/security/bans/", wrap(false, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		if !requireRole(w, r, "admin") {
			return
		}
		raw := strings.TrimPrefix(r.URL.Path, "/api/v1/security/bans/")
		ip, err := parseBanIP(raw)
		if err == nil {
			err = unbanIP(ip)
		}
		apiAudit(r, "security unban", raw, err)
		apiReply(w, err, APIMessage{Status: "ok", Message: "unbanned " + raw})
	}))

	// Alert endpoints hold webhook URLs and signing secrets: admin only, secrets never returned
	// except once on creation.
	mux.HandleFunc("/api/v1/security/alerting", wrap(false, func(w http.ResponseWriter, r *http.Request) {
		if !requireRole(w, r, "admin") {
			return
		}
		switch r.Method {
		case http.MethodGet:
			cfg, err := loadAlertConfig()
			apiReply(w, err, map[string]any{"endpoints": publicEndpoints(cfg), "queued": len(spoolFiles())})
		case http.MethodPost:
			var req struct {
				Name        string   `json:"name"`
				URL         string   `json:"url"`
				MinSeverity string   `json:"min_severity"`
				Format      string   `json:"format"`
				Events      []string `json:"events"`
			}
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&req); err != nil {
				apiReply(w, err, nil)
				return
			}
			e, err := addAlertEndpoint(req.Name, req.URL, req.MinSeverity, req.Format, req.Events)
			apiAudit(r, "alerting add", req.Name, err)
			apiReply(w, err, e) // the only response that carries the secret
		default:
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		}
	}))
	mux.HandleFunc("/api/v1/security/alerting/", wrap(false, func(w http.ResponseWriter, r *http.Request) {
		if !requireRole(w, r, "admin") {
			return
		}
		name := strings.TrimPrefix(r.URL.Path, "/api/v1/security/alerting/")
		switch {
		case r.Method == http.MethodDelete:
			err := removeAlertEndpoint(name)
			apiAudit(r, "alerting remove", name, err)
			apiReply(w, err, APIMessage{Status: "ok", Message: "removed " + name})
		case r.Method == http.MethodPost && strings.HasSuffix(name, "/test"):
			var sb strings.Builder
			err := testAlertEndpoints([]string{strings.TrimSuffix(name, "/test")}, &sb)
			apiReply(w, err, APIMessage{Status: "ok", Message: strings.TrimSpace(sb.String())})
		default:
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		}
	}))
}

type errString string

func (e errString) Error() string { return string(e) }

func decodeBody(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384)).Decode(v); err != nil {
		apiReply(w, err, nil)
		return false
	}
	return true
}

// registerHostRoutes: networking, disks and SSH keys.
func registerHostRoutes(mux *http.ServeMux, wrap func(bool, http.HandlerFunc) http.HandlerFunc) {
	mux.HandleFunc("/api/v1/network", wrap(false, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			pending, _ := loadNetConfig(netConfigPath)
			applied, _ := loadNetConfig(netAppliedPath)
			host, _ := os.Hostname()
			resolv, _ := os.ReadFile(resolvPath)
			apiReply(w, nil, map[string]any{"hostname": host, "pending": pending, "applied": applied,
				"resolv_conf": string(resolv), "resolvers_pinned": fileExists(resolvPinned), "awaiting_confirm": fileExists(netRollbackPath)})
		case http.MethodPut: // replace the pending config and apply it; always with a rollback timer
			if !requireRole(w, r, "admin") {
				return
			}
			var req struct {
				Config         NetConfig `json:"config"`
				ConfirmTimeout string    `json:"confirm_timeout"`
			}
			if !decodeBody(w, r, &req) {
				return
			}
			d, err := time.ParseDuration(req.ConfirmTimeout)
			if err != nil || d < 30*time.Second || d > 30*time.Minute {
				apiReply(w, errString("confirm_timeout is required over the API (30s-30m): a bad config must not strand the host"), nil)
				return
			}
			if err = saveNetConfig(netConfigPath, &req.Config); err == nil {
				err = startNetApply(d)
			}
			apiAudit(r, "network apply", "confirm within "+d.String(), err)
			apiReply(w, err, APIMessage{Status: "ok", Message: "applied; POST /api/v1/network/confirm within " + d.String()})
		default:
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		}
	}))
	mux.HandleFunc("/api/v1/network/", wrap(false, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		var err error
		action := strings.TrimPrefix(r.URL.Path, "/api/v1/network/")
		switch action {
		case "confirm":
			if !requireRole(w, r, "admin") {
				return
			}
			if err = os.Remove(netRollbackPath); err != nil {
				err = errString("nothing to confirm")
			}
		case "hostname":
			var req struct {
				Hostname string `json:"hostname"`
			}
			if !decodeBody(w, r, &req) {
				return
			}
			err = setHostname(req.Hostname)
		case "dns":
			var req struct {
				Servers []string `json:"servers"` // empty: follow DHCP
				Search  []string `json:"search"`
			}
			if !decodeBody(w, r, &req) {
				return
			}
			if len(req.Servers) == 0 {
				if err = setResolvers(nil, nil); os.IsNotExist(err) {
					err = nil
				}
			} else {
				err = setResolvers(req.Servers, req.Search)
			}
		default:
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}
		apiAudit(r, "network "+action, "", err)
		apiReply(w, err, APIMessage{Status: "ok", Message: "network " + action + " done"})
	}))

	mux.HandleFunc("/api/v1/disks", wrap(false, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			root, fs := mountSource("/")
			apiReply(w, nil, map[string]any{"root": root, "root_fs": fs, "data_disks": loadDataDisks()})
		case http.MethodPost: // {"device": "/dev/vdb", "mount": "/data"}
			if !requireRole(w, r, "admin") {
				return
			}
			var req struct {
				Device string `json:"device"`
				Mount  string `json:"mount"`
				Label  string `json:"label"`
			}
			if !decodeBody(w, r, &req) {
				return
			}
			d, err := addDataDisk(req.Device, req.Mount, req.Label, false) // never --force over the API
			apiAudit(r, "disk add", req.Device+" -> "+req.Mount, err)
			apiReply(w, err, d)
		default:
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		}
	}))
	mux.HandleFunc("/api/v1/disks/expand", wrap(false, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		if !requireRole(w, r, "admin") {
			return
		}
		err := expandAll(false, true)
		apiAudit(r, "disk expand", "", err)
		apiReply(w, err, APIMessage{Status: "ok", Message: "filesystems grown where the disk had room"})
	}))

	// Authorized keys grant root: admin only, also for reading (who can log in is sensitive).
	mux.HandleFunc("/api/v1/ssh/keys", wrap(false, func(w http.ResponseWriter, r *http.Request) {
		if !requireRole(w, r, "admin") {
			return
		}
		switch r.Method {
		case http.MethodGet:
			b, _ := os.ReadFile(sshAuthorizedKeysPath)
			var keys []map[string]string
			for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
				if f := strings.Fields(l); len(f) >= 2 {
					c := ""
					if len(f) > 2 {
						c = strings.Join(f[2:], " ")
					}
					keys = append(keys, map[string]string{"type": f[0], "comment": c})
				}
			}
			apiReply(w, nil, keys)
		case http.MethodPost: // {"source": "gh:alice", "sync": false}
			var req struct {
				Source string `json:"source"`
				Sync   bool   `json:"sync"`
			}
			if !decodeBody(w, r, &req) {
				return
			}
			added, removed, rejected, err := importKeys(req.Source, req.Sync)
			apiAudit(r, "ssh key import", req.Source, err)
			apiReply(w, err, map[string]any{"added": added, "removed": removed, "rejected": rejected})
		case http.MethodDelete: // ?source=gh:alice
			src := r.URL.Query().Get("source")
			n, err := removeImportedKeys(src)
			apiAudit(r, "ssh key remove", src, err)
			apiReply(w, err, map[string]any{"removed": n})
		default:
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		}
	}))
}

// registerDNSRoutes: reading is for any token. Records and blocks: operator. Upstreams and
// forwards decide where every lookup goes (a hijack vector): admin.
func registerDNSRoutes(mux *http.ServeMux, wrap func(bool, http.HandlerFunc) http.HandlerFunc) {
	mux.HandleFunc("/api/v1/dns", wrap(false, func(w http.ResponseWriter, r *http.Request) {
		cfg, _ := loadDNSConfig()
		var st dnsStatsFile
		if b, err := os.ReadFile(dnsStatsPath); err == nil {
			_ = json.Unmarshal(b, &st)
		}
		apiReply(w, nil, map[string]any{"enabled": dnsEnabled(), "config": cfg, "stats": st, "cluster_records": loadClusterRecords()})
	}))
	mux.HandleFunc("/api/v1/dns/", wrap(false, func(w http.ResponseWriter, r *http.Request) {
		what := strings.TrimPrefix(r.URL.Path, "/api/v1/dns/")
		need := "operator"
		if what == "upstreams" || what == "forwards" {
			need = "admin"
		}
		if !requireRole(w, r, need) {
			return
		}
		var err error
		switch {
		case what == "records" && r.Method == http.MethodPost:
			var rec DNSRecord
			if !decodeBody(w, r, &rec) {
				return
			}
			err = mutateDNS(func(c *DNSConfig) error {
				if _, _, err := parseRecord(rec); err != nil {
					return err
				}
				c.Records = append(c.Records, rec)
				return nil
			})
		case what == "records" && r.Method == http.MethodDelete:
			name, typ := r.URL.Query().Get("name"), r.URL.Query().Get("type")
			err = mutateDNS(func(c *DNSConfig) error {
				kept := c.Records[:0]
				for _, x := range c.Records {
					if fqdn(x.Name) == fqdn(name) && (typ == "" || strings.EqualFold(x.Type, typ)) {
						continue
					}
					kept = append(kept, x)
				}
				c.Records = kept
				return nil
			})
		case what == "block" && r.Method == http.MethodPut:
			var req struct {
				Domains []string `json:"domains"`
			}
			if !decodeBody(w, r, &req) {
				return
			}
			err = mutateDNS(func(c *DNSConfig) error { c.Block = req.Domains; return nil })
		case what == "upstreams" && r.Method == http.MethodPut:
			var req struct {
				Upstreams []DNSUpstream `json:"upstreams"` // empty: from DHCP
			}
			if !decodeBody(w, r, &req) {
				return
			}
			err = mutateDNS(func(c *DNSConfig) error { c.Upstreams = req.Upstreams; return nil })
		case what == "forwards" && r.Method == http.MethodPut:
			var req struct {
				Forwards []DNSForward `json:"forwards"`
			}
			if !decodeBody(w, r, &req) {
				return
			}
			err = mutateDNS(func(c *DNSConfig) error { c.Forwards = req.Forwards; return nil })
		default:
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}
		apiAudit(r, "dns "+what+" "+strings.ToLower(r.Method), "", err)
		apiReply(w, err, APIMessage{Status: "ok", Message: "dns " + what + " updated (the resolver reloads within 2s)"})
	}))
}

// mutateDNS edits and validates the config; nothing is written when validation fails.
func mutateDNS(edit func(*DNSConfig) error) error {
	cfg, err := loadDNSConfig()
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := edit(cfg); err != nil {
		return err
	}
	return saveDNSConfig(cfg)
}

// registerModuleRoutes: listing modules is for any token; enabling, upgrading or disabling installs software
// as root, so it needs admin. The work runs detached through the ziroctl CLI (a ClamAV signature
// download outlasts any HTTP timeout); poll GET /api/v1/modules for its status.
func registerModuleRoutes(mux *http.ServeMux, wrap func(bool, http.HandlerFunc) http.HandlerFunc) {
	mux.HandleFunc("/api/v1/modules", wrap(false, func(w http.ResponseWriter, r *http.Request) {
		mods, err := listModules()
		apiReply(w, err, mods)
	}))
	mux.HandleFunc("/api/v1/modules/", wrap(false, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		if !requireRole(w, r, "admin") {
			return
		}
		name, action, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/api/v1/modules/"), "/")
		all, err := loadManifests()
		if err != nil {
			apiReply(w, err, nil)
			return
		}
		m, ok := all[name]
		act := map[string]string{"enable": "enable", "disable": "disable", "upgrade": "upgrade"}[action]
		if !ok || act == "" {
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(APIMessage{Status: "error", Message: "unknown module or action"})
			return
		}
		err = startModuleJob(act, m.Name) // the name comes from a verified manifest, not the URL
		apiAudit(r, "module "+act, m.Name, err)
		if err != nil {
			apiReply(w, err, nil)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(APIMessage{Status: "accepted", Message: "module " + act + " " + m.Name + " started; poll GET /api/v1/modules"})
	}))
}
