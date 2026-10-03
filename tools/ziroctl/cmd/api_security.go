package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ziro-os/ziro-os/sdk/schema"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

func registerSecurityRoutes(a *apiRouter) {
	a.get("/api/v1/security/protect", "viewer", func(w http.ResponseWriter, r *http.Request) {
		fw := loadFirewallConfig()
		bans, _ := listBans()
		apiReply(w, nil, map[string]any{"active": fw.Enabled && !fw.Guard.Disabled && guardActive(),
			"config": fw.Guard.withDefaults(), "bans": len(bans)})
	})
	// Replace the protection settings (validated, saved and applied like `security protect set`).
	a.put("/api/v1/security/protect", "admin", func(w http.ResponseWriter, r *http.Request) {
		var g GuardConfig
		if !decodeBody(w, r, &g) {
			return
		}
		apiReply(w, updateGuard(func(cur *GuardConfig) { *cur = g }), APIMessage{Status: "ok", Message: "protection settings applied"})
	})
	a.get("/api/v1/security/bans", "viewer", func(w http.ResponseWriter, r *http.Request) {
		bans, err := listBans()
		apiReply(w, err, bans)
	})
	a.post("/api/v1/security/bans", "admin", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			IP       string `json:"ip"`
			Duration string `json:"duration"`
		}
		if !decodeBody(w, r, &req) {
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
		apiReply(w, err, APIMessage{Status: "ok", Message: "banned " + req.IP + " for " + d.String()})
	})
	a.delete("/api/v1/security/bans/{ip}", "admin", func(w http.ResponseWriter, r *http.Request) {
		raw := r.PathValue("ip")
		ip, err := parseBanIP(raw)
		if err == nil {
			err = unbanIP(ip)
		}
		apiReply(w, err, APIMessage{Status: "ok", Message: "unbanned " + raw})
	})

	// Alert endpoints hold webhook URLs and signing secrets: admin only, secrets never returned
	// except once on creation.
	a.get("/api/v1/security/alerting", "admin", func(w http.ResponseWriter, r *http.Request) {
		cfg, err := loadAlertConfig()
		apiReply(w, err, map[string]any{"endpoints": publicEndpoints(cfg), "queued": len(spoolFiles())})
	})
	a.post("/api/v1/security/alerting", "admin", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Name        string   `json:"name"`
			URL         string   `json:"url"`
			MinSeverity string   `json:"min_severity"`
			Format      string   `json:"format"`
			Events      []string `json:"events"`
		}
		if !decodeBody(w, r, &req) {
			return
		}
		e, err := addAlertEndpoint(req.Name, req.URL, req.MinSeverity, req.Format, req.Events)
		apiReply(w, err, e) // the only response that carries the secret
	})
	a.delete("/api/v1/security/alerting/{name}", "admin", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		err := validName(name)
		if err == nil {
			err = removeAlertEndpoint(name)
		}
		apiReply(w, err, APIMessage{Status: "ok", Message: "removed " + name})
	})
	a.post("/api/v1/security/alerting/{name}/test", "admin", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		var sb strings.Builder
		err := validName(name)
		if err == nil {
			err = testAlertEndpoints([]string{name}, &sb)
		}
		apiReply(w, err, APIMessage{Status: "ok", Message: strings.TrimSpace(sb.String())})
	})
}

type errString string

func (e errString) Error() string { return string(e) }

// registerHostRoutes: networking, disks and SSH keys. Anything that changes how the host is
// reached (addresses, hostname, resolvers, keys, disks) needs admin.
func registerHostRoutes(a *apiRouter) {
	a.get("/api/v1/network", "viewer", func(w http.ResponseWriter, r *http.Request) {
		pending, _ := loadNetConfig(netConfigPath)
		applied, _ := loadNetConfig(netAppliedPath)
		host, _ := os.Hostname()
		resolv, _ := os.ReadFile(resolvPath)
		apiReply(w, nil, map[string]any{"hostname": host, "pending": pending, "applied": applied,
			"resolv_conf": string(resolv), "resolvers_pinned": fileExists(resolvPinned), "awaiting_confirm": fileExists(netRollbackPath)})
	})
	// Replace the pending config and apply it, always with a rollback timer.
	a.put("/api/v1/network", "admin", func(w http.ResponseWriter, r *http.Request) {
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
		apiReply(w, err, APIMessage{Status: "ok", Message: "applied; POST /api/v1/network/confirm within " + d.String()})
	})
	a.post("/api/v1/network/confirm", "admin", func(w http.ResponseWriter, r *http.Request) {
		var err error
		if os.Remove(netRollbackPath) != nil {
			err = errString("nothing to confirm")
		}
		apiReply(w, err, APIMessage{Status: "ok", Message: "network change confirmed"})
	})
	a.post("/api/v1/network/hostname", "admin", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Hostname string `json:"hostname"`
		}
		if !decodeBody(w, r, &req) {
			return
		}
		apiReply(w, setHostname(req.Hostname), APIMessage{Status: "ok", Message: "hostname set"})
	})
	// Resolvers decide where every lookup goes (a hijack vector): admin, like /dns/upstreams.
	a.post("/api/v1/network/dns", "admin", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Servers []string `json:"servers"` // empty: follow DHCP
			Search  []string `json:"search"`
		}
		if !decodeBody(w, r, &req) {
			return
		}
		var err error
		if len(req.Servers) == 0 {
			if err = setResolvers(nil, nil); os.IsNotExist(err) {
				err = nil
			}
		} else {
			err = setResolvers(req.Servers, req.Search)
		}
		apiReply(w, err, APIMessage{Status: "ok", Message: "resolvers set"})
	})

	a.get("/api/v1/disks", "viewer", func(w http.ResponseWriter, r *http.Request) {
		root, fs := mountSource("/")
		apiReply(w, nil, map[string]any{"root": root, "root_fs": fs, "data_disks": loadDataDisks()})
	})
	a.post("/api/v1/disks", "admin", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Device string `json:"device"`
			Mount  string `json:"mount"`
			Label  string `json:"label"`
		}
		if !decodeBody(w, r, &req) {
			return
		}
		d, err := addDataDisk(req.Device, req.Mount, req.Label, false) // never --force over the API
		apiReply(w, err, d)
	})
	a.post("/api/v1/disks/expand", "admin", func(w http.ResponseWriter, r *http.Request) {
		apiReply(w, expandAll(false, true), APIMessage{Status: "ok", Message: "filesystems grown where the disk had room"})
	})

	// Authorized keys grant root: admin only, also for reading (who can log in is sensitive).
	a.get("/api/v1/ssh/keys", "admin", func(w http.ResponseWriter, r *http.Request) {
		b, _ := os.ReadFile(sshAuthorizedKeysPath)
		keys := []map[string]string{}
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
	})
	a.post("/api/v1/ssh/keys", "admin", func(w http.ResponseWriter, r *http.Request) { // {"source": "gh:alice", "sync": false}
		var req struct {
			Source string `json:"source"`
			Sync   bool   `json:"sync"`
		}
		if !decodeBody(w, r, &req) {
			return
		}
		added, removed, rejected, err := importKeys(req.Source, req.Sync)
		apiReply(w, err, map[string]any{"added": added, "removed": removed, "rejected": rejected})
	})
	a.delete("/api/v1/ssh/keys", "admin", func(w http.ResponseWriter, r *http.Request) { // ?source=gh:alice
		n, err := removeImportedKeys(r.URL.Query().Get("source"))
		apiReply(w, err, map[string]any{"removed": n})
	})
}

// registerDNSRoutes: reading is for any token. Records and blocks: operator. Upstreams and
// forwards decide where every lookup goes (a hijack vector): admin. Edits go through editDNS,
// the same validation as the CLI.
func registerDNSRoutes(a *apiRouter) {
	a.get("/api/v1/dns", "viewer", func(w http.ResponseWriter, r *http.Request) {
		cfg, _ := loadDNSConfig()
		var st dnsStatsFile
		if b, err := os.ReadFile(dnsStatsPath); err == nil {
			_ = json.Unmarshal(b, &st)
		}
		apiReply(w, nil, map[string]any{"enabled": dnsEnabled(), "config": cfg, "stats": st, "cluster_records": loadClusterRecords()})
	})
	done := APIMessage{Status: "ok", Message: "dns updated (the resolver reloads within 2s)"}
	a.post("/api/v1/dns/records", "operator", func(w http.ResponseWriter, r *http.Request) {
		var rec DNSRecord
		if !decodeBody(w, r, &rec) {
			return
		}
		apiReply(w, editDNS(func(c *DNSConfig) error { return addDNSRecord(c, rec) }), done)
	})
	a.delete("/api/v1/dns/records", "operator", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		apiReply(w, editDNS(func(c *DNSConfig) error { return removeDNSRecords(c, q.Get("name"), q.Get("type")) }), done)
	})
	a.put("/api/v1/dns/block", "operator", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Domains []string `json:"domains"`
		}
		if !decodeBody(w, r, &req) {
			return
		}
		apiReply(w, editDNS(func(c *DNSConfig) error { c.Block = req.Domains; return nil }), done)
	})
	a.put("/api/v1/dns/upstreams", "admin", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Upstreams []DNSUpstream `json:"upstreams"` // empty: from DHCP
		}
		if !decodeBody(w, r, &req) {
			return
		}
		apiReply(w, editDNS(func(c *DNSConfig) error { c.Upstreams = req.Upstreams; return nil }), done)
	})
	a.put("/api/v1/dns/forwards", "admin", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Forwards []DNSForward `json:"forwards"`
		}
		if !decodeBody(w, r, &req) {
			return
		}
		apiReply(w, editDNS(func(c *DNSConfig) error { c.Forwards = req.Forwards; return nil }), done)
	})
}

// registerModuleRoutes: listing modules is for any token; enabling, upgrading or disabling
// installs software as root, so it needs admin. The work runs detached through the ziroctl CLI
// (a ClamAV signature download outlasts any HTTP timeout); poll GET /api/v1/modules.
func registerModuleRoutes(a *apiRouter) {
	a.get("/api/v1/modules", "viewer", func(w http.ResponseWriter, r *http.Request) {
		mods, err := listModules()
		apiReply(w, err, mods)
	})
	a.post("/api/v1/modules/{name}/{action}", "admin", func(w http.ResponseWriter, r *http.Request) {
		all, err := loadManifests()
		if err != nil {
			apiReply(w, err, nil)
			return
		}
		m, ok := all[r.PathValue("name")]
		act := map[string]string{"enable": "enable", "disable": "disable", "upgrade": "upgrade", "purge": "purge"}[r.PathValue("action")]
		if !ok || act == "" {
			apiReply(w, errNotFound("unknown module or action"), nil)
			return
		}
		job := []string{act, m.Name} // the name comes from a verified manifest, not the URL
		if act == "purge" {
			job = []string{"disable", m.Name, "--purge"}
		}
		if err := startModuleJob(job...); err != nil {
			apiReply(w, err, nil)
			return
		}
		apiAccepted(w, "module "+act+" "+m.Name+" started; poll GET /api/v1/modules")
	})
}

// validAppRef checks "name[:version]" with the catalog's own name and version rules.
func validAppRef(ref string) error {
	name, version := parseAppRef(ref)
	if err := validName(name); err != nil {
		return fmt.Errorf("invalid app %q (want name[:version])", ref)
	}
	if strings.Contains(ref, ":") && !schema.AppVersionRe.MatchString(version) {
		return fmt.Errorf("invalid app version in %q", ref)
	}
	return nil
}

// deployJobArgs turns a request into `ziroctl apps deploy` argv. Every value goes in a
// --flag=value form after validation, and the app ref after "--", so nothing can become a flag.
func deployJobArgs(req AppDeployRequest) ([]string, error) {
	args, _, err := deployJob(req)
	return args, err
}

// deployJob is deployJobArgs plus the environment carrying input secrets (--secret KEY reads
// $ZIRO_SECRET_KEY), so a secret never appears in the job's argv.
func deployJob(req AppDeployRequest) (args, env []string, err error) {
	args, err = deployJobArgv(req)
	if err != nil {
		return nil, nil, err
	}
	keys := make([]string, 0, len(req.Secrets))
	for k := range req.Secrets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var flags []string
	for _, k := range keys {
		if !envKeyRe.MatchString(k) || strings.HasPrefix(k, "ZIRO_") {
			return nil, nil, fmt.Errorf("invalid secret name %q", k)
		}
		if err := schema.ValidSecretValue(req.Secrets[k]); err != nil {
			return nil, nil, fmt.Errorf("secret %s: %w", k, err)
		}
		flags = append(flags, "--secret="+k)
		env = append(env, secretEnvPrefix+k+"="+req.Secrets[k])
	}
	n := len(args) - 2 // before "--", app
	return append(append(args[:n:n], flags...), args[n:]...), env, nil
}

func deployJobArgv(req AppDeployRequest) ([]string, error) {
	if err := validAppRef(req.App); err != nil {
		return nil, err
	}
	args := []string{"apps", "deploy"}
	if req.Name != "" {
		if err := validName(req.Name); err != nil {
			return nil, err
		}
		args = append(args, "--name="+req.Name)
	}
	keys := make([]string, 0, len(req.Set))
	for k := range req.Set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !settingNameRe.MatchString(k) || strings.ContainsAny(req.Set[k], "\x00\r\n") {
			return nil, fmt.Errorf("invalid setting %q", k)
		}
		args = append(args, "--set="+k+"="+req.Set[k])
	}
	if req.Replicas < 0 || req.Replicas > 64 || req.Publish < 0 || req.Publish > 65535 {
		return nil, errors.New("invalid replicas or publish port")
	}
	if req.Replicas > 0 {
		args = append(args, "--replicas="+strconv.Itoa(req.Replicas))
	}
	if req.Publish > 0 {
		args = append(args, "--publish="+strconv.Itoa(req.Publish))
	}
	for _, a := range req.AllowFrom {
		if a != "*" {
			if err := validName(a); err != nil {
				return nil, err
			}
		}
		args = append(args, "--allow-from="+a)
	}
	if req.Expose != "" {
		if !validHost(req.Expose) || strings.HasPrefix(req.Expose, "*.") {
			return nil, fmt.Errorf("invalid expose host %q", req.Expose)
		}
		args = append(args, "--expose="+req.Expose)
	}
	if req.ExposeTLS != "" {
		if req.ExposeTLS != "auto" && req.ExposeTLS != "internal" && req.ExposeTLS != "off" &&
			!(strings.HasPrefix(req.ExposeTLS, "cert:") && validName(strings.TrimPrefix(req.ExposeTLS, "cert:")) == nil) {
			return nil, fmt.Errorf("invalid expose_tls %q", req.ExposeTLS)
		}
		args = append(args, "--expose-tls="+req.ExposeTLS)
	}
	return append(args, "--", req.App), nil
}

// registerAppRoutes: reading is for any token; deploying and removing run containers, so they
// need admin. Deploys run detached (image pulls outlast HTTP timeouts); poll GET /api/v1/apps.
// Credentials are never served over the API: use the CLI on the host.
func registerAppRoutes(a *apiRouter) {
	a.get("/api/v1/apps", "viewer", func(w http.ResponseWriter, r *http.Request) {
		apiReply(w, nil, appsStatus())
	})
	a.get("/api/v1/apps/catalog", "viewer", func(w http.ResponseWriter, r *http.Request) {
		apiReply(w, nil, appCatalogList(strings.ToLower(r.URL.Query().Get("q"))))
	})
	a.get("/api/v1/apps/catalog/{app}", "viewer", func(w http.ResponseWriter, r *http.Request) {
		d, ok := loadAppDefs()[r.PathValue("app")]
		if !ok {
			apiReply(w, errNotFound("unknown app "+r.PathValue("app")), nil)
			return
		}
		apiReply(w, nil, d)
	})
	a.post("/api/v1/apps/deploy", "admin", func(w http.ResponseWriter, r *http.Request) {
		var req AppDeployRequest
		if err := decodeStrict(w, r, &req, 64<<10); err != nil {
			apiReply(w, err, nil)
			return
		}
		args, env, err := deployJob(req)
		if err == nil {
			err = startJobEnv(args, env, "/var/log/ziro-apps.log")
		}
		if err != nil {
			apiReply(w, err, nil)
			return
		}
		apiAccepted(w, "deploying "+req.App+"; poll GET /api/v1/apps")
	})
	// ?purge=true also deletes the app's data and credentials.
	a.delete("/api/v1/apps/{name}", "admin", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if err := validName(name); err != nil {
			apiReply(w, err, nil)
			return
		}
		args := []string{"apps", "rm", name}
		if r.URL.Query().Get("purge") == "true" {
			args = []string{"apps", "purge", name}
		}
		if err := startJob(args, "/var/log/ziro-apps.log"); err != nil {
			apiReply(w, err, nil)
			return
		}
		apiAccepted(w, "removing "+name+"; poll GET /api/v1/apps")
	})
}

// registerNFSRoutes: read-only views of NFS (any token). Exports change through the CLI, which
// also opens the firewall to the clients.
func registerNFSRoutes(a *apiRouter) {
	a.get("/api/v1/nfs", "viewer", func(w http.ResponseWriter, r *http.Request) {
		c, err := loadNFSConfig()
		if os.IsNotExist(err) {
			err = nil
		}
		apiReply(w, err, c)
	})
	a.get("/api/v1/nfs/clients", "viewer", func(w http.ResponseWriter, r *http.Request) {
		clients, err := listNFSClients(nfsAllExports())
		apiReply(w, err, clients)
	})
}
