package cmd

import (
	"encoding/json"
	"net"
	"net/http"
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
		_ = json.NewEncoder(w).Encode(map[string]any{"active": fw.Enabled && !fw.Guard.Disabled,
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
