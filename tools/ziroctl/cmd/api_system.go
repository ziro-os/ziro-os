package cmd

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os/exec"
	"time"
)

// System routes: live resource use, disk usage and pruning, power, and tools updates. They call
// the same functions as `ziroctl system top|df|prune|reboot|poweroff` and `ziroctl update`.
func registerSystemRoutes(mux apiMux, wrap func(bool, http.HandlerFunc) http.HandlerFunc) {
	mux.HandleFunc("/api/v1/system/top", wrap(false, func(w http.ResponseWriter, r *http.Request) {
		if !requireMethod(w, r, http.MethodGet) {
			return
		}
		s := takeSnapshot(time.Second)
		(&topView{sortBy: "cpu"}).sortSnapshot(&s)
		apiReply(w, nil, s)
	}))
	mux.HandleFunc("/api/v1/system/df", wrap(false, func(w http.ResponseWriter, r *http.Request) {
		if !requireMethod(w, r, http.MethodGet) {
			return
		}
		apiReply(w, nil, systemDiskUsage())
	}))
	// Prune plans by default; {"confirm": true} removes. Admin only: it deletes data.
	mux.HandleFunc("/api/v1/system/prune", wrap(false, func(w http.ResponseWriter, r *http.Request) {
		if !requireMethod(w, r, http.MethodPost) || !requireRole(w, r, "admin") {
			return
		}
		var req struct {
			Categories []string `json:"categories,omitempty"`
			All        bool     `json:"all,omitempty"`
			Confirm    bool     `json:"confirm,omitempty"`
		}
		if err := decodeStrict(w, r, &req, 64<<10); err != nil {
			apiReply(w, err, nil)
			return
		}
		cats, err := pruneSelection(req.Categories, req.All)
		if err != nil {
			apiReply(w, err, nil)
			return
		}
		items := planPrune(cats, time.Now())
		if !req.Confirm {
			var total int64
			for _, it := range items {
				total += it.Bytes
			}
			apiReply(w, nil, map[string]any{"items": items, "bytes": total, "applied": false})
			return
		}
		freed, errs := applyPrune(items)
		err = errors.Join(errs...)
		apiAudit(r, "system prune", "", err)
		apiReply(w, nil, map[string]any{"items": items, "bytes": freed, "applied": true, "errors": len(errs)})
	}))
	for _, act := range []string{"reboot", "poweroff"} {
		mux.HandleFunc("/api/v1/system/"+act, wrap(false, func(w http.ResponseWriter, r *http.Request) {
			if !requireMethod(w, r, http.MethodPost) || !requireRole(w, r, "admin") {
				return
			}
			apiAudit(r, "system "+act, "", nil)
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(APIMessage{Status: "accepted", Message: act + " in 2 seconds"})
			go func() { // let the reply reach the client first
				time.Sleep(2 * time.Second)
				_ = exec.Command("sync").Run()
				_ = exec.Command("/sbin/" + act).Run()
			}()
		}))
	}
	// GET: the cached daily check (?refresh=true checks now). POST: install (admin, background job).
	mux.HandleFunc("/api/v1/system/update", wrap(false, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			u := readUpdateCheck()
			if r.URL.Query().Get("refresh") == "true" {
				u = checkForUpdate()
			}
			apiReply(w, nil, u)
		case http.MethodPost:
			if !requireRole(w, r, "admin") {
				return
			}
			err := startJob([]string{"update"}, "/var/log/ziro-update.log")
			apiAudit(r, "update", "tools", err)
			if err != nil {
				apiReply(w, err, nil)
				return
			}
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(APIMessage{Status: "accepted", Message: "update started; see /var/log/ziro-update.log"})
		default:
			requireMethod(w, r, http.MethodGet, http.MethodPost)
		}
	}))
}

// requireMethod answers 405 (with Allow) unless the request uses one of the methods.
func requireMethod(w http.ResponseWriter, r *http.Request, methods ...string) bool {
	for _, m := range methods {
		if r.Method == m {
			return true
		}
	}
	allow := ""
	for i, m := range methods {
		if i > 0 {
			allow += ", "
		}
		allow += m
	}
	w.Header().Set("Allow", allow)
	w.WriteHeader(http.StatusMethodNotAllowed)
	_ = json.NewEncoder(w).Encode(APIMessage{Status: "error", Message: "method not allowed"})
	return false
}

// decodeStrict reads a JSON body of at most max bytes, rejecting unknown fields; an empty body
// leaves v unchanged.
func decodeStrict(w http.ResponseWriter, r *http.Request, v any, max int64) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, max))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}
