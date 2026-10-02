package cmd

import (
	"net/http"
	"os/exec"
	"time"
)

// System routes: live resource use, disk usage and pruning, power, and tools updates. They call
// the same functions as `ziroctl system top|df|prune|reboot|poweroff` and `ziroctl update`.
func registerSystemRoutes(a *apiRouter) {
	a.get("/api/v1/system/top", "viewer", func(w http.ResponseWriter, r *http.Request) {
		s := takeSnapshot(time.Second)
		(&topView{sortBy: "cpu"}).sortSnapshot(&s)
		apiReply(w, nil, s)
	})
	a.get("/api/v1/system/df", "viewer", func(w http.ResponseWriter, r *http.Request) {
		apiReply(w, nil, systemDiskUsage())
	})
	// Prune plans by default; {"confirm": true} removes. Admin: it deletes data.
	a.post("/api/v1/system/prune", "admin", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Categories []string `json:"categories,omitempty"`
			All        bool     `json:"all,omitempty"`
			Confirm    bool     `json:"confirm,omitempty"`
		}
		if !decodeBody(w, r, &req) {
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
		apiReply(w, nil, map[string]any{"items": items, "bytes": freed, "applied": true, "errors": errorStrings(errs)})
	})
	for _, act := range []string{"reboot", "poweroff"} {
		a.post("/api/v1/system/"+act, "admin", func(w http.ResponseWriter, r *http.Request) {
			apiAccepted(w, act+" in 2 seconds")
			go func() { // let the reply reach the client first
				time.Sleep(2 * time.Second)
				_ = exec.Command("sync").Run()
				_ = exec.Command("/sbin/" + act).Run()
			}()
		})
	}
	// The cached daily check (?refresh=true checks now); POST installs in the background.
	a.get("/api/v1/system/update", "viewer", func(w http.ResponseWriter, r *http.Request) {
		u := readUpdateCheck()
		if r.URL.Query().Get("refresh") == "true" {
			u = checkForUpdate()
		}
		apiReply(w, nil, u)
	})
	a.post("/api/v1/system/update", "admin", func(w http.ResponseWriter, r *http.Request) {
		if err := startJob([]string{"update"}, "/var/log/ziro-update.log"); err != nil {
			apiReply(w, err, nil)
			return
		}
		apiAccepted(w, "update started; GET /api/v1/system/update shows the result")
	})
}

func errorStrings(errs []error) []string {
	out := make([]string, 0, len(errs))
	for _, e := range errs {
		if e != nil {
			out = append(out, e.Error())
		}
	}
	return out
}
