package cmd

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
)

// Stacks and host provisioning over the API. A stack received here may only use catalog apps
// (never paths on the host); deploys run in the background like `apps deploy`.

var stackIncomingDir = "/var/lib/ziro/stacks/incoming"

// stageJobFile writes a validated definition for a background job to run (0600, root only).
func stageJobFile(dir, name string, data []byte) (string, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	p := filepath.Join(dir, name)
	return p, writeFileAtomic(p, data, 0600)
}

func registerStackRoutes(a *apiRouter) {
	a.get("/api/v1/stacks", "viewer", func(w http.ResponseWriter, r *http.Request) {
		apiReply(w, nil, listStacks())
	})
	a.get("/api/v1/stacks/{name}", "viewer", func(w http.ResponseWriter, r *http.Request) {
		s, err := stackStatus(r.PathValue("name"))
		apiReply(w, err, s)
	})
	// readStack decodes a stack (JSON) for {name}, catalog apps only.
	readStack := func(w http.ResponseWriter, r *http.Request) (Stack, map[string]resolvedApp, bool) {
		var s Stack
		if err := decodeStrict(w, r, &s, 256<<10); err != nil {
			apiReply(w, err, nil)
			return s, nil, false
		}
		err := s.Validate()
		if err == nil && s.Stack != r.PathValue("name") {
			err = errors.New("the stack name in the body must match the URL")
		}
		var apps map[string]resolvedApp
		if err == nil {
			apps, err = resolveStackApps(s, "")
		}
		if err != nil {
			apiReply(w, err, nil)
			return s, nil, false
		}
		return s, apps, true
	}
	a.post("/api/v1/stacks/{name}/plan", "operator", func(w http.ResponseWriter, r *http.Request) {
		s, apps, ok := readStack(w, r)
		if !ok {
			return
		}
		prev, _ := loadStackState(s.Stack)
		plan, err := planStack(s, apps, prev)
		apiReply(w, err, map[string]any{"stack": s.Stack, "plan": plan})
	})
	a.put("/api/v1/stacks/{name}", "admin", func(w http.ResponseWriter, r *http.Request) {
		s, _, ok := readStack(w, r)
		if !ok {
			return
		}
		data, _ := json.MarshalIndent(s, "", "  ")
		path, err := stageJobFile(stackIncomingDir, s.Stack+".json", data)
		if err == nil {
			err = startJob([]string{"stack", "up", "-f", path}, "/var/log/ziro-stacks.log")
		}
		if err != nil {
			apiReply(w, err, nil)
			return
		}
		apiAccepted(w, "stack "+s.Stack+" is being applied; GET /api/v1/stacks/"+s.Stack)
	})
	a.delete("/api/v1/stacks/{name}", "admin", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if _, err := loadStackState(name); err != nil {
			apiReply(w, err, nil)
			return
		}
		args := []string{"stack", "down", name}
		if r.URL.Query().Get("purge") == "true" {
			args = append(args, "--purge")
		}
		if err := startJob(args, "/var/log/ziro-stacks.log"); err != nil {
			apiReply(w, err, nil)
			return
		}
		apiAccepted(w, "removing stack "+name)
	})

	// Host provisioning: ?dry_run=true answers the plan; otherwise it applies in the background.
	// Stack files are not available over the API (send stacks to /api/v1/stacks instead).
	a.post("/api/v1/apply", "admin", func(w http.ResponseWriter, r *http.Request) {
		var cfg HostConfig
		if err := decodeStrict(w, r, &cfg, 256<<10); err != nil {
			apiReply(w, err, nil)
			return
		}
		if err := cfg.Validate(); err != nil {
			apiReply(w, err, nil)
			return
		}
		if len(cfg.Host.Stacks) > 0 {
			apiReply(w, errors.New("stacks: put them with PUT /api/v1/stacks/{name}"), nil)
			return
		}
		data, _ := json.MarshalIndent(cfg, "", "  ")
		if r.URL.Query().Get("dry_run") == "true" {
			plan, err := applyHostFile(data, "", true, 0)
			apiReply(w, err, map[string]any{"plan": plan})
			return
		}
		path, err := stageJobFile("/var/lib/ziro/apply", "host.json", data)
		if err == nil {
			err = startJob([]string{"apply", "-f", path}, "/var/log/ziro-apply.log")
		}
		if err != nil {
			apiReply(w, err, nil)
			return
		}
		apiAccepted(w, "applying; see /var/log/ziro-apply.log")
	})
}
