package cmd

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/spf13/cobra"
)

// Git webhooks: a push to the deployment's branch builds and releases it. GitHub signs the body
// (X-Hub-Signature-256: HMAC-SHA256 with the hook secret); GitLab sends the secret as
// X-Gitlab-Token. Both are compared in constant time. A delivery ID seen before is ignored
// (replays), and a push while a build of the app is still queued doesn't queue another.
// The endpoint is public (POST /api/v1/hooks/deploy/<app>, through the REST API or the gateway):
// everything about it is decided by the secret.

func hookSecretPath(app string) string { return filepath.Join(deployTokenDir, app+".hook") }

// hookSecret returns the app's hook secret, creating it (or a new one) when asked.
func hookSecret(app string, rotate bool) (string, error) {
	if b, err := os.ReadFile(hookSecretPath(app)); err == nil && !rotate {
		return strings.TrimSpace(string(b)), nil
	}
	s := randomHex(32)
	if err := os.MkdirAll(deployTokenDir, 0700); err != nil {
		return "", err
	}
	return s, writeFileAtomic(hookSecretPath(app), []byte(s), 0600)
}

// verifyHook checks a webhook request against secret.
func verifyHook(h http.Header, body []byte, secret string) error {
	if secret == "" {
		return errors.New("no hook secret: ziroctl deploy hook <app>")
	}
	if sig, ok := strings.CutPrefix(h.Get("X-Hub-Signature-256"), "sha256="); ok {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(body)
		want := hex.EncodeToString(mac.Sum(nil))
		if subtle.ConstantTimeCompare([]byte(strings.ToLower(sig)), []byte(want)) == 1 {
			return nil
		}
		return errors.New("bad signature")
	}
	if tok := h.Get("X-Gitlab-Token"); tok != "" {
		if subtle.ConstantTimeCompare([]byte(tok), []byte(secret)) == 1 {
			return nil
		}
		return errors.New("bad token")
	}
	return errors.New("unsigned request")
}

// pushBranch reads the pushed branch and the repository's default branch from a GitHub or
// GitLab push payload.
func pushBranch(body []byte) (branch, def string, err error) {
	var p struct {
		Ref        string `json:"ref"`
		Repository struct {
			DefaultBranch string `json:"default_branch"`
		} `json:"repository"`
		Project struct {
			DefaultBranch string `json:"default_branch"`
		} `json:"project"`
	}
	if err := json.Unmarshal(body, &p); err != nil {
		return "", "", errors.New("not a push event")
	}
	def = p.Repository.DefaultBranch
	if def == "" {
		def = p.Project.DefaultBranch
	}
	b, ok := strings.CutPrefix(p.Ref, "refs/heads/")
	if !ok {
		return "", def, errors.New("not a branch push")
	}
	return b, def, nil
}

// hookDeliveries remembers recent delivery IDs per app (replay protection).
type hookDeliveries struct {
	mu   sync.Mutex
	seen map[string][]string
}

func (h *hookDeliveries) first(app, id string) bool {
	if id == "" {
		return true
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.seen == nil {
		h.seen = map[string][]string{}
	}
	for _, s := range h.seen[app] {
		if s == id {
			return false
		}
	}
	h.seen[app] = append(h.seen[app], id)
	if len(h.seen[app]) > 64 {
		h.seen[app] = h.seen[app][1:]
	}
	return true
}

// handleHook is POST /v1/hooks/deploy/{app}.
func (dd *deployDaemon) handleHook(w http.ResponseWriter, r *http.Request) {
	app := r.PathValue("app")
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		apiError(w, http.StatusRequestEntityTooLarge, "body too large")
		return
	}
	d, derr := loadDeployment(app)
	secret := ""
	if derr == nil {
		if b, err := os.ReadFile(hookSecretPath(app)); err == nil {
			secret = strings.TrimSpace(string(b))
		}
	}
	if err := verifyHook(r.Header, body, secret); err != nil || derr != nil {
		apiError(w, http.StatusUnauthorized, "unauthorized") // same answer whether or not the app exists
		return
	}
	if d.Source == deploySourceUpload {
		apiAccepted(w, "ignored: an uploaded deployment has no repository")
		return
	}
	if ev := r.Header.Get("X-GitHub-Event"); ev == "ping" {
		apiAccepted(w, "pong")
		return
	}
	branch, def, err := pushBranch(body)
	if err != nil {
		apiAccepted(w, "ignored: "+err.Error())
		return
	}
	want := d.Ref
	if want == "" {
		want = def
	}
	if branch != want {
		apiAccepted(w, "ignored: push to "+branch+", deploying "+want)
		return
	}
	id := r.Header.Get("X-GitHub-Delivery")
	if id == "" {
		id = r.Header.Get("X-Gitlab-Event-UUID")
	}
	if !dd.hooks.first(app, id) {
		apiAccepted(w, "ignored: delivery already seen")
		return
	}
	for _, b := range listBuilds(app) {
		if b.Status == "queued" {
			apiAccepted(w, "already queued: "+b.ID)
			return
		}
	}
	b, err := dd.enqueue(d, &Build{}, nil)
	if err != nil {
		apiError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	apiAccepted(w, "queued "+b.ID)
}

var deployHookRotate bool

var deployHookCmd = &cobra.Command{
	Use:   "hook <app>",
	Short: "Show the git webhook URL and secret of a deployment",
	Long: `Show the webhook to add to the repository (GitHub: Settings > Webhooks, content type
application/json, push events; GitLab: Settings > Webhooks, secret token). Each push to the
deployment's branch then builds and releases it. The URL is the REST API (ziroctl api start
--bind 0.0.0.0) or a gateway route to it.`,
	Example: `  ziroctl deploy hook web
  ziroctl deploy hook web --rotate`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		var out struct {
			Path   string `json:"path"`
			Secret string `json:"secret"`
		}
		q := ""
		if deployHookRotate {
			q = "?rotate=true"
		}
		if err := deployCall("GET", "/v1/deployments/"+args[0]+"/hook"+q, nil, &out); err != nil {
			return err
		}
		return printResult(out, func() {
			fmt.Printf("URL      https://<this host or gateway hostname>%s\nSecret   %s\n", out.Path, out.Secret)
		})
	},
}

func init() {
	deployHookCmd.Flags().BoolVar(&deployHookRotate, "rotate", false, "Replace the secret (the old one stops working)")
	deployCmd.AddCommand(deployHookCmd)
}
