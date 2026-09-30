package cmd

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

// Security alerting: every protection feature raises alerts through alertf. Alerts are spooled to
// disk first (so an unreachable endpoint loses nothing), then pushed to the configured webhooks,
// signed with a per-endpoint HMAC so receivers can verify origin and reject replays.

var (
	alertConfigPath = "/etc/ziro/alerting.json"
	alertSpoolDir   = "/var/lib/ziro/alerts"
)

const (
	alertSpoolMax   = 1000             // oldest alerts are dropped beyond this
	alertDedupe     = 10 * time.Minute // the same alert (category+title) is sent once per window
	alertGiveUp     = 24 * time.Hour   // stop retrying an alert this old
	alertMaxBackoff = time.Hour
)

var alertSeverities = map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

var alertCategories = map[string]bool{"ban": true, "threat": true, "fim": true, "canary": true,
	"av": true, "disk": true, "service": true, "module": true, "test": true}

var alertNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

type AlertEndpoint struct {
	Name        string   `json:"name"`
	URL         string   `json:"url"`
	Secret      string   `json:"secret"`
	MinSeverity string   `json:"min_severity"`
	Events      []string `json:"events,omitempty"` // categories; empty = all
	Format      string   `json:"format"`           // "json" or "slack"
	Created     string   `json:"created"`
}

type AlertConfig struct {
	Endpoints []AlertEndpoint `json:"endpoints"`
}

type Alert struct {
	ID        string         `json:"id"`
	Time      string         `json:"time"`
	Host      string         `json:"host"`
	NodeID    string         `json:"node_id,omitempty"`
	ClusterID string         `json:"cluster_id,omitempty"`
	Severity  string         `json:"severity"`
	Category  string         `json:"category"`
	Title     string         `json:"title"`
	Details   map[string]any `json:"details,omitempty"`
}

// spooled is an alert waiting for delivery; Pending lists endpoints that have not accepted it yet.
type spooled struct {
	Alert    Alert     `json:"alert"`
	Pending  []string  `json:"pending"`
	Attempts int       `json:"attempts"`
	NextTry  time.Time `json:"next_try"`
}

func loadAlertConfig() (AlertConfig, error) {
	var c AlertConfig
	b, err := os.ReadFile(alertConfigPath)
	if os.IsNotExist(err) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	return c, json.Unmarshal(b, &c)
}

func saveAlertConfig(c AlertConfig) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(alertConfigPath), 0755); err != nil {
		return err
	}
	return writeFileAtomic(alertConfigPath, b, 0600) // holds the HMAC secrets
}

// validateAlertURL: HTTPS only, except plain HTTP to loopback (a local relay or collector).
func validateAlertURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil {
		return nil, fmt.Errorf("invalid webhook URL %q", raw)
	}
	switch u.Scheme {
	case "https":
		return u, nil
	case "http":
		host := u.Hostname()
		if host == "localhost" {
			return u, nil
		}
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			return u, nil
		}
	}
	return nil, fmt.Errorf("webhook URL must be https:// (plain http only to loopback): %q", raw)
}

func alertSign(secret string, ts string, body []byte) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(ts))
	m.Write([]byte("."))
	m.Write(body)
	return "sha256=" + hex.EncodeToString(m.Sum(nil))
}

func (e AlertEndpoint) wants(a Alert) bool {
	if alertSeverities[a.Severity] < alertSeverities[e.MinSeverity] && a.Category != "test" {
		return false
	}
	if len(e.Events) == 0 || a.Category == "test" {
		return true
	}
	for _, ev := range e.Events {
		if ev == a.Category {
			return true
		}
	}
	return false
}

func alertBody(e AlertEndpoint, a Alert) ([]byte, error) {
	if e.Format != "slack" {
		return json.Marshal(a)
	}
	keys := make([]string, 0, len(a.Details))
	for k := range a.Details {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var sb strings.Builder
	fmt.Fprintf(&sb, "*[%s] %s*\nhost `%s` · %s · %s", strings.ToUpper(a.Severity), a.Title, a.Host, a.Category, a.Time)
	for _, k := range keys {
		fmt.Fprintf(&sb, "\n• %s: `%v`", k, a.Details[k])
	}
	return json.Marshal(map[string]string{"text": sb.String()})
}

var alertHTTP = &http.Client{
	Timeout: 5 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		Proxy:               http.ProxyFromEnvironment,
		MaxIdleConnsPerHost: 2,
	},
	// A webhook that redirects could bounce signed alerts elsewhere: treat redirects as failure.
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

func deliverAlert(e AlertEndpoint, a Alert) error {
	u, err := validateAlertURL(e.URL)
	if err != nil {
		return err
	}
	body, err := alertBody(e, a)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "ziro-alerts/"+Version)
	req.Header.Set("X-Ziro-Event", a.Category)
	req.Header.Set("X-Ziro-Alert-Id", a.ID)
	req.Header.Set("X-Ziro-Timestamp", ts)
	req.Header.Set("X-Ziro-Signature", alertSign(e.Secret, ts, body))
	resp, err := alertHTTP.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("webhook %s answered %s", e.Name, resp.Status)
	}
	return nil
}

func newAlertID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// alertf raises an alert. It never blocks the caller on the network: the alert is spooled (unless
// the same category+title was raised within alertDedupe) and a background flush is started.
// Long-running daemons (Sentinel) also call flushAlerts periodically to retry.
func alertf(severity, category, title string, details map[string]any) {
	if _, ok := alertSeverities[severity]; !ok {
		severity = "medium"
	}
	host, _ := os.Hostname()
	a := Alert{ID: newAlertID(), Time: time.Now().UTC().Format(time.RFC3339), Host: host,
		Severity: severity, Category: category, Title: title, Details: details}
	if cfg, err := loadClusterConfig(); err == nil && cfg != nil {
		a.NodeID, a.ClusterID = cfg.NodeID, cfg.ClusterID
	}
	if err := spoolAlert(a, time.Now()); err != nil {
		fmt.Fprintf(os.Stderr, "[alerts] spool: %v\n", err)
		return
	}
	go flushAlerts()
}

// spoolAlert writes the alert for every endpoint that wants it. Returns nil (and spools nothing)
// when no endpoint is configured or the alert is a duplicate inside the dedupe window.
func spoolAlert(a Alert, now time.Time) error {
	cfg, err := loadAlertConfig()
	if err != nil {
		return err
	}
	var pending []string
	for _, e := range cfg.Endpoints {
		if e.wants(a) {
			pending = append(pending, e.Name)
		}
	}
	if len(pending) == 0 {
		return nil
	}
	if err := os.MkdirAll(alertSpoolDir, 0700); err != nil {
		return err
	}
	unlock, err := lockSpool()
	if err != nil {
		return err
	}
	defer unlock()
	if a.Category != "test" && seenRecently(a.Category+"|"+a.Title, now) {
		return nil
	}
	b, err := json.Marshal(spooled{Alert: a, Pending: pending, NextTry: now})
	if err != nil {
		return err
	}
	if err := writeFileAtomic(filepath.Join(alertSpoolDir, fmt.Sprintf("%020d-%s.json", now.UnixNano(), a.ID)), b, 0600); err != nil {
		return err
	}
	trimSpool()
	return nil
}

func lockSpool() (func(), error) {
	f, err := os.OpenFile(filepath.Join(alertSpoolDir, ".lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() { f.Close() }, nil
}

// seenRecently records key and reports whether it was already seen inside the dedupe window.
func seenRecently(key string, now time.Time) bool {
	path := filepath.Join(alertSpoolDir, ".recent")
	recent := map[string]time.Time{}
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &recent)
	}
	for k, t := range recent {
		if now.Sub(t) > alertDedupe {
			delete(recent, k)
		}
	}
	_, dup := recent[key]
	if !dup {
		recent[key] = now
	}
	if b, err := json.Marshal(recent); err == nil {
		_ = writeFileAtomic(path, b, 0600)
	}
	return dup
}

func spoolFiles() []string {
	ents, _ := os.ReadDir(alertSpoolDir)
	var files []string
	for _, e := range ents {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") && !strings.HasPrefix(e.Name(), ".") {
			files = append(files, filepath.Join(alertSpoolDir, e.Name()))
		}
	}
	sort.Strings(files) // names start with the timestamp: oldest first
	return files
}

func trimSpool() {
	files := spoolFiles()
	for i := 0; i < len(files)-alertSpoolMax; i++ {
		_ = os.Remove(files[i])
	}
}

var (
	flushMu    sync.Mutex
	flushAgain atomic.Bool
)

// flushAlerts delivers due spooled alerts, retrying failures with exponential backoff. If a flush
// is already running, it is asked to run once more instead: the running pass may have listed the
// spool before this caller's alert was written, and that alert must not wait for the next tick.
func flushAlerts() {
	if !flushMu.TryLock() {
		flushAgain.Store(true)
		return
	}
	defer flushMu.Unlock()
	for {
		flushAgain.Store(false)
		flushOnce()
		if !flushAgain.Load() {
			return
		}
	}
}

func flushOnce() {
	cfg, err := loadAlertConfig()
	if err != nil {
		return
	}
	byName := map[string]AlertEndpoint{}
	for _, e := range cfg.Endpoints {
		byName[e.Name] = e
	}
	now := time.Now()
	for _, path := range spoolFiles() {
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var s spooled
		if json.Unmarshal(b, &s) != nil {
			_ = os.Remove(path)
			continue
		}
		if now.Before(s.NextTry) {
			continue
		}
		var still []string
		for _, name := range s.Pending {
			e, ok := byName[name]
			if !ok {
				continue // endpoint removed since
			}
			if err := deliverAlert(e, s.Alert); err != nil {
				still = append(still, name)
				fmt.Fprintf(os.Stderr, "[alerts] %s: %v\n", name, err)
				continue
			}
			fmt.Printf("[alerts] delivered %s (%s) to %s\n", s.Alert.ID, s.Alert.Category, name)
		}
		if len(s.Pending) > 0 && len(still) == 0 && len(s.Pending) != countKnown(s.Pending, byName) {
			fmt.Fprintf(os.Stderr, "[alerts] dropped %s: endpoint removed\n", s.Alert.ID)
		}
		created, _ := time.Parse(time.RFC3339, s.Alert.Time)
		if len(still) == 0 || now.Sub(created) > alertGiveUp {
			_ = os.Remove(path)
			continue
		}
		s.Pending, s.Attempts = still, s.Attempts+1
		backoff := time.Duration(1<<min(s.Attempts, 12)) * 30 * time.Second
		s.NextTry = now.Add(min(backoff, alertMaxBackoff))
		if b, err := json.Marshal(s); err == nil {
			_ = writeFileAtomic(path, b, 0600)
		}
	}
}

func countKnown(names []string, byName map[string]AlertEndpoint) int {
	n := 0
	for _, name := range names {
		if _, ok := byName[name]; ok {
			n++
		}
	}
	return n
}

// ---- CLI ----

var (
	alertURL, alertMinSev, alertFormat string
	alertEvents                        []string
)

var securityAlertingCmd = &cobra.Command{
	Use:   "alerting",
	Short: "Push security alerts to webhooks (signed with HMAC-SHA256)",
}

var alertingAddCmd = &cobra.Command{
	Use:   "add <name>",
	Short: "Add a webhook endpoint (prints its signing secret once)",
	Example: `  ziroctl security alerting add soc --url https://hooks.example.com/ziro --min-severity high
  ziroctl security alerting add chat --url https://hooks.slack.com/services/... --format slack --events ban,threat`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		e, err := addAlertEndpoint(args[0], alertURL, alertMinSev, alertFormat, alertEvents)
		if err != nil {
			return err
		}
		fmt.Printf("Added alert endpoint %s -> %s\n", e.Name, e.URL)
		fmt.Printf("Signing secret (shown once; verify X-Ziro-Signature = HMAC-SHA256(secret, timestamp + \".\" + body)):\n  %s\n", e.Secret)
		return nil
	},
}

func addAlertEndpoint(name, rawURL, minSev, format string, events []string) (AlertEndpoint, error) {
	if !alertNameRe.MatchString(name) {
		return AlertEndpoint{}, fmt.Errorf("invalid name %q (a-z 0-9 _ -, max 32)", name)
	}
	if _, err := validateAlertURL(rawURL); err != nil {
		return AlertEndpoint{}, err
	}
	if minSev == "" {
		minSev = "medium"
	}
	if _, ok := alertSeverities[minSev]; !ok {
		return AlertEndpoint{}, fmt.Errorf("invalid severity %q (info, low, medium, high, critical)", minSev)
	}
	if format == "" {
		format = "json"
	}
	if format != "json" && format != "slack" {
		return AlertEndpoint{}, fmt.Errorf("invalid format %q (json, slack)", format)
	}
	for _, ev := range events {
		if !alertCategories[ev] {
			return AlertEndpoint{}, fmt.Errorf("unknown event %q (ban, threat, fim, canary, av, disk, service, module)", ev)
		}
	}
	cfg, err := loadAlertConfig()
	if err != nil {
		return AlertEndpoint{}, err
	}
	for _, e := range cfg.Endpoints {
		if e.Name == name {
			return AlertEndpoint{}, fmt.Errorf("endpoint %q already exists (remove it first)", name)
		}
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return AlertEndpoint{}, err
	}
	e := AlertEndpoint{Name: name, URL: rawURL, Secret: hex.EncodeToString(secret), MinSeverity: minSev,
		Events: events, Format: format, Created: time.Now().UTC().Format(time.RFC3339)}
	cfg.Endpoints = append(cfg.Endpoints, e)
	return e, saveAlertConfig(cfg)
}

func removeAlertEndpoint(name string) error {
	cfg, err := loadAlertConfig()
	if err != nil {
		return err
	}
	for i, e := range cfg.Endpoints {
		if e.Name == name {
			cfg.Endpoints = append(cfg.Endpoints[:i], cfg.Endpoints[i+1:]...)
			return saveAlertConfig(cfg)
		}
	}
	return fmt.Errorf("no alert endpoint %q", name)
}

// publicEndpoints hides secrets (list output and the API).
func publicEndpoints(cfg AlertConfig) []AlertEndpoint {
	out := make([]AlertEndpoint, 0, len(cfg.Endpoints))
	for _, e := range cfg.Endpoints {
		e.Secret = ""
		out = append(out, e)
	}
	return out
}

var alertingListCmd = &cobra.Command{
	Use:   "list",
	Short: "List alert endpoints and the delivery queue",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadAlertConfig()
		if err != nil {
			return err
		}
		if jsonOutput {
			return json.NewEncoder(os.Stdout).Encode(map[string]any{"endpoints": publicEndpoints(cfg), "queued": len(spoolFiles())})
		}
		fmt.Printf("%-16s %-10s %-6s %-24s %s\n", "NAME", "MIN-SEV", "FORMAT", "EVENTS", "URL")
		for _, e := range cfg.Endpoints {
			ev := strings.Join(e.Events, ",")
			if ev == "" {
				ev = "all"
			}
			fmt.Printf("%-16s %-10s %-6s %-24s %s\n", e.Name, e.MinSeverity, e.Format, ev, e.URL)
		}
		fmt.Printf("\nQueued for delivery: %d\n", len(spoolFiles()))
		return nil
	},
}

var alertingRemoveCmd = &cobra.Command{
	Use:   "remove <name>",
	Short: "Remove an alert endpoint",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := removeAlertEndpoint(args[0]); err != nil {
			return err
		}
		fmt.Printf("Removed alert endpoint %s\n", args[0])
		return nil
	},
}

var alertingTestCmd = &cobra.Command{
	Use:   "test [name]",
	Short: "Send a signed test alert now and report the result",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return testAlertEndpoints(args, os.Stdout)
	},
}

func testAlertEndpoints(names []string, w io.Writer) error {
	cfg, err := loadAlertConfig()
	if err != nil {
		return err
	}
	host, _ := os.Hostname()
	a := Alert{ID: newAlertID(), Time: time.Now().UTC().Format(time.RFC3339), Host: host, Severity: "info",
		Category: "test", Title: "Ziro-OS alerting test", Details: map[string]any{"version": Version}}
	sent := 0
	var failed []string
	for _, e := range cfg.Endpoints {
		if len(names) == 1 && e.Name != names[0] {
			continue
		}
		sent++
		if err := deliverAlert(e, a); err != nil {
			failed = append(failed, e.Name)
			fmt.Fprintf(w, "✗ %s: %v\n", e.Name, err)
			continue
		}
		fmt.Fprintf(w, "✓ %s: delivered\n", e.Name)
	}
	if sent == 0 {
		return errors.New("no matching alert endpoint")
	}
	if len(failed) > 0 {
		return fmt.Errorf("delivery failed: %s", strings.Join(failed, ", "))
	}
	return nil
}

func init() {
	alertingAddCmd.Flags().StringVar(&alertURL, "url", "", "Webhook URL (https://; http:// only to loopback)")
	alertingAddCmd.Flags().StringVar(&alertMinSev, "min-severity", "medium", "Lowest severity to send: info, low, medium, high, critical")
	alertingAddCmd.Flags().StringVar(&alertFormat, "format", "json", "Payload format: json or slack")
	alertingAddCmd.Flags().StringSliceVar(&alertEvents, "events", nil, "Categories to send (ban,threat,fim,canary,av,disk,service); default all")
	_ = alertingAddCmd.MarkFlagRequired("url")
	securityAlertingCmd.AddCommand(alertingAddCmd, alertingListCmd, alertingRemoveCmd, alertingTestCmd)
	securityCmd.AddCommand(securityAlertingCmd)
}
