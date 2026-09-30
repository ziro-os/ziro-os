package cmd

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestAlertURLValidation(t *testing.T) {
	for _, ok := range []string{"https://hooks.example.com/x", "http://127.0.0.1:9000/h", "http://localhost/h", "http://[::1]:8/h"} {
		if _, err := validateAlertURL(ok); err != nil {
			t.Errorf("%s rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"http://hooks.example.com/x", "ftp://x", "https://user:pw@x/", "notaurl", "https:///nohost"} {
		if _, err := validateAlertURL(bad); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

func TestAlertEndpointFilter(t *testing.T) {
	e := AlertEndpoint{MinSeverity: "high", Events: []string{"ban"}}
	if !e.wants(Alert{Severity: "critical", Category: "ban"}) || e.wants(Alert{Severity: "medium", Category: "ban"}) ||
		e.wants(Alert{Severity: "critical", Category: "fim"}) || !e.wants(Alert{Severity: "info", Category: "test"}) {
		t.Fatal("severity/category filter wrong")
	}
}

// A receiver verifies the signature exactly as documented: HMAC-SHA256(secret, ts + "." + body).
func TestAlertDeliverySignedAndRetried(t *testing.T) {
	alertConfigPath = filepath.Join(t.TempDir(), "alerting.json")
	alertSpoolDir = t.TempDir()
	clusterDir = t.TempDir()

	var calls atomic.Int32
	var got Alert
	var sigOK bool
	var secret string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable) // first attempt fails: must be retried
			return
		}
		ts := r.Header.Get("X-Ziro-Timestamp")
		sigOK = r.Header.Get("X-Ziro-Signature") == alertSign(secret, ts, body) && r.Header.Get("X-Ziro-Event") == "ban"
		_ = json.Unmarshal(body, &got)
	}))
	defer srv.Close()

	e, err := addAlertEndpoint("soc", srv.URL+"/hook", "medium", "json", []string{"ban"})
	if err != nil {
		t.Fatal(err)
	}
	secret = e.Secret
	if len(secret) != 64 {
		t.Fatalf("secret %q", secret)
	}
	if _, err := addAlertEndpoint("soc", srv.URL, "", "", nil); err == nil {
		t.Fatal("duplicate endpoint name accepted")
	}

	a := Alert{ID: "a1", Time: time.Now().UTC().Format(time.RFC3339), Severity: "high", Category: "ban",
		Title: "SSH brute force from 203.0.113.5 banned", Details: map[string]any{"ip": "203.0.113.5"}}
	if err := spoolAlert(a, time.Now()); err != nil {
		t.Fatal(err)
	}
	// Same category+title inside the window is deduplicated; a filtered-out category is not spooled.
	spoolAlert(Alert{ID: "a2", Time: a.Time, Severity: "high", Category: "ban", Title: a.Title}, time.Now())
	spoolAlert(Alert{ID: "a3", Time: a.Time, Severity: "high", Category: "fim", Title: "x"}, time.Now())
	if n := len(spoolFiles()); n != 1 {
		t.Fatalf("spooled %d alerts, want 1", n)
	}

	flushAlerts() // 503: stays queued with backoff
	if n := len(spoolFiles()); n != 1 || calls.Load() != 1 {
		t.Fatalf("after failure: %d queued, %d calls", n, calls.Load())
	}
	flushAlerts() // not due yet
	if calls.Load() != 1 {
		t.Fatal("retried before the backoff elapsed")
	}
	// Make it due and retry.
	path := spoolFiles()[0]
	var s spooled
	b, _ := os.ReadFile(path)
	json.Unmarshal(b, &s)
	s.NextTry = time.Now().Add(-time.Second)
	b, _ = json.Marshal(s)
	writeFileAtomic(path, b, 0600)
	flushAlerts()
	if len(spoolFiles()) != 0 || !sigOK || got.ID != "a1" || got.Details["ip"] != "203.0.113.5" {
		t.Fatalf("delivery: queued=%d sigOK=%v got=%+v", len(spoolFiles()), sigOK, got)
	}

	// Listing never exposes secrets.
	cfg, _ := loadAlertConfig()
	for _, pe := range publicEndpoints(cfg) {
		if pe.Secret != "" {
			t.Fatal("secret leaked by publicEndpoints")
		}
	}
}

func TestAlertRedirectNotFollowed(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("signed alert followed a redirect")
	}))
	defer target.Close()
	redir := httptest.NewServer(http.RedirectHandler(target.URL, http.StatusTemporaryRedirect))
	defer redir.Close()
	err := deliverAlert(AlertEndpoint{Name: "r", URL: redir.URL, Secret: "s"}, Alert{ID: "x", Category: "test"})
	if err == nil || !strings.Contains(err.Error(), "307") {
		t.Fatalf("redirect must fail delivery, got %v", err)
	}
}

func TestAlertSlackFormat(t *testing.T) {
	b, err := alertBody(AlertEndpoint{Format: "slack"}, Alert{Severity: "high", Title: "t", Host: "h", Category: "ban",
		Details: map[string]any{"ip": "203.0.113.5"}})
	var m map[string]string
	if err != nil || json.Unmarshal(b, &m) != nil || !strings.Contains(m["text"], "*[HIGH] t*") || !strings.Contains(m["text"], "203.0.113.5") {
		t.Fatalf("slack body %s", b)
	}
}
