package cmd

import (
	"net/http"
	"regexp"
	"strings"
	"testing"
)

func TestPGDashboardIsServedWithStrictHeaders(t *testing.T) {
	h := newAPIHarness(t, registerPGUIRoutes)
	for path, typ := range map[string]string{
		"/ui/":           "text/html; charset=utf-8",
		"/ui/index.html": "text/html; charset=utf-8",
		"/ui/app.js":     "text/javascript; charset=utf-8",
		"/ui/app.css":    "text/css; charset=utf-8",
	} {
		rec := h.req("", "GET", path, "") // no token: the page has no data
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: %d", path, rec.Code)
		}
		hd := rec.Header()
		if hd.Get("Content-Type") != typ || hd.Get("X-Content-Type-Options") != "nosniff" || hd.Get("X-Frame-Options") != "DENY" ||
			hd.Get("Referrer-Policy") != "no-referrer" {
			t.Fatalf("%s headers: %v", path, hd)
		}
		csp := hd.Get("Content-Security-Policy")
		for _, want := range []string{"default-src 'none'", "script-src 'self'", "connect-src 'self'", "frame-ancestors 'none'"} {
			if !strings.Contains(csp, want) {
				t.Errorf("%s: CSP lacks %q: %s", path, want, csp)
			}
		}
		if strings.Contains(csp, "unsafe") {
			t.Fatalf("%s: CSP allows unsafe sources: %s", path, csp)
		}
	}
	for _, path := range []string{"/ui/../api_routes.go", "/ui/.hidden.js", "/ui/x/app.js", "/ui/app.go", "/ui/nope.js"} {
		if c := h.code("", "GET", path, ""); c != http.StatusNotFound && (c < 300 || c > 399) { // ".." is cleaned by a redirect
			t.Errorf("%s: %d", path, c)
		}
	}
	if c := h.code("", "POST", "/ui/app.js", ""); c == http.StatusOK {
		t.Fatal("POST serves the page")
	}
}

func TestPGDashboardHasNoInlineCodeOrRemoteSources(t *testing.T) {
	for _, f := range []string{"ui/index.html", "ui/app.js", "ui/app.css"} {
		b, err := pgUIFiles.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		s := string(b)
		if regexp.MustCompile(`https?://`).MatchString(strings.ReplaceAll(s, "http://www.w3.org/2000/svg", "")) {
			t.Errorf("%s loads or links something remote", f)
		}
		if f == "ui/index.html" {
			if regexp.MustCompile(`<script>|<style>| on[a-z]+="|style="`).MatchString(s) {
				t.Errorf("%s has inline script or style (the CSP refuses it)", f)
			}
		}
		if f == "ui/app.js" {
			for _, bad := range []string{"innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", "localStorage"} {
				if strings.Contains(s, bad) {
					t.Errorf("app.js uses %s", bad)
				}
			}
		}
	}
}

func TestPGDashboardDataNeedsAToken(t *testing.T) {
	h := newAPIHarness(t)
	for _, path := range []string{"/api/v1/pg-overview", "/api/v1/pg/shop/roles", "/api/v1/pg/shop/spec", "/api/v1/pg/shop/events"} {
		if c := h.code("", "GET", path, ""); c != http.StatusUnauthorized {
			t.Errorf("%s without a token: %d", path, c)
		}
	}
	if c := h.code("viewer", "POST", "/api/v1/pg-apply", `{"spec":{}}`); c != http.StatusForbidden {
		t.Errorf("a viewer applies: %d", c)
	}
	if c := h.code("viewer", "POST", "/api/v1/pg-plan", `{"spec":{}}`); c != http.StatusForbidden {
		t.Errorf("a viewer plans: %d", c)
	}
}
