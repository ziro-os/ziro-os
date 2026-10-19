package cmd

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sdkapi "github.com/ziro-os/ziro-os/sdk/api"
	"github.com/ziro-os/ziro-os/sdk/schema"
)

// stubPreviews makes the gateway a map of routes.
func stubPreviews(t *testing.T, m *sandboxManager, domain string) map[string]GatewayRoute {
	routes := map[string]GatewayRoute{}
	oldD, oldP, oldR := previewDomain, previewPutRoute, previewDelRoute
	previewDomain = func() schema.GatewayDomain { return schema.GatewayDomain{Name: domain} }
	previewPutRoute = func(r GatewayRoute) error { routes[r.Name] = r; return nil }
	previewDelRoute = func(name string) error { delete(routes, name); return nil }
	t.Cleanup(func() { previewDomain, previewPutRoute, previewDelRoute = oldD, oldP, oldR })
	m.previewKey, m.previewPort = []byte("0123456789abcdef0123456789abcdef"), 22997
	return routes
}

func TestSandboxPreviews(t *testing.T) {
	m, _, _ := stubSandboxes(t)
	m.now = time.Now
	routes := stubPreviews(t, m, "apps.example.com")
	plain, _ := m.create(context.Background(), schema.SandboxSpec{Image: "a"}, alice)
	if _, err := m.expose(plain.ID, alice, sdkapi.SandboxPreviewRequest{Port: 3000}); err == nil {
		t.Error("a sandbox without a network published a port")
	}
	sb, err := m.create(context.Background(), schema.SandboxSpec{Image: "a", Network: &schema.SandboxNetwork{Mode: "open"}}, alice)
	if err != nil {
		t.Fatal(err)
	}
	// The "sandbox" is a local web server that echoes what it got.
	got := make(chan *http.Request, 8)
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r
		io.WriteString(w, "hello from the sandbox")
	}))
	defer app.Close()
	host, port, _ := net.SplitHostPort(strings.TrimPrefix(app.URL, "http://"))
	m.st.update(sb.ID, func(x *sdkapi.Sandbox) { x.IP = host })
	p := 0
	for _, c := range port {
		p = p*10 + int(c-'0')
	}

	pv, err := m.expose(sb.ID, alice, sdkapi.SandboxPreviewRequest{Port: p})
	if err != nil {
		t.Fatal(err)
	}
	wantHost := port + "-" + sb.ID + ".apps.example.com"
	r := routes[previewRoute(sb.ID, p)]
	if pv.URL != "https://"+wantHost+"/" || pv.Token == "" || len(r.Hosts) != 1 || r.Hosts[0] != wantHost || r.To[0].Address != "127.0.0.1:22997" || r.TLS != "auto" {
		t.Fatalf("preview %+v route %+v", pv, r)
	}
	if _, err := m.expose(sb.ID, bob, sdkapi.SandboxPreviewRequest{Port: p}); err == nil {
		t.Error("bob published alice's port")
	}
	h := m.previewHandler()
	do := func(path string, hdr map[string]string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "http://"+wantHost+path, nil)
		for k, v := range hdr {
			if k == "Host" {
				req.Host = v
			} else {
				req.Header.Set(k, v)
			}
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}
	if w := do("/", nil); w.Code != 401 {
		t.Fatalf("no token: %d", w.Code)
	}
	if w := do("/", map[string]string{previewHeader: "bogus"}); w.Code != 401 {
		t.Fatalf("bad token: %d", w.Code)
	}
	// A link with the token: a cookie and a redirect without it.
	w := do("/app?x=1&ziro_token="+pv.Token, nil)
	ck := w.Result().Cookies()
	if w.Code != 303 || w.Header().Get("Location") != "/app?x=1" || len(ck) != 1 || !ck[0].HttpOnly || !ck[0].Secure || ck[0].Name != previewCookie {
		t.Fatalf("token link: %d %v %v", w.Code, w.Header(), ck)
	}
	w = do("/app?x=1", map[string]string{"Cookie": previewCookie + "=" + pv.Token + "; theme=dark"})
	if w.Code != 200 || w.Body.String() != "hello from the sandbox" {
		t.Fatalf("with cookie: %d %s", w.Code, w.Body)
	}
	in := <-got
	if strings.Contains(in.Header.Get("Cookie"), pv.Token) || !strings.Contains(in.Header.Get("Cookie"), "theme=dark") || in.Host != wantHost {
		t.Errorf("the sandbox saw cookie %q host %q", in.Header.Get("Cookie"), in.Host)
	}
	if w := do("/", map[string]string{previewHeader: pv.Token}); w.Code != 200 {
		t.Errorf("header token: %d", w.Code)
	}
	if in := <-got; in.Header.Get(previewHeader) != "" {
		t.Error("the token header reached the sandbox")
	}
	// Another port or sandbox: the token doesn't carry over.
	if w := do("/", map[string]string{"Host": "1-" + sb.ID + ".apps.example.com", previewHeader: pv.Token}); w.Code != 404 {
		t.Errorf("unpublished port: %d", w.Code)
	}
	// Re-publishing revokes old tokens; a public preview needs none.
	if err := m.unexpose(sb.ID, alice, p); err != nil {
		t.Fatal(err)
	}
	if _, ok := routes[previewRoute(sb.ID, p)]; ok {
		t.Error("route kept")
	}
	if _, err := m.expose(sb.ID, alice, sdkapi.SandboxPreviewRequest{Port: p, Public: true}); err != nil {
		t.Fatal(err)
	}
	if w := do("/", map[string]string{previewHeader: pv.Token}); w.Code != 200 {
		t.Errorf("public: %d", w.Code)
	}
	<-got
	m.unexpose(sb.ID, alice, p)
	pv2, _ := m.expose(sb.ID, alice, sdkapi.SandboxPreviewRequest{Port: p})
	if _, ok := previewTokenOK(m.previewKey, sb.ID, stripTok(pv2), pv.Token, time.Now()); ok {
		t.Error("a token of the old preview still works")
	}
	// Expired tokens; a paused sandbox.
	short, _ := m.expose(sb.ID, alice, sdkapi.SandboxPreviewRequest{Port: p, TTL: "1m"})
	if _, ok := previewTokenOK(m.previewKey, sb.ID, stripTok(pv2), short.Token, time.Now().Add(2*time.Minute)); ok {
		t.Error("expired token accepted")
	}
	m.st.update(sb.ID, func(x *sdkapi.Sandbox) { x.State = "paused" })
	if w := do("/", map[string]string{previewHeader: short.Token}); w.Code != 503 {
		t.Errorf("paused: %d", w.Code)
	}
	// Deleting the sandbox removes its routes.
	if err := m.remove(sb.ID, alice); err != nil {
		t.Fatal(err)
	}
	if len(routes) != 0 {
		t.Errorf("routes left: %v", routes)
	}
	// No domain, no previews.
	previewDomain = func() schema.GatewayDomain { return schema.GatewayDomain{} }
	sb3, _ := m.create(context.Background(), schema.SandboxSpec{Image: "a", Network: &schema.SandboxNetwork{Mode: "open"}}, alice)
	if _, err := m.expose(sb3.ID, alice, sdkapi.SandboxPreviewRequest{Port: 80}); err == nil || !strings.Contains(err.Error(), "gateway domain") {
		t.Errorf("no domain: %v", err)
	}
}

func stripTok(p sdkapi.SandboxPreview) sdkapi.SandboxPreview {
	p.Token, p.TokenURL = "", ""
	return p
}
