package cmd

import (
	"context"
	"errors"
	sdkapi "github.com/ziro-os/ziro-os/sdk/api"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ziro-os/ziro-os/sdk/client"
	"github.com/ziro-os/ziro-os/sdk/schema"
)

// The SDK client against the real API routes: request and response shapes agree.
func TestSDKClientAgainstServer(t *testing.T) {
	stubApps(t)
	dir := t.TempDir()
	oldDir, oldSync := gatewayLocalDir, syncLocalGatewayService
	gatewayLocalDir = dir
	syncLocalGatewayService = func(bool) error { return nil }
	defer func() { gatewayLocalDir, syncLocalGatewayService = oldDir, oldSync }()

	api := newAPIHarness(t)
	srv := httptest.NewServer(api.h)
	defer srv.Close()
	c, err := client.New(srv.URL, api.tok["admin"])
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	route := schema.GatewayRoute{Name: "api", Hosts: []string{"api.test"}, To: []schema.GatewayUpstream{{Address: "10.0.0.5:9000", Weight: 3}},
		LB: "least_conn", Health: &schema.GatewayHealth{Path: "/healthz"}}
	if _, err := c.PutGatewayRoute(ctx, route); err != nil {
		t.Fatal(err)
	}
	got, err := c.GatewayRoute(ctx, "api")
	if err != nil || got.LB != "least_conn" || len(got.Upstreams) != 1 || got.Upstreams[0] != "10.0.0.5:9000" {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	routes, err := c.GatewayRoutes(ctx)
	if err != nil || len(routes) != 1 {
		t.Fatalf("list: %v %v", routes, err)
	}
	if err := c.DeleteGatewayRoute(ctx, "api"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GatewayRoute(ctx, "api"); !client.IsNotFound(err) {
		t.Fatalf("deleted route: %v", err)
	}
	if apps, err := c.Apps(ctx); err != nil || len(apps) != 0 {
		t.Fatalf("apps: %v %v", apps, err)
	}
}

// The client against the real server: token lifecycle, role errors, the audit trail and the
// live event stream.
func TestSDKClientOps(t *testing.T) {
	api := newAPIHarness(t)
	srv := httptest.NewServer(api.h)
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	admin, _ := client.New(srv.URL, api.tok["admin"])
	viewer, _ := client.New(srv.URL, api.tok["viewer"])

	events := make(chan string, 8)
	go func() {
		_ = admin.Events(ctx, func(r sdkapi.AuditRecord) error { events <- r.Action + " " + r.Target; return nil })
	}()
	time.Sleep(1500 * time.Millisecond) // the stream starts at the current end of the log

	tok, err := admin.CreateToken(ctx, "ci", "operator", "1h")
	if err != nil || tok.Secret == "" || tok.Role != "operator" || tok.Expires == "" {
		t.Fatalf("create token: %+v %v", tok, err)
	}
	if _, err := viewer.CreateToken(ctx, "x", "admin", ""); !client.IsForbidden(err) {
		t.Fatalf("viewer created a token: %v", err)
	}
	ts, err := admin.Tokens(ctx)
	if err != nil || len(ts) != 4 {
		t.Fatalf("tokens: %+v %v", ts, err)
	}
	for _, tk := range ts {
		if tk.Secret != "" {
			t.Fatal("a token listing leaked a secret")
		}
	}
	if _, err := admin.RevokeToken(ctx, "ci"); err != nil {
		t.Fatal(err)
	}
	var ce *client.Error
	if _, err := admin.RevokeToken(ctx, "ci"); !errors.As(err, &ce) || ce.Code != "not_found" {
		t.Fatalf("revoking twice: %v", err)
	}
	recs, err := admin.Audit(ctx, 10, "")
	if err != nil || len(recs) < 2 {
		t.Fatalf("audit: %+v %v", recs, err)
	}
	select {
	case ev := <-events:
		if !strings.Contains(ev, "POST /api/v1/tokens") {
			t.Errorf("first event %q", ev)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no event streamed")
	}
}
