package cmd

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

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

	mux := http.NewServeMux()
	registerAPIRoutes(mux, func(_ bool, h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			h(w, r.WithContext(context.WithValue(r.Context(), apiRoleKey{}, "admin")))
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c, err := client.New(srv.URL, "t")
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
