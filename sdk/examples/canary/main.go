// canary shifts traffic from one app to another in steps, watching the gateway for errors and
// rolling back when the new version fails its health checks.
//
//	ZIRO_URL=https://10.0.0.5:8443 ZIRO_TOKEN=... go run ./examples/canary -host www.example.com -from web -to web-next
//
// A server certificate from a private CA is trusted through SSL_CERT_FILE (or the system store).
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/ziro-os/ziro-os/sdk/client"
	"github.com/ziro-os/ziro-os/sdk/schema"
)

func main() {
	host := flag.String("host", "", "hostname the route serves")
	from := flag.String("from", "", "current app")
	to := flag.String("to", "", "new app")
	step := flag.Duration("step", time.Minute, "time between shifts")
	flag.Parse()
	if *host == "" || *from == "" || *to == "" {
		flag.Usage()
		os.Exit(2)
	}
	c, err := client.New(os.Getenv("ZIRO_URL"), os.Getenv("ZIRO_TOKEN"))
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()
	route := func(newWeight int) schema.GatewayRoute {
		return schema.GatewayRoute{
			Name: *from, Hosts: []string{*host}, LB: "round_robin",
			To:     []schema.GatewayUpstream{{App: *from, Weight: 100 - newWeight}, {App: *to, Weight: max(newWeight, 1)}},
			Health: &schema.GatewayHealth{Path: "/healthz", Interval: "5s"},
		}
	}
	for _, w := range []int{1, 10, 25, 50, 100} {
		r := route(w)
		if w == 100 {
			r.To = []schema.GatewayUpstream{{App: *to}}
		}
		if _, err := c.PutGatewayRoute(ctx, r); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%d%% of %s -> %s\n", w, *host, *to)
		time.Sleep(*step)
		st, err := c.GatewayStatus(ctx)
		if err != nil {
			log.Fatal(err)
		}
		for _, rs := range st.Routes {
			if rs.Name != *from {
				continue
			}
			for _, u := range rs.Upstreams {
				if !u.Healthy {
					fmt.Printf("%s is unhealthy: rolling back\n", u.Addr)
					back := route(0)
					back.To = []schema.GatewayUpstream{{App: *from}} // all traffic back to the current app
					if _, err := c.PutGatewayRoute(ctx, back); err != nil {
						log.Fatal(err)
					}
					os.Exit(1)
				}
			}
		}
	}
	fmt.Println("done")
}
