package schema

import (
	"slices"
	"strings"
	"testing"
)

func TestStack(t *testing.T) {
	s, err := ParseStack([]byte(`
stack: shop
version: 1
apps:
  web: {app: ./apps/web/app.yaml, expose: shop.example.com, depends_on: [api]}
  api: {app: "myapi:2", depends_on: [db, cache], resources: {memory: 512Mi}}
  db: {app: "postgres:18", set: {database: shop}}
  cache: {app: valkey}
`))
	if err != nil {
		t.Fatal(err)
	}
	order, _ := s.Order()
	if !slices.Equal(order, []string{"cache", "db", "api", "web"}) || s.Instance("db") != "shop-db" {
		t.Errorf("order %v", order)
	}
	for name, bad := range map[string]string{
		"cycle":         "stack: s\nversion: 1\napps: {a: {app: x, depends_on: [b]}, b: {app: y, depends_on: [a]}}\n",
		"unknown dep":   "stack: s\nversion: 1\napps: {a: {app: x, depends_on: [zz]}}\n",
		"path escape":   "stack: s\nversion: 1\napps: {a: {app: ../../etc/app.yaml}}\n",
		"not a ref":     "stack: s\nversion: 1\napps: {a: {app: 'x; rm -rf /'}}\n",
		"no version":    "stack: s\napps: {a: {app: x}}\n",
		"bad setting":   "stack: s\nversion: 1\napps: {a: {app: x, set: {'bad key': v}}}\n",
		"unknown field": "stack: s\nversion: 1\napps: {a: {app: x, env: {A: b}}}\n",
	} {
		if _, err := ParseStack([]byte(bad)); err == nil {
			t.Errorf("%s accepted", name)
		} else if name == "cycle" && !strings.Contains(err.Error(), "cycle") {
			t.Errorf("cycle error: %v", err)
		}
	}
}

func TestHostConfig(t *testing.T) {
	ok := `
host:
  version: 1
  hostname: web-1
  ssh: {keys: ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl ops@example"], import: [gh:alice]}
  firewall: {allow: [80/tcp, "443"]}
  packages: [htop]
  plugins: [{name: clamav, set: {onaccess: /srv}}]
  stacks: [./shop.yaml]
  update: {auto: true}
  network: {interfaces: [{name: eth0, mode: dhcp}]}
  cluster: {join: {address: "10.0.0.1:7443", token_file: /run/secrets/join}}
`
	c, err := ParseHostConfig([]byte(ok))
	if err != nil || c.Host.Hostname != "web-1" || len(c.Host.Network) == 0 {
		t.Fatalf("%+v %v", c, err)
	}
	for name, bad := range map[string]string{
		"fqdn hostname": "host: {version: 1, hostname: a.b}\n",
		"bad key":       "host: {version: 1, ssh: {keys: [not-a-key]}}\n",
		"bad port":      "host: {version: 1, firewall: {allow: [http]}}\n",
		"abs stack":     "host: {version: 1, stacks: [/etc/x.yaml]}\n",
		"token inline":  "host: {version: 1, cluster: {join: {address: 'a:1', token: x}}}\n",
		"unknown":       "host: {version: 1, users: []}\n",
	} {
		if _, err := ParseHostConfig([]byte(bad)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestStackLinks(t *testing.T) {
	ok := "stack: s\nversion: 1\napps:\n  db: {app: postgres}\n  web: {app: x, depends_on: [db], links: {DATABASE_URL: db.url}}\n"
	if _, err := ParseStack([]byte(ok)); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]string{
		"not a dependency": "stack: s\nversion: 1\napps:\n  db: {app: postgres}\n  web: {app: x, links: {DATABASE_URL: db.url}}\n",
		"no output":        "stack: s\nversion: 1\napps:\n  db: {app: postgres}\n  web: {app: x, depends_on: [db], links: {DATABASE_URL: db}}\n",
		"reserved name":    "stack: s\nversion: 1\napps:\n  db: {app: postgres}\n  web: {app: x, depends_on: [db], links: {ZIRO_X: db.url}}\n",
	} {
		if _, err := ParseStack([]byte(bad)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
