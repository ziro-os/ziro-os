package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func TestDNSWildcardRecords(t *testing.T) {
	s := newTestServer(t, &DNSConfig{Records: []DNSRecord{
		{Name: "*.apps.example.com", Type: "A", Value: "10.0.0.5", TTL: 60},
		{Name: "api.apps.example.com", Type: "A", Value: "10.0.0.9", TTL: 60},
	}})
	ip := func(name string) [4]byte {
		m := decode(t, s.resolve(query(name, dnsmessage.TypeA, 1)))
		if len(m.Answers) != 1 {
			t.Fatalf("%s: %+v", name, m)
		}
		if got := m.Answers[0].Header.Name.String(); got != name {
			t.Errorf("%s answered as %s", name, got)
		}
		return m.Answers[0].Body.(*dnsmessage.AResource).A
	}
	if ip("web.apps.example.com.") != [4]byte{10, 0, 0, 5} || ip("a.b.apps.example.com.") != [4]byte{10, 0, 0, 5} {
		t.Error("the wildcard didn't answer")
	}
	if ip("api.apps.example.com.") != [4]byte{10, 0, 0, 9} {
		t.Error("an exact record must win over the wildcard")
	}
	if _, ok := s.localAnswer(decode(t, query("apps.example.com.", dnsmessage.TypeA, 2))); ok {
		t.Error("the wildcard answered for the domain itself")
	}
	if _, ok := s.localAnswer(decode(t, query("web.other.com.", dnsmessage.TypeA, 3))); ok {
		t.Error("the wildcard answered for another domain")
	}
	if _, _, err := parseRecord(DNSRecord{Name: "*.*.x.com", Type: "A", Value: "10.0.0.1"}); err == nil {
		t.Error("a wildcard in the middle was accepted")
	}
}

func TestGatewayDomain(t *testing.T) {
	d := GatewayDomain{Name: "apps.example.com"}
	if d.Host("web") != "web.apps.example.com" || d.TLS() != "auto" || (GatewayDomain{}).Host("web") != "" {
		t.Errorf("public domain: %s %s", d.Host("web"), d.TLS())
	}
	for _, n := range []string{"ziro-test.local", "apps.internal", "apps.lan", "intranet", "x.home.arpa"} {
		if (GatewayDomain{Name: n}).TLS() != "internal" {
			t.Errorf("%s should use the internal CA", n)
		}
	}
}

// Setting a domain on a standalone host stores it, adds the wildcard record, makes deployments
// without a host of their own follow it, and removing it undoes the lot.
func TestSetGatewayDomainStandalone(t *testing.T) {
	oldGW, oldDNS, oldCl, oldAddrs := gatewayLocalDir, dnsConfigPath, clusterDir, hostAddrs
	gatewayLocalDir, dnsConfigPath, clusterDir = t.TempDir(), filepath.Join(t.TempDir(), "dns.json"), t.TempDir()
	hostAddrs = func() []HostAddress { return []HostAddress{{IP: "203.0.113.7", Iface: "eth0", Role: "primary"}} }
	defer func() { gatewayLocalDir, dnsConfigPath, clusterDir, hostAddrs = oldGW, oldDNS, oldCl, oldAddrs }()

	app := &Deployment{Name: "site1"}
	if h, _ := exposeFor(app); h != "" || deploymentURL(app) != "" {
		t.Fatalf("no domain, no port: host %q url %q", h, deploymentURL(app))
	}
	if u := deploymentURL(&Deployment{Name: "x", Publish: 20001}); u != "http://127.0.0.1:20001" {
		t.Errorf("single host url %q", u)
	}

	if _, err := setGatewayDomain("*.example.com"); err == nil {
		t.Error("a wildcard domain was accepted")
	}
	info, err := setGatewayDomain("Apps.Example.com.")
	if err != nil {
		t.Fatal(err)
	}
	if info.Domain != "apps.example.com" || info.TLS != "auto" || len(info.Records) != 1 || info.Records[0] != "*.apps.example.com. A 203.0.113.7" {
		t.Fatalf("info %+v", info)
	}
	cfg, _ := loadDNSConfig()
	if len(cfg.Records) != 1 || cfg.Records[0].Name != "*.apps.example.com" || cfg.Records[0].Value != "203.0.113.7" {
		t.Fatalf("dns records %+v", cfg.Records)
	}
	if h, tls := exposeFor(app); h != "site1.apps.example.com" || tls != "auto" || deploymentURL(app) != "https://site1.apps.example.com" {
		t.Errorf("app host %q (%s) url %q", h, tls, deploymentURL(app))
	}
	own := &Deployment{Name: "site1", Expose: "shop.example.org", ExposeTLS: "off"}
	if h, tls := exposeFor(own); h != "shop.example.org" || tls != "off" || deploymentURL(own) != "http://shop.example.org" {
		t.Errorf("an explicit --expose must win: %q %q", h, tls)
	}

	// Changing the domain moves the record; removing it clears everything.
	if _, err := setGatewayDomain("apps.lan"); err != nil {
		t.Fatal(err)
	}
	if cfg, _ = loadDNSConfig(); len(cfg.Records) != 1 || cfg.Records[0].Name != "*.apps.lan" {
		t.Fatalf("after the change %+v", cfg.Records)
	}
	if _, tls := exposeFor(app); tls != "internal" {
		t.Errorf("a .lan domain should use the internal CA, got %s", tls)
	}
	if _, err := setGatewayDomain(""); err != nil {
		t.Fatal(err)
	}
	if cfg, _ = loadDNSConfig(); len(cfg.Records) != 0 || gatewayDomain().Name != "" {
		t.Errorf("not removed: %+v %q", cfg.Records, gatewayDomain().Name)
	}
	_ = os.Remove(dnsConfigPath)
}

// On a cluster the domain lives in the cluster state, the wildcard record points at the gateway
// nodes and goes out as a cluster DNS record, and a deployment with no host follows the domain.
func TestSetGatewayDomainCluster(t *testing.T) {
	oldCl := clusterDir
	clusterDir = t.TempDir()
	defer func() { clusterDir = oldCl }()
	if err := os.WriteFile(clusterConfigPath(), []byte(`{"role":"master","node_id":"m"}`), 0600); err != nil {
		t.Fatal(err)
	}
	st := &ClusterState{Nodes: []ClusterNode{
		{ID: "m", Role: "master", IP: "10.0.0.1"},
		{ID: "edge1", Role: "worker", IP: "10.0.0.8", Gateway: true},
		{ID: "edge2", Role: "worker", IP: "10.0.0.9", Gateway: true},
	}}
	if err := saveStateFiles(clusterDir, st); err != nil {
		t.Fatal(err)
	}
	info, err := setGatewayDomain("apps.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(info.Addresses) != 2 || len(info.Records) != 2 {
		t.Fatalf("info %+v", info)
	}
	got, _ := readState()
	if got.GatewayDomain.Name != "apps.example.com" || len(got.DNSRecords) != 2 || got.DNSRecords[0].Name != "*.apps.example.com" {
		t.Fatalf("state: %q %+v", got.GatewayDomain.Name, got.DNSRecords)
	}
	if _, err := setGatewayDomain(""); err != nil {
		t.Fatal(err)
	}
	if got, _ = readState(); got.GatewayDomain.Name != "" || len(got.DNSRecords) != 0 {
		t.Errorf("not removed: %+v", got.DNSRecords)
	}
}
