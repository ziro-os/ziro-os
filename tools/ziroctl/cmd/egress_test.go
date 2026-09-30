package cmd

import (
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestValidateEgress(t *testing.T) {
	if err := validateEgress([]string{"api.stripe.com", "10.0.0.0/8", "192.0.2.10"}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]string{{"2001:db8::/32"}, {"not a domain"}, {"x;drop"}, make([]string, 65)} {
		if validateEgress(bad) == nil {
			t.Errorf("accepted %v", bad)
		}
	}
	app := &ClusteredApp{Name: "web", Image: "nginx", Replicas: 1, Egress: []string{"api.stripe.com"}}
	if err := validateApp(app, nil); err == nil || !strings.Contains(err.Error(), "pod network") {
		t.Fatalf("egress without the pod network: %v", err)
	}
}

func TestEgressScript(t *testing.T) {
	egress := map[string][]string{"web": {"api.stripe.com", "10.20.0.0/16", "192.0.2.10"}, "idle": {"example.com"}}
	as := []Assignment{{App: "web", IP: "10.201.1.5"}, {App: "web", IP: "10.201.1.6"}, {App: "other", IP: "10.201.1.9"}}
	apps := egressApps(egress, as)
	if len(apps) != 1 || apps[0].App != "web" { // "idle" has no pod on this node
		t.Fatalf("%+v", apps)
	}
	s, err := buildEgressScript(apps, "10.201.0.0/16", "10.200.0.0/16")
	if err != nil {
		t.Fatal(err)
	}
	set := egressSet("web")
	for _, want := range []string{
		"table inet ziro_egress {", "set " + set + "d { type ipv4_addr; flags timeout; }",
		"flush chain inet ziro_egress forward", "add rule inet ziro_egress forward ct state established,related accept",
		"add element inet ziro_egress " + set + "p { 10.201.1.5, 10.201.1.6 }",
		"add element inet ziro_egress " + set + "s { 10.20.0.0/16, 192.0.2.10/32 }",
		"ip saddr @" + set + "p ip daddr { 10.201.0.0/16, 10.200.0.0/16 } accept",
		"ip saddr @" + set + "p counter drop comment \"egress web\"",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q\n%s", want, s)
		}
	}
	if strings.Contains(s, "flush set inet ziro_egress "+set+"d") || strings.Contains(s, "delete table") {
		t.Error("learned addresses must survive re-applies")
	}
	if s, _ := buildEgressScript(nil, "", ""); !strings.Contains(s, "delete table inet ziro_egress") {
		t.Error("no egress apps: the table goes away")
	}
	if _, err := buildEgressScript([]egressApp{{App: "x", Set: "e1", PodIPs: []string{"10.0.0.1; drop"}}}, "", ""); err == nil {
		t.Error("unvalidated pod IP reached the script")
	}
}

func TestEgressLearner(t *testing.T) {
	type added struct {
		set string
		ips []string
		ttl time.Duration
	}
	var got []added
	l := &egressLearner{add: func(set string, ips []string, ttl time.Duration) error {
		got = append(got, added{set, ips, ttl})
		return nil
	}}
	l.set(map[string][]string{"web": {"stripe.com", "10.0.0.0/8"}}, []Assignment{{App: "web", IP: "10.201.1.5"}})
	answer := func(name string, ttl uint32) []byte {
		m := dnsmessage.Message{Header: dnsmessage.Header{Response: true},
			Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
			Answers: []dnsmessage.Resource{
				{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: ttl},
					Body: &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName("edge.cdn.example.")}},
				{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("edge.cdn.example."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: ttl},
					Body: &dnsmessage.AResource{A: [4]byte{203, 0, 113, 7}}}}}
		b, _ := m.Pack()
		return b
	}
	l.learn("10.201.1.5", answer("api.stripe.com.", 30))
	l.learn("10.201.1.5", answer("evil.example.", 30))   // not allowed
	l.learn("10.201.1.9", answer("api.stripe.com.", 30)) // another app's pod
	l.learn("10.201.1.5", answer("notstripe.com.", 30))  // suffix, not a subdomain
	if len(got) != 1 || got[0].set != egressSet("web") || got[0].ips[0] != "203.0.113.7" || got[0].ttl != 5*time.Minute {
		t.Fatalf("learned %+v (CNAME targets count; TTL has a 5 minute floor)", got)
	}
	var nilLearner *egressLearner
	nilLearner.learn("10.201.1.5", answer("api.stripe.com.", 30)) // pods without egress: no-op
}
