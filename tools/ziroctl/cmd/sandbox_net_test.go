package cmd

import (
	"context"
	"encoding/json"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	sdkapi "github.com/ziro-os/ziro-os/sdk/api"
	"github.com/ziro-os/ziro-os/sdk/schema"
	"golang.org/x/net/dns/dnsmessage"
)

func TestSandboxNftScript(t *testing.T) {
	sbs := []sdkapi.Sandbox{
		{ID: "aaaaaaaaaaaa", IP: "10.250.0.2", Spec: schema.SandboxSpec{Network: &schema.SandboxNetwork{Mode: "allowlist", Allow: []string{"pypi.org", "1.2.3.4", "10.9.0.0/16"}}}},
		{ID: "bbbbbbbbbbbb", IP: "10.250.0.3", Spec: schema.SandboxSpec{Network: &schema.SandboxNetwork{Mode: "open"}}},
		{ID: "cccccccccccc", IP: "10.250.0.4", Spec: schema.SandboxSpec{Network: &schema.SandboxNetwork{Mode: "none"}}},
	}
	script, err := sandboxNftScript("10.250.0.0/16", sbs, []string{"dddddddddddd"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(script, "\n")
	idx := func(s string) int {
		i := slices.IndexFunc(lines, func(l string) bool { return strings.Contains(l, s) })
		if i < 0 {
			t.Fatalf("missing %q in\n%s", s, script)
		}
		return i
	}
	// Nothing enters the subnet but answers; nothing leaves it unless a sandbox rule accepts.
	into, final := idx(`ip daddr 10.250.0.0/16 counter drop`), idx(`counter drop comment "sandbox egress"`)
	if idx("ip daddr 10.250.0.0/16 ct state established,related accept") > into {
		t.Error("answers must pass before the drop into the subnet")
	}
	// allowlist: static CIDRs (even private, an operator's choice), then blocked, then learned.
	s, b, d := idx("ip saddr 10.250.0.2 ip daddr @saaaaaaaaaaaas accept"), idx("ip saddr 10.250.0.2 ip daddr @blocked drop"), idx("ip saddr 10.250.0.2 ip daddr @saaaaaaaaaaaad accept")
	if !(s < b && b < d && d < final) {
		t.Errorf("allowlist order %d %d %d %d", s, b, d, final)
	}
	idx("add element inet ziro_sandbox saaaaaaaaaaaas { 1.2.3.4/32, 10.9.0.0/16 }")
	if strings.Contains(script, "pypi") {
		t.Error("domains are not addresses")
	}
	// open: the internet, not the blocked ranges.
	if idx("ip saddr 10.250.0.3 ip daddr @blocked drop") > idx("ip saddr 10.250.0.3 accept") {
		t.Error("open must drop blocked ranges first")
	}
	// none: no rule at all for that address.
	if strings.Contains(script, "10.250.0.4") {
		t.Error("a sandbox switched to none has rules")
	}
	// The host: DNS on the gateway only.
	if idx("input ip saddr 10.250.0.0/16 ip daddr 10.250.0.1 udp dport 53 accept") > idx(`counter drop comment "sandbox to host"`) {
		t.Error("host drop before DNS")
	}
	idx("delete set inet ziro_sandbox sddddddddddddd")
	for _, blocked := range []string{"169.254.0.0/16", "10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12", "100.64.0.0/10", "127.0.0.0/8"} {
		if !strings.Contains(lines[idx("add element inet ziro_sandbox blocked")], blocked) {
			t.Errorf("%s not blocked", blocked)
		}
	}
	if _, err := sandboxNftScript("10.250.0.0/16", []sdkapi.Sandbox{{ID: "aaaaaaaaaaaa", IP: "192.168.1.5", Spec: sbs[1].Spec}}, nil, 0); err == nil {
		t.Error("an IP outside the subnet was accepted")
	}
	if _, err := sandboxNftScript("10.250.0.0/16", nil, []string{"x; flush ruleset"}, 0); err == nil {
		t.Error("a bad id reached the script")
	}
}

func TestSandboxSubnetAndIPs(t *testing.T) {
	for _, bad := range []string{"10.201.0.0/16", "172.20.0.0/16", "10.250.0.0/8", "10.250.0.1/16", "fd00::/64"} {
		if validateSandboxSubnet(bad) == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	all := map[string]*sdkapi.Sandbox{"a": {IP: "10.250.0.2"}, "b": {IP: "10.250.0.4"}}
	if ip, err := allocSandboxIP("10.250.0.0/16", all); err != nil || ip != "10.250.0.3" {
		t.Fatalf("%s %v", ip, err)
	}
	full := map[string]*sdkapi.Sandbox{}
	for i := 2; i < 255; i++ {
		full[strconv.Itoa(i)] = &sdkapi.Sandbox{IP: "10.250.9." + strconv.Itoa(i)}
	}
	if _, err := allocSandboxIP("10.250.9.0/24", full); err == nil {
		t.Error("a full /24 handed out an address")
	}
	if privilegedAllow(&schema.SandboxNetwork{Allow: []string{"pypi.org", "8.8.8.8"}}) != "" ||
		privilegedAllow(&schema.SandboxNetwork{Allow: []string{"169.254.169.254"}}) != "169.254.169.254" ||
		privilegedAllow(&schema.SandboxNetwork{Allow: []string{"0.0.0.0/0"}}) != "0.0.0.0/0" {
		t.Error("privileged allow entries")
	}
}

func dnsAnswer(t *testing.T, name string, ips ...string) []byte {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 7, Response: true})
	b.StartQuestions()
	n := dnsmessage.MustNewName(name)
	b.Question(dnsmessage.Question{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	b.StartAnswers()
	for _, ip := range ips {
		b.AResource(dnsmessage.ResourceHeader{Name: n, Class: dnsmessage.ClassINET, TTL: 60}, dnsmessage.AResource{A: netip.MustParseAddr(ip).As4()})
	}
	r, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestSandboxDNSPolicy(t *testing.T) {
	n := newSandboxNet(sandboxDefSubnet)
	n.byIP = map[string]ipPolicy{
		"10.250.0.2": {"aaaaaaaaaaaa", &schema.SandboxNetwork{Mode: "allowlist", Allow: []string{"pypi.org", "*.github.com", "1.2.3.4"}}},
		"10.250.0.3": {"bbbbbbbbbbbb", &schema.SandboxNetwork{Mode: "open"}},
	}
	for _, c := range []struct {
		client, name string
		ok           bool
	}{
		{"10.250.0.2", "pypi.org.", true}, {"10.250.0.2", "files.pypi.org.", true}, {"10.250.0.2", "api.github.com.", true},
		{"10.250.0.2", "github.com.", true}, {"10.250.0.2", "evil.com.", false}, {"10.250.0.2", "notpypi.org.", false},
		{"10.250.0.3", "anything.example.", true}, {"10.250.0.9", "pypi.org.", false},
	} {
		if n.allow(c.client, c.name) != c.ok {
			t.Errorf("%s %s: want %v", c.client, c.name, c.ok)
		}
	}
	var added []string
	old := sandboxNftAdd
	sandboxNftAdd = func(family, table, set string, ips []string, ttl time.Duration) error {
		added = append(added, set+"="+strings.Join(ips, ","))
		if ttl < 5*time.Minute {
			t.Errorf("ttl %v", ttl)
		}
		return nil
	}
	defer func() { sandboxNftAdd = old }()
	// Public addresses are learned; a private one in the answer (DNS rebinding) is not.
	n.learn("10.250.0.2", dnsAnswer(t, "files.pypi.org.", "151.101.0.223", "10.0.0.5", "169.254.169.254"))
	n.learn("10.250.0.2", dnsAnswer(t, "evil.com.", "6.6.6.6"))       // not allowed
	n.learn("10.250.0.3", dnsAnswer(t, "example.com.", "93.184.0.1")) // open: nothing to learn
	if !slices.Equal(added, []string{"saaaaaaaaaaaad=151.101.0.223"}) {
		t.Errorf("learned %v", added)
	}
	// The responder answers NXDOMAIN for a name the sandbox may not resolve.
	d := &podDNS{policy: n}
	resp := d.refuse(dnsQuery("evil.com.", 1), "10.250.0.2")
	var m dnsmessage.Message
	if resp == nil || m.Unpack(resp) != nil || m.Header.RCode != dnsmessage.RCodeNameError || m.Header.ID != 0x1234 || !m.Header.Response {
		t.Fatalf("refuse: %v %+v", resp, m.Header)
	}
	if d.refuse(dnsQuery("pypi.org.", 1), "10.250.0.2") != nil {
		t.Error("an allowed name was refused")
	}
}

func TestSandboxNetworkLifecycle(t *testing.T) {
	m, f, _ := stubSandboxes(t)
	mk := func(spec string, c sandboxCaller) (sdkapi.Sandbox, error) {
		var s schema.SandboxSpec
		if err := json.Unmarshal([]byte(spec), &s); err != nil {
			t.Fatal(err)
		}
		return m.create(context.Background(), s, c)
	}
	sb, err := mk(`{"image":"a","network":{"mode":"allowlist","allow":["pypi.org"]}}`, alice)
	if err != nil || sb.IP != "10.250.0.2" {
		t.Fatalf("%+v %v", sb, err)
	}
	// The rules for its address were applied before the container started.
	nft, run := -1, -1
	for i, c := range f.calls {
		if c[0] == "nft" && strings.Contains(c[1], "ip saddr 10.250.0.2") && nft < 0 {
			nft = i
		}
		if c[0] == "run" {
			run = i
			if !strings.Contains(strings.Join(c, " "), "--network ziro-sandbox --ip 10.250.0.2 --dns 10.250.0.1") {
				t.Errorf("run args %v", c)
			}
		}
	}
	if nft < 0 || run < nft {
		t.Fatalf("nft %d, run %d", nft, run)
	}
	plain, _ := mk(`{"image":"a"}`, alice)
	if plain.IP != "" {
		t.Errorf("a sandbox without a network got %s", plain.IP)
	}
	// A private range needs an operator.
	if _, err := mk(`{"image":"a","network":{"mode":"allowlist","allow":["192.168.1.0/24"]}}`, alice); err == nil {
		t.Error("deployer allowed the LAN")
	}
	// Live policy changes; no network can't become one.
	if _, err := m.setNetwork(context.Background(), sb.ID, alice, schema.SandboxNetwork{Mode: "open"}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.setNetwork(context.Background(), plain.ID, alice, schema.SandboxNetwork{Mode: "open"}); err == nil {
		t.Error("a sandbox without an interface got a network")
	}
	if _, err := m.setNetwork(context.Background(), sb.ID, bob, schema.SandboxNetwork{Mode: "open"}); err == nil {
		t.Error("bob changed alice's network")
	}
	// Fail closed: rules that can't be applied pause the sandbox, and a new one never starts.
	f.fail = "nft"
	got, err := m.setNetwork(context.Background(), sb.ID, alice, schema.SandboxNetwork{Mode: "allowlist", Allow: []string{"a.com"}})
	if err == nil || got.State != "failed" || f.ps[sandboxContainer(sb.ID)] == "" {
		t.Errorf("failed apply: %+v %v", got, err)
	}
	if !slices.ContainsFunc(f.calls, func(c []string) bool { return c[0] == "pause" }) {
		t.Error("not paused")
	}
	runs := len(slices.DeleteFunc(slices.Clone(f.calls), func(c []string) bool { return c[0] != "run" }))
	if _, err := mk(`{"image":"a","network":{"mode":"open"}}`, alice); err == nil || !strings.Contains(err.Error(), "network policy") {
		t.Errorf("create with broken nft: %v", err)
	}
	if n := len(slices.DeleteFunc(slices.Clone(f.calls), func(c []string) bool { return c[0] != "run" })); n != runs {
		t.Error("a sandbox started without its rules")
	}
	f.fail = ""
	// Deleting it drops its sets.
	if err := m.remove(sb.ID, alice); err != nil {
		t.Fatal(err)
	}
	last := f.calls[len(f.calls)-1]
	if last[0] != "nft" || !strings.Contains(last[1], "delete set inet ziro_sandbox s"+sb.ID+"s") {
		t.Errorf("last call %v", last)
	}
}
