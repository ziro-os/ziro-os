package schema

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestGatewayV2Validation(t *testing.T) {
	ok := GatewayRoute{Name: "ok", Hosts: []string{"a.test"}, To: []GatewayUpstream{{App: "web"}}}
	for name, mut := range map[string]func(r *GatewayRoute){
		"two handlers": func(r *GatewayRoute) { r.Redirect = "https://x.test" },
		"header injection": func(r *GatewayRoute) {
			r.RequestHeaders = &HeaderRules{Set: map[string]string{"X": "a\r\nInjected: 1"}}
		},
		"bad header name":    func(r *GatewayRoute) { r.Headers = map[string]string{"Bad Name": "1"} },
		"plaintext password": func(r *GatewayRoute) { r.BasicAuth = map[string]string{"admin": "hunter2"} },
		"hostname upstream":  func(r *GatewayRoute) { r.To = []GatewayUpstream{{Address: "evil.example:80"}} },
		"acme wildcard":      func(r *GatewayRoute) { r.Hosts = []string{"*.a.test"}; r.TLS = "auto" },
		"bad lb":             func(r *GatewayRoute) { r.LB = "random" },
		"bad redirect":       func(r *GatewayRoute) { r.To = nil; r.Redirect = "javascript:alert(1)" },
		"tcp on 443":         func(r *GatewayRoute) { r.Kind = "tcp"; r.Listen = 443 },
		"weight 0 overflow":  func(r *GatewayRoute) { r.To[0].Weight = 5000 },
		"cookie without tls": func(r *GatewayRoute) { r.LB = "cookie"; r.TLS = "off" },
	} {
		r := ok
		r.To = append([]GatewayUpstream(nil), ok.To...)
		mut(&r)
		r.Normalize()
		if err := r.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	r := ok
	r.Normalize()
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestAppDefValidation(t *testing.T) {
	if err := testPostgresDef().Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(d *AppDef){
		"image without digest": func(d *AppDef) { d.Versions["18"].Images["db"] = "postgres:18" },
		"secret in env":        func(d *AppDef) { d.Components[0].Env["X"] = "{{secret.POSTGRES_PASSWORD}}" },
		"secret in args":       func(d *AppDef) { d.Components[0].Args = []string{"--pw={{secret.POSTGRES_PASSWORD}}"} },
		"replicas w/o cluster": func(d *AppDef) { d.Components[0].Replicas = 3 },
		"unknown secret":       func(d *AppDef) { d.Components[0].Secrets = []string{"NOPE"} },
		"bad data path":        func(d *AppDef) { d.Components[0].Data = []string{"/var/lib/x:/etc"} },
		"reserved env":         func(d *AppDef) { d.Components[0].Env["ZIRO_REPLICA"] = "7" },
		"missing default":      func(d *AppDef) { d.Default = "99" },
		"unknown placeholder":  func(d *AppDef) { d.Outputs["x"] = "{{secret.NOPE}}" },
	} {
		d := testPostgresDef()
		mut(&d)
		if d.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	b, _ := json.Marshal(testPostgresDef())
	if _, err := ParseAppDef(append(b[:len(b)-1], []byte(`,"privileged":true}`)...)); err == nil {
		t.Error("unknown field accepted")
	}
}

const testDigest = "@sha256:1a6ab3f5345eb6dbe04a1349529caabdb0ab09293a09590fad07b2246bfa4b54"

func testPostgresDef() AppDef {
	return AppDef{Schema: 1, Name: "postgres", Description: "pg", Default: "18",
		Versions: map[string]AppVersion{"17": {Images: map[string]string{"db": "docker.io/library/postgres:17" + testDigest}},
			"18": {Images: map[string]string{"db": "docker.io/library/postgres:18" + testDigest}}},
		Settings: []Setting{{Name: "user", Default: "app", Pattern: `^[a-z_][a-z0-9_]{0,62}$`}},
		Secrets:  map[string]string{"POSTGRES_PASSWORD": "alnum:32"},
		Components: []AppComponent{{Name: "db", Port: 5432, Env: map[string]string{"POSTGRES_USER": "{{setting.user}}"},
			Secrets: []string{"POSTGRES_PASSWORD"}, Data: []string{"/var/lib/postgresql/data"}, Health: []string{"pg_isready"}}},
		Outputs: map[string]string{"url": "postgres://{{setting.user}}:{{secret.POSTGRES_PASSWORD}}@{{host}}:{{port}}/app"}}
}

func TestExpandAndSettings(t *testing.T) {
	vars := map[string]string{"setting.port": "80", "secret.k": "{{setting.port}}"}
	if out, err := Expand("p={{ setting.port }} k={{secret.k}}", vars); err != nil || out != "p=80 k={{setting.port}}" {
		t.Fatalf("%q %v (values must not be re-expanded)", out, err)
	}
	for _, bad := range []string{"{{setting.nope}}", "{{ bad", "{{exec \"x\"}}"} {
		if _, err := Expand(bad, vars); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	defs := []Setting{{Name: "port", Default: "80", Pattern: `^[0-9]{2,5}$`}}
	if _, err := ResolveSettings(defs, nil, map[string]string{"port": "80\nevil"}); err == nil {
		t.Fatal("setting with a newline accepted")
	}
	if _, err := ResolveSettings(defs, nil, map[string]string{"nope": "1"}); err == nil {
		t.Fatal("unknown setting accepted")
	}
	if got, _ := ResolveSettings(defs, map[string]string{"port": "81"}, nil); got["port"] != "81" {
		t.Fatal("previous setting not kept")
	}
	if ValidateSettings([]Setting{{Name: "a", Default: "x", Pattern: "x"}}) == nil {
		t.Fatal("unanchored pattern accepted")
	}
	s, err := GenSecret("hex:32")
	if err != nil || len(s) != 64 {
		t.Fatal(s, err)
	}
	if _, err := GenSecret("hex:8"); err == nil {
		t.Fatal("short secret accepted")
	}
}

func TestPluginManifestRejectsUnsafe(t *testing.T) {
	sha := strings.Repeat("a", 64)
	for _, m := range []ModuleManifest{
		{Name: "p", Artifacts: []ModuleArtifact{{URL: "https://x/y", SHA256: sha, Path: "/usr/bin/y", Mode: "0755"}}},
		{Name: "p", Artifacts: []ModuleArtifact{{URL: "https://x/y", SHA256: sha, Path: "/var/lib/ziro/plugins/q/y", Mode: "0755"}}},
		{Name: "p", Artifacts: []ModuleArtifact{{URL: "http://x/y", SHA256: sha, Path: "/var/lib/ziro/plugins/p/y", Mode: "0755"}}},
		{Name: "p", Artifacts: []ModuleArtifact{{URL: "https://x/y", Path: "/var/lib/ziro/plugins/p/y", Mode: "0755"}}},
		{Name: "p", Artifacts: []ModuleArtifact{{URL: "https://x/y", SHA256: sha, Path: "/var/lib/ziro/plugins/p/y", Mode: "0777"}}},
		{Name: "p", Secrets: map[string]string{"k": "hex:32"}, Files: []ModuleFile{{Path: "/etc/p.conf", Mode: "0644", Content: "k={{secret.k}}"}}},
		{Name: "p", Secrets: map[string]string{"k": "hex:32"}, PostStart: []ModuleCmd{{Exec: "/bin/x", Args: []string{"--token={{secret.k}}"}}}},
		{Name: "p", Files: []ModuleFile{{Path: "/etc/p.conf", Mode: "0644", Content: "{{setting.undefined}}"}}},
		{Name: "p", Packages: []string{"x; rm -rf /"}},
		{Name: "p", Services: []ModuleService{{Name: "s", Exec: "/bin/s", User: "root:0", PIDFile: "/run/s.pid", LogFile: "/var/log/s.log"}}},
	} {
		if err := m.Validate(); err == nil {
			t.Errorf("accepted %+v", m)
		}
	}
	if _, err := ParseManifest([]byte(`{"name":"p","version":"1","servces":[]}`)); err == nil {
		t.Error("unknown field accepted")
	}
}
