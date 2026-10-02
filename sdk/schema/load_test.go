package schema

import (
	"reflect"
	"strings"
	"testing"
)

func TestYAMLAndJSONDecodeTheSame(t *testing.T) {
	js := `{"name":"hello","version":"1.0","description":"d","services":[{"name":"hello","description":"d","exec":"/usr/sbin/httpd",
"args":"-f","pidfile":"/run/ziro-hello.pid","logfile":"/var/log/hello.log","user":"nobody","resources":{"memory":"64Mi","cpus":0.5}}]}`
	ym := `
name: hello
version: "1.0"
description: d
services:
  - name: hello
    description: d
    exec: /usr/sbin/httpd
    args: -f
    pidfile: /run/ziro-hello.pid
    logfile: /var/log/hello.log
    user: nobody
    resources: {memory: 64Mi, cpus: 0.5}
`
	a, err1 := ParseManifest([]byte(js))
	b, err2 := ParseManifest([]byte(ym))
	if err1 != nil || err2 != nil || !reflect.DeepEqual(a, b) {
		t.Fatalf("json %+v %v\nyaml %+v %v", a, err1, b, err2)
	}
	for name, bad := range map[string]string{
		"unknown field":   ym + "sevices: []\n",
		"duplicate key":   "name: a\nname: b\n",
		"non-string keys": "name: a\n1: x\n",
		"two documents":   "name: a\n---\nname: b\n",
	} {
		if _, err := ParseManifest([]byte(bad)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	for want, doc := range map[string]string{"stack": "stack: shop\napps: {}\n", "host": "host: {hostname: a}\n",
		"app": `{"components":[]}`, "plugin": "name: x\n"} {
		if got, err := Kind([]byte(doc)); err != nil || got != want {
			t.Errorf("Kind(%q) = %q %v", strings.TrimSpace(doc), got, err)
		}
	}
}

func TestToYAMLRoundTrip(t *testing.T) {
	m := ModuleManifest{Name: "hello", Version: "1.0", Description: "d: with a colon", Packages: []string{"busybox-extras"},
		Settings: []Setting{{Name: "port", Default: "8080", Pattern: "^[0-9]+$"}}}
	y, err := ToYAML(m)
	if err != nil {
		t.Fatal(err)
	}
	var back ModuleManifest
	if err := DecodeStrict(y, &back); err != nil || !reflect.DeepEqual(m, back) {
		t.Fatalf("round trip:\n%s\n%+v %v", y, back, err)
	}
	if !strings.HasPrefix(string(y), "name: hello\nversion: \"1.0\"\n") {
		t.Errorf("field order or quoting:\n%s", y)
	}
}
