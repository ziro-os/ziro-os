package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"testing"
)

// specHashReference is specHash as it was written with fmt: the hash must never change (it names
// every running replica). specHash changes whenever a replica must be recreated (image, port, env, secrets).
func specHashReference(a ClusteredApp) string {
	keys := make([]string, 0, len(a.Env))
	for k := range a.Env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00%s", a.Image, a.Port)
	for _, k := range keys {
		fmt.Fprintf(h, "\x00%s=%s", k, a.Env[k])
	}
	if len(a.Secrets) > 0 || a.MeshOnly || len(a.Args) > 0 {
		fmt.Fprintf(h, "\x00secrets=%s\x00mesh=%v\x00args=%q", strings.Join(a.Secrets, ","), a.MeshOnly, a.Args)
	}
	if a.Network != "" { // moving an app onto the pod network recreates its containers (rolling)
		fmt.Fprintf(h, "\x00net=%s", a.Network)
	}
	if a.AllowPrivilegeEscalation { // only when set, so existing apps keep their hash
		h.Write([]byte("\x00privesc"))
	}
	if a.NetEpoch > 0 { // a mesh mode change (pod MTU): containers are recreated, one at a time
		fmt.Fprintf(h, "\x00netepoch=%d", a.NetEpoch)
	}
	if len(a.Volumes) > 0 || a.VolumeEpoch > 0 {
		fmt.Fprintf(h, "\x00volumes=%q\x00epoch=%d", a.Volumes, a.VolumeEpoch)
	}
	if len(a.ConfigFiles) > 0 {
		names := make([]string, 0, len(a.ConfigFiles))
		for n := range a.ConfigFiles {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			fmt.Fprintf(h, "\x00file=%s\x00%s", n, a.ConfigFiles[n])
		}
	}
	if a.StopTimeout > 0 { // only when set: the default grace period must not roll existing apps
		fmt.Fprintf(h, "\x00stop=%d", a.StopTimeout)
	}
	if a.Resources != nil { // only when set, so existing apps keep their hash
		fmt.Fprintf(h, "\x00resources=%+v", *a.Resources)
	}
	if len(a.Data) > 0 {
		fmt.Fprintf(h, "\x00data=%q", a.Data)
	}
	if a.DataUID > 0 { // only when set, so existing apps keep their hash
		fmt.Fprintf(h, "\x00datauid=%d", a.DataUID)
	}
	if a.Arch != "" {
		fmt.Fprintf(h, "\x00arch=%s", a.Arch)
	}
	return hex.EncodeToString(h.Sum(nil))[:8]
}

// The fast specHash produces exactly the bytes the fmt version did, for every kind of app.
func TestSpecHashUnchanged(t *testing.T) {
	apps := []ClusteredApp{
		{Image: "nginx:1", Port: "80"},
		{Image: "nginx:1", Port: "80", Env: map[string]string{"B": "2", "A": "1=x", "": ""}},
		{Image: "app@sha256:abc", Port: "8080", Secrets: []string{"db", "api"}, MeshOnly: true, Args: []string{"-x", "a b"}},
		{Image: "i", Network: "pod", AllowPrivilegeEscalation: true, NetEpoch: 3},
		{Image: "i", Volumes: []string{"/data"}, VolumeEpoch: 2, ConfigFiles: map[string]string{"b.conf": "x\x00y", "a.conf": "z"}},
		{Image: "i", StopTimeout: 30, Resources: &Resources{Memory: "1Gi", CPUs: 2}, Data: []string{"/var/lib/x"}, DataUID: 999, Arch: "arm64"},
		{Image: "ünïcødé", Port: "%s%d", Env: map[string]string{"%v": "%q"}},
	}
	for i, a := range apps {
		if got, want := specHash(a), specHashReference(a); got != want {
			t.Errorf("app %d: %s, was %s", i, got, want)
		}
	}
}
