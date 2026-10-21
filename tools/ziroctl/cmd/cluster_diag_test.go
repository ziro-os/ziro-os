package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCondenseRuntimeError(t *testing.T) {
	for in, want := range map[string]string{
		`time="2026-10-21T08:33:22Z" level=fatal msg="failed to create shim task: OCI runtime create failed: runc create failed: unable to start container process: error during container init: error running hook #0: plugin type=\"ptp\" failed (add): no IP addresses available in range set: 10.9.1.1-10.9.1.254: unknown"`: `error running hook #0: plugin type="ptp" failed (add): no IP addresses available in range set: 10.9.1.1-10.9.1.254`,
		`FATA[0000] failed to create shim task: OCI runtime create failed: runc create failed: unable to start container process: exec: "x": executable file not found in $PATH: unknown`:                                                                                                                                        `exec: "x": executable file not found in $PATH`,
		"Error: No such image: docker.io/library/nope:1": "Error: No such image: docker.io/library/nope:1",
		"  plain failure  ": "plain failure",
		"failed to create shim task: OCI runtime create failed: runc create failed:": "runc create failed:",
	} {
		if got := condenseRuntimeError(in); got != want {
			t.Errorf("condense(%q)\n got %q\nwant %q", in, got, want)
		}
	}
}

func TestPodPreflight(t *testing.T) {
	dir := t.TempDir()
	oldConf, oldBin, oldLease := cniConfPath, cniBinDir, cniLeaseDir
	cniConfPath, cniBinDir, cniLeaseDir = filepath.Join(dir, "net.d", "20.conflist"), filepath.Join(dir, "bin"), filepath.Join(dir, "leases")
	t.Cleanup(func() { cniConfPath, cniBinDir, cniLeaseDir = oldConf, oldBin, oldLease })
	live := func() map[string]bool { return map[string]bool{"alive": true} }
	unknown := func() map[string]bool { return nil }

	if err := podPreflight(Assignment{}, live); err != nil {
		t.Fatalf("a container without a pod IP needs no network: %v", err)
	}
	a := Assignment{IP: "10.9.1.5", Port: "5432:5432"}
	if err := podPreflight(a, live); err == nil || !strings.Contains(err.Error(), "CNI config") {
		t.Fatalf("missing config: %v", err)
	}
	must := func(p string, b []byte) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, b, 0644); err != nil {
			t.Fatal(err)
		}
	}
	must(cniConfPath, []byte("{}"))
	must(filepath.Join(cniBinDir, "ptp"), nil)
	if err := podPreflight(a, live); err == nil || !strings.Contains(err.Error(), "host-local") {
		t.Fatalf("missing plugin: %v", err)
	}
	must(filepath.Join(cniBinDir, "host-local"), nil)
	if err := podPreflight(a, live); err == nil || !strings.Contains(err.Error(), "portmap") {
		t.Fatalf("a published port needs portmap: %v", err)
	}
	if err := podPreflight(Assignment{IP: "10.9.1.5"}, live); err != nil {
		t.Fatalf("no port, no portmap: %v", err)
	}
	must(filepath.Join(cniBinDir, "portmap"), nil)

	// A lease whose container is gone is released; one whose container exists, or whose owner is
	// unknown because the container list failed, is kept.
	lease := filepath.Join(cniLeaseDir, "10.9.1.5")
	must(lease, []byte("deadbeef\neth0\n"))
	if err := podPreflight(a, unknown); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(lease); err != nil {
		t.Fatal("a lease must stay when containers cannot be listed")
	}
	must(lease, []byte("alive\neth0\n"))
	if err := podPreflight(a, live); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(lease); err != nil {
		t.Fatal("a lease of a live container must stay")
	}
	must(lease, []byte("deadbeef\neth0\n"))
	if err := podPreflight(a, live); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(lease); !os.IsNotExist(err) {
		t.Fatal("a stale lease must be released")
	}
}

func TestReplicaViewsAndStatus(t *testing.T) {
	st := &ClusterState{
		Nodes: []ClusterNode{{ID: "n1", Status: "Ready", Running: []string{replicaName("db", 1, "h")}}, {ID: "n2", Status: "Ready"}},
		Apps:  []ClusteredApp{{Name: "db", Replicas: 3}},
		Replicas: []Replica{
			{App: "db", Index: 1, Node: "n1", Hash: "h"},
			{App: "db", Index: 2, Node: "n2", Hash: "h", Fails: 3, Error: "exit status 1: no IP addresses available"},
			{App: "db", Index: 3, Hash: "h"},
			{App: "other", Index: 1, Node: "n2", Hash: "x"},
		},
	}
	v := replicaViews(st, "db")
	if len(v) != 3 || v[0].State != "running" || v[1].State != "failing" || v[2].State != "pending" {
		t.Fatalf("views: %+v", v)
	}
	if len(replicaViews(st, "")) != 4 {
		t.Fatal("all replicas")
	}
	if s := st.appStatus(st.Apps[0]); !strings.Contains(s, "error: replica 2 on n2: exit status 1") {
		t.Fatalf("status names the replica and node: %s", s)
	}
}
