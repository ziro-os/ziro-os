package cmd

import (
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Containers record the full reference (docker.io/library/mysql:8.4.11, often pinned by
// digest); `nerdctl images` lists the short one. Images in use must never be planned.
func TestPruneKeepsImagesInUse(t *testing.T) {
	old := runNerdctl
	defer func() { runNerdctl = old }()
	dig := "sha256:" + strings.Repeat("a", 64)
	runNerdctl = func(args ...string) ([]byte, error) {
		switch args[0] {
		case "ps":
			return []byte("c1\tziro-app-db\tUp 2 hours\tdocker.io/library/mysql:8.4.11@" + dig + "\tziro.app=db\n" +
				"c2\tziro-app-cache\tUp 1 hour\tdocker.io/valkey/valkey:9.1.2\t\n" +
				"c3\tweb\tUp 3 min\tcaddy:alpine\t\n" +
				"c4\told\tExited (0) 2 days ago\tdocker.io/library/nginx:1.27\t\n"), nil
		case "images":
			return []byte("mysql:8.4.11\tid1\t" + dig + "\t600 MiB\n" +
				"valkey/valkey:9.1.2\tid2\tsha256:" + strings.Repeat("b", 64) + "\t150 MiB\n" +
				"caddy:alpine\tid3\tsha256:" + strings.Repeat("c", 64) + "\t50 MiB\n" +
				"nginx:1.27\tid4\tsha256:" + strings.Repeat("d", 64) + "\t70 MiB\n" +
				"<none>:<none>\tid5\tsha256:" + strings.Repeat("e", 64) + "\t10 MiB\n"), nil
		}
		return nil, nil
	}
	var got []string
	for _, it := range planPrune(map[string]bool{"containers": true, "images": true}, time.Now()) {
		got = append(got, it.Category+":"+it.Target)
	}
	if strings.Join(got, ",") != "containers:old (c4),images:nginx:1.27,images:id5" {
		t.Fatalf("plan = %v", got)
	}

	// An image a container started using since the plan is kept, not an error.
	runNerdctl = func(args ...string) ([]byte, error) {
		return nil, &exec.ExitError{Stderr: []byte("Error: image \"nginx:1.27\" is being used by running container")}
	}
	freed, errs := applyPrune([]PruneItem{{"images", "nginx:1.27", 70 << 20}})
	if freed != 0 || len(errs) != 0 {
		t.Errorf("in-use image: freed %d, errs %v", freed, errs)
	}
	runNerdctl = func(args ...string) ([]byte, error) {
		return nil, &exec.ExitError{Stderr: []byte("Error: permission denied")}
	}
	if _, errs := applyPrune([]PruneItem{{"images", "x:1", 1}}); len(errs) != 1 || !strings.Contains(errs[0].Error(), "permission denied") {
		t.Errorf("runtime message lost: %v", errs)
	}
}

// An image pulled pinned by digest is stored as docker.io/library/postgres:18.6@sha256:… but listed as
// postgres:18.6, and `nerdctl rmi postgres:18.6` answers "no such image" for it. The prune removes by the
// stored name, copes with a plain and a pinned name that show alike, and does not fail on an image that
// went away since the plan.
func TestPruneRemovesImagesByTheirStoredName(t *testing.T) {
	old := runNerdctl
	defer func() { runNerdctl = old }()
	dig := "sha256:" + strings.Repeat("a", 64)
	stored := map[string]bool{ // what the runtime holds
		"docker.io/library/postgres:18.6@" + dig: true,
		"docker.io/n8nio/n8n:2.41.6":             true,
		"docker.io/valkey/valkey:9.1.2":          true,
		"docker.io/valkey/valkey:9.1.2@" + dig:   true, // the same image shown twice: plain and pinned
	}
	var removed []string
	runNerdctl = func(args ...string) ([]byte, error) {
		switch args[0] {
		case "images":
			return []byte("postgres:18.6\tdocker.io/library/postgres:18.6@" + dig + "\n" +
				"n8nio/n8n:2.41.6\tdocker.io/n8nio/n8n:2.41.6\n" +
				"valkey/valkey:9.1.2\tdocker.io/valkey/valkey:9.1.2\n" +
				"valkey/valkey:9.1.2\tdocker.io/valkey/valkey:9.1.2@" + dig + "\n" +
				"valkey/valkey:9.1.2\tdocker.io/valkey/valkey:9.1.2@" + dig + "\n"), nil // one row per platform
		case "rmi":
			if !stored[args[1]] {
				return nil, &exec.ExitError{Stderr: []byte(`time="2026-10-14T09:14:38Z" level=fatal msg="1 errors:\nno such image: ` + args[1] + `"`)}
			}
			delete(stored, args[1])
			removed = append(removed, args[1])
			return nil, nil
		}
		return nil, nil
	}
	items := []PruneItem{
		{"images", "postgres:18.6", 700 << 20},
		{"images", "n8nio/n8n:2.41.6", 900 << 20},
		{"images", "valkey/valkey:9.1.2", 150 << 20},
		{"images", "valkey/valkey:9.1.2", 0}, // listed twice: already removed by the first
	}
	freed, errs := applyPrune(items)
	if len(errs) != 0 {
		t.Fatalf("errors: %v", errs)
	}
	if want := int64(700+900+150) << 20; freed != want {
		t.Errorf("freed %d, want %d", freed, want)
	}
	if len(stored) != 0 {
		t.Errorf("still stored: %v (removed %v)", stored, removed)
	}
	for _, r := range removed {
		if r == "postgres:18.6" {
			t.Errorf("removed by the shown name: %v", removed)
		}
	}

	// A target the runtime lists under no name (a dangling image shown by its ID) is passed through as it is;
	// when the runtime does not know it either, the operator is told what to look at.
	runNerdctl = func(args ...string) ([]byte, error) {
		if args[0] == "images" {
			return []byte(""), nil
		}
		return nil, &exec.ExitError{Stderr: []byte("no such image: abc123def456")}
	}
	freed, errs = applyPrune([]PruneItem{{"images", "abc123def456", 10}})
	if freed != 0 || len(errs) != 1 || !strings.Contains(errs[0].Error(), "nerdctl images --names") || strings.Contains(errs[0].Error(), "already gone") {
		t.Errorf("unknown image: freed %d, errs %v", freed, errs)
	}

	// An image a container started using since the plan is kept, also when found by its stored name.
	runNerdctl = func(args ...string) ([]byte, error) {
		if args[0] == "images" {
			return []byte("nginx:1.27\tdocker.io/library/nginx:1.27@" + dig + "\n"), nil
		}
		return nil, &exec.ExitError{Stderr: []byte("conflict: unable to delete: image is being used by running container c1")}
	}
	if freed, errs = applyPrune([]PruneItem{{"images", "nginx:1.27", 70 << 20}}); freed != 0 || len(errs) != 0 {
		t.Errorf("in-use image: freed %d, errs %v", freed, errs)
	}
}
