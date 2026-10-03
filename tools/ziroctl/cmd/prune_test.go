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
