package cmd

import (
	"testing"
	"time"
)

func TestParseContainerList(t *testing.T) {
	out := "web-1\tUp 3 minutes\tziro.cluster=true,ziro.app=web\n" +
		"db-1\tExited (1) 2 seconds ago\tziro.app=db,ziro.cluster=true\n" +
		"other\tUp 1 hour\tfoo=bar\n" +
		"fake\tUp 1 hour\tnote=ziro.cluster=true-ish\n"
	cluster, running := parseContainerList(out)
	if len(cluster) != 2 || !cluster["web-1"] || cluster["db-1"] || running != 3 {
		t.Errorf("%v running %d", cluster, running)
	}
}

// The heartbeat reuses the reconcile loop's listing while it is recent.
func TestContainerListShared(t *testing.T) {
	old := listNodeContainers
	t.Cleanup(func() { listNodeContainers = old })
	runs := 0
	listNodeContainers = func() (map[string]bool, int, error) { runs++; return map[string]bool{"a": true}, 1, nil }
	var c containerList
	c.get(0)             // reconcile: always fresh
	c.get(agentInterval) // heartbeat right after: reused
	if runs != 1 {
		t.Errorf("%d listings", runs)
	}
	c.at = time.Now().Add(-2 * agentInterval)
	c.get(agentInterval)
	if runs != 2 {
		t.Errorf("a stale listing was reused (%d)", runs)
	}
}
