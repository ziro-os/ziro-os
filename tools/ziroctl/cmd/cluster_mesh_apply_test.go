package cmd

import (
	"errors"
	"testing"
	"time"
)

// The master sends the same mesh view every heartbeat: it is applied once, again when it
// changes, when the interface is gone, after a failure, and every meshReapplyEvery.
func TestApplyMeshOnlyWhenNeeded(t *testing.T) {
	oldNow, oldUp, oldApplied := meshApplyNow, meshLinkUp, meshApplied
	t.Cleanup(func() { meshApplyNow, meshLinkUp, meshApplied = oldNow, oldUp, oldApplied })
	runs, up, fail := 0, true, false
	meshApplyNow = func(string, int, []MeshPeer) error {
		runs++
		if fail {
			return errors.New("wg: boom")
		}
		return nil
	}
	meshLinkUp = func(string) bool { return up }
	meshApplied.key = ""
	peers := []MeshPeer{{PubKey: "k1", MeshIP: "10.200.0.2"}}
	for i := 0; i < 5; i++ {
		applyMesh("10.200.0.1", 24, peers)
	}
	if runs != 1 {
		t.Fatalf("same view applied %d times", runs)
	}
	applyMesh("10.200.0.1", 24, append(peers, MeshPeer{PubKey: "k2", MeshIP: "10.200.0.3"}))
	if runs != 2 {
		t.Errorf("a new peer wasn't applied (%d)", runs)
	}
	up = false
	applyMesh("10.200.0.1", 24, append(peers, MeshPeer{PubKey: "k2", MeshIP: "10.200.0.3"}))
	if runs != 3 {
		t.Errorf("a missing interface wasn't recreated (%d)", runs)
	}
	up, fail = true, true
	applyMesh("10.200.0.1", 24, peers)
	fail = false
	applyMesh("10.200.0.1", 24, peers)
	if runs != 5 {
		t.Errorf("a failed apply wasn't retried (%d)", runs)
	}
	meshApplied.at = time.Now().Add(-meshReapplyEvery)
	applyMesh("10.200.0.1", 24, peers)
	if runs != 6 {
		t.Errorf("no periodic re-apply (%d)", runs)
	}
}
