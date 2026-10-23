package cmd

import (
	"encoding/json"
	"errors"
	"slices"
	"testing"
)

// Through the wire: the first answer is complete, the next carries only what changed, and the
// agent's view is the full answer every time.
func TestHeartbeatDelta(t *testing.T) {
	st := scaleState(20, 5, 4)
	n := &st.Nodes[3]
	answer := func() heartbeatResponse {
		var r heartbeatResponse
		r.Assignments = assignmentsFor(st, n.ID, st.Secrets)
		r.MeshIP, r.MeshPrefix, r.Peers = meshView(st, n, "10.200.0.0/16")
		r.Endpoints = appEndpoints(st)
		return r
	}
	wire := func(r heartbeatResponse) (heartbeatResponse, int) {
		b, _ := json.Marshal(r)
		var out heartbeatResponse
		json.Unmarshal(b, &out)
		return out, len(b)
	}
	var d heartbeatDelta

	first := answer()
	full, _ := json.Marshal(first)
	first.omitUnchanged(d.have())
	got, size1 := wire(first)
	if err := d.fill(&got); err != nil || len(got.Same) != 0 {
		t.Fatalf("first answer: %v %v", err, got.Same)
	}

	second := answer()
	second.omitUnchanged(d.have())
	got, size2 := wire(second)
	if err := d.fill(&got); err != nil {
		t.Fatal(err)
	}
	if len(got.Same) == 0 || size2*5 > size1 {
		t.Errorf("an unchanged answer was %d bytes (first %d), same %v", size2, size1, got.Same)
	}
	got.Same, got.Hashes = nil, nil
	if b, _ := json.Marshal(got); string(b) != string(full) {
		t.Errorf("the filled answer differs from the full one")
	}

	// A change is sent; an old agent (no Have) gets everything.
	st.Nodes[5].MeshIP = "10.200.9.9" // a peer moved
	third := answer()
	third.omitUnchanged(d.have())
	got, _ = wire(third)
	if err := d.fill(&got); err != nil {
		t.Fatal(err)
	}
	moved := false
	for _, p := range got.Peers {
		moved = moved || p.MeshIP == "10.200.9.9"
	}
	if !moved || slices.Contains(third.Same, "peers") || len(third.Same) == 0 { // assignments and endpoints carry mesh IPs too
		t.Errorf("after a peer moved: same %v, moved %v", third.Same, moved)
	}
	old := answer()
	old.omitUnchanged(nil)
	if len(old.Same) != 0 {
		t.Errorf("an agent without hashes got a partial answer: %v", old.Same)
	}

	// Told a part is unchanged that it doesn't hold: an error, never an empty part.
	var fresh heartbeatDelta
	if err := fresh.fill(&heartbeatResponse{Same: []string{"assignments"}}); !errors.Is(err, errDeltaMissing) {
		t.Errorf("missing part: %v", err)
	}
}
