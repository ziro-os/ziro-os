package cmd

import (
	"bytes"
	"testing"
	"time"
)

// Probes change on every heartbeat: they must not make a Raft commit; role changes must.
func TestPGProbesAreSoftState(t *testing.T) {
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	st := &ClusterState{PG: map[string]*PGCluster{"db": {Groups: []PGGroup{{Name: "main", Members: []PGMember{
		{ID: "m1", Node: "n1", Role: pgPrimary, Probe: PGProbe{At: now, OK: true, LSN: 100, Timeline: 1}},
		{ID: "m2", Node: "n2", Role: pgReplica, Probe: PGProbe{At: now, OK: true, Recovery: true, Streaming: true, LSN: 90}},
	}}}}}}
	before := hardKey(st)
	m := &st.PG["db"].Groups[0].Members[1]
	m.Probe.At, m.Probe.LSN, m.Probe.LagMs = now.Add(10*time.Second), 99, 12
	if !bytes.Equal(before, hardKey(st)) {
		t.Error("a probe-only change would be committed")
	}
	if m.Probe.LSN != 99 {
		t.Error("hardKey changed the live state")
	}
	m.Role = pgFenced
	if bytes.Equal(before, hardKey(st)) {
		t.Error("a role change wouldn't be committed")
	}

	// A new leader: probes are unknown (not OK) but last heard now, so nothing is fresh yet and a
	// silent primary is failed over a grace period later, never at once.
	m.Role = pgReplica
	later := now.Add(time.Hour) // the committed probes are an hour old
	pgProbesUnknown(st, later)
	p := &st.PG["db"].Groups[0].Members[0]
	if p.Probe.OK || !p.Probe.At.Equal(later) || m.fresh(later) {
		t.Errorf("after takeover: %+v / fresh %v", p.Probe, m.fresh(later))
	}
	if pgPrimaryFailed(p, later.Add(pgGrace/2)) || !pgPrimaryFailed(p, later.Add(pgGrace+time.Second)) {
		t.Error("primary failure after a takeover isn't judged from the takeover")
	}
}

// The unready timer follows the probes of a replica that is catching up; it must not make a Raft commit
// every few seconds. A new leader starts it over (its probes are unknown, so no member is unready yet).
func TestPGProgressTimerIsSoftState(t *testing.T) {
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	st := &ClusterState{PG: map[string]*PGCluster{"db": {Groups: []PGGroup{{Name: "main", Members: []PGMember{
		{ID: "m1", Node: "n1", Role: pgPrimary},
		{ID: "m2", Node: "n2", Role: pgReplica},
	}}}}}}
	before := hardKey(st)
	m := &st.PG["db"].Groups[0].Members[1]
	m.UnreadySince, m.UnreadyLSN = now, 12345
	if !bytes.Equal(before, hardKey(st)) {
		t.Error("the progress timer would be committed on every probe")
	}
	m.RebuiltAt = now
	if bytes.Equal(before, hardKey(st)) {
		t.Error("a rebuild must be committed (it gates the next one)")
	}
	m.RebuiltAt = time.Time{}
	m.Initialised = true
	if bytes.Equal(before, hardKey(st)) {
		t.Error("a member seen serving must be committed (its role file follows)")
	}
}
