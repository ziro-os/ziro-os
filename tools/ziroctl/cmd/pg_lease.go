package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Leases: a primary that loses the master stops acknowledging writes before a replica can be promoted
// in its place (the pattern Patroni uses with its DCS).
//
// With every heartbeat the master grants a lease to each member whose probe in that heartbeat is fresh
// and whose role it agrees with (pgLeaseGrant). The grant reaches the node as the member's "lease"
// file (a dynamic file, rewritten while the container runs); the agent then writes "lease-until", the
// time the lease ends on the node's own clock, counted from when it sent the heartbeat. A watchdog in
// the container (pg_entry.sh) fences a primary whose lease has ended: synchronous_standby_names is set
// to a standby that never exists, so commits wait and are never acknowledged, and client sessions are
// ended. It lifts the fence when a lease is granted again.
//
// The timing rule (tested): a lease ends at most pgLeaseFresh + pgLeaseTTL after the probe the master
// last saw, which is well before the master fails the primary over (pgGrace after that probe). So by
// the time a replica is promoted, the old primary has stopped acknowledging writes, whatever the
// reason it stopped answering (node down, network cut, a hung container runtime).
//
// A lease is only enforced once a member has had one ("lease-until" exists), so a cluster whose agents
// predate leases keeps running, and a group with no replica (nothing to fail over to) is never fenced.

const (
	pgLeaseTTL    = 22 * time.Second // how long a grant lasts on the node; spans one missed heartbeat
	pgLeaseFresh  = 7 * time.Second  // a member's probe must be at most this old for a grant
	pgLeaseMargin = 5 * time.Second  // pgGrace - (pgLeaseFresh + pgLeaseTTL) must be at least this
)

// pgLeaseGrant decides whether a member gets a lease with this heartbeat: its probe is fresh, and it is
// what the master thinks it is (a fenced member, or a "replica" found out of recovery, gets none).
func pgLeaseGrant(m *PGMember, now time.Time) bool {
	if !m.Probe.OK || now.Sub(m.Probe.At) > pgLeaseFresh {
		return false
	}
	switch m.Role {
	case pgPrimary, pgPromoting:
		return true
	case pgReplica:
		return m.Probe.Recovery // a replica that is not in recovery is a primary nobody elected
	}
	return false
}

// pgLeaseFile is the member's "lease" file: whether this heartbeat grants a lease, for how long, under
// which epoch, and whether the watchdog enforces it (only when the group has a replica to fail over to).
func pgLeaseFile(g *PGGroup, m *PGMember, now time.Time) string {
	grant := 0
	if pgLeaseGrant(m, now) {
		grant = 1
	}
	fence := 0
	if len(g.Members) > 1 {
		fence = 1
	}
	return fmt.Sprintf("grant=%d\nttl=%d\nepoch=%d\nfence=%d\n", grant, int(pgLeaseTTL/time.Second), g.Epoch, fence)
}

// parseLeaseFile reads a lease file (unknown keys are ignored).
func parseLeaseFile(s string) (grant bool, ttl time.Duration, epoch int64) {
	for _, line := range strings.Split(s, "\n") {
		k, v, _ := strings.Cut(strings.TrimSpace(line), "=")
		switch k {
		case "grant":
			grant = v == "1"
		case "ttl":
			if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 120 {
				ttl = time.Duration(n) * time.Second
			}
		case "epoch":
			epoch, _ = strconv.ParseInt(v, 10, 64)
		}
	}
	return grant, ttl, epoch
}

// pgRenewLeases writes "lease-until" for each Postgres member the master granted a lease in the
// heartbeat sent at sent. A member without a grant keeps its old "lease-until", which runs out.
func pgRenewLeases(assignments []Assignment, sent time.Time) {
	for _, a := range assignments {
		lease, ok := a.Dynamic["lease"]
		if !a.PG || !ok {
			continue
		}
		grant, ttl, epoch := parseLeaseFile(lease)
		if !grant || ttl == 0 {
			continue
		}
		dir := configDir(a.Name)
		if _, err := os.Stat(dir); err != nil {
			continue // the container is not set up yet
		}
		_ = writeFileAtomic(filepath.Join(dir, "lease-until"), []byte(fmt.Sprintf("%d %d\n", sent.Add(ttl).Unix(), epoch)), 0644)
	}
}
