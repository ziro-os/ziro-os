package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func healKinds(st *ClusterState) []string {
	var k []string
	for _, a := range st.Heal.Actions {
		k = append(k, a.Kind)
	}
	return k
}

// webOn is an app with n replicas, all placed on node (already running, so the scheduler is idle).
func webOn(st *ClusterState, n int, node string) {
	st.Apps = append(st.Apps, ClusteredApp{Name: "web", Image: "nginx", Replicas: n})
	for i := 1; i <= n; i++ {
		st.Replicas = append(st.Replicas, Replica{App: "web", Index: i, Node: node, Hash: specHash(st.Apps[len(st.Apps)-1])})
	}
}

func onNode(st *ClusterState, id string) int {
	c := 0
	for _, r := range st.Replicas {
		if r.Node == id {
			c++
		}
	}
	return c
}

func TestFlapGuardHoldsReplicasThroughTheGrace(t *testing.T) {
	now := time.Now()
	st := &ClusterState{Nodes: testNodes(now, "a", "b", "c")}
	webOn(st, 3, "c")

	st.Nodes[2].LastSeen = now.Add(-(nodeTimeout + healGrace/2)) // NotReady, inside the grace
	scheduleReplicas(st, now)
	if st.Nodes[2].Status != "NotReady" || onNode(st, "c") != 3 {
		t.Fatalf("replicas must stay put inside the grace: status %s, %d on c", st.Nodes[2].Status, onNode(st, "c"))
	}
	if len(st.Heal.Actions) != 0 {
		t.Fatalf("nothing happened yet: %v", st.Heal.Actions)
	}

	st.Nodes[2].LastSeen = now.Add(-(nodeTimeout + healGrace + time.Second))
	scheduleReplicas(st, now)
	if onNode(st, "c") != 0 || onNode(st, "a")+onNode(st, "b") != 3 {
		t.Fatalf("replicas should move once the grace is over: %v", st.Replicas)
	}
	if k := healKinds(st); len(k) != 1 || k[0] != "reschedule" || st.Heal.Actions[0].Node != "c" {
		t.Fatalf("the move must be recorded: %v", st.Heal.Actions)
	}
}

func TestHealDisabledKeepsTheOldImmediateFailover(t *testing.T) {
	now := time.Now()
	st := &ClusterState{Nodes: testNodes(now, "a", "b", "c"), Heal: HealConfig{Disabled: true}}
	webOn(st, 3, "c")
	st.Nodes[2].LastSeen = now.Add(-(nodeTimeout + time.Second))
	scheduleReplicas(st, now)
	if onNode(st, "c") != 0 || len(st.Heal.Actions) != 0 {
		t.Fatalf("with healing off replicas move at NotReady and nothing is recorded: %v %v", st.Replicas, st.Heal.Actions)
	}
}

func TestMoveCapLimitsOneDeadNodeDrainPerPass(t *testing.T) {
	now := time.Now()
	st := &ClusterState{Nodes: testNodes(now, "a", "b", "c")}
	webOn(st, 12, "c")
	st.Nodes[2].LastSeen = now.Add(-time.Hour)

	scheduleReplicas(st, now)
	if left := onNode(st, "c"); left != 12-healMaxMoves {
		t.Fatalf("one pass moves at most %d replicas, %d still on c", healMaxMoves, left)
	}
	scheduleReplicas(st, now)
	scheduleReplicas(st, now)
	if onNode(st, "c") != 0 {
		t.Fatalf("later passes finish the job: %d left", onNode(st, "c"))
	}
}

func TestPartitionBrakeStopsMassEviction(t *testing.T) {
	now := time.Now()
	st := &ClusterState{Nodes: testNodes(now, "m", "b", "c", "d")}
	webOn(st, 6, "c")
	webOn2 := ClusteredApp{Name: "db", Image: "pg", Replicas: 2}
	st.Apps = append(st.Apps, webOn2)
	st.Replicas = append(st.Replicas, Replica{App: "db", Index: 1, Node: "d", Hash: specHash(webOn2)}, Replica{App: "db", Index: 2, Node: "d", Hash: specHash(webOn2)})
	for _, i := range []int{2, 3} { // c and d vanish together: half of four
		st.Nodes[i].LastSeen = now.Add(-time.Hour)
	}
	if !partitioned(st, now) {
		t.Fatal("2 of 4 nodes NotReady must trip the brake")
	}
	scheduleReplicas(st, now)
	if onNode(st, "c") != 6 || onNode(st, "d") != 2 {
		t.Fatalf("the brake must leave every replica where it is: c=%d d=%d", onNode(st, "c"), onNode(st, "d"))
	}
	scheduleReplicas(st, now)
	if k := healKinds(st); len(k) != 1 || k[0] != "hold" {
		t.Fatalf("one hold report, not one per pass: %v", k)
	}
	// Even the 24h forget-the-node GC waits while the brake holds.
	st.Nodes[2].LastSeen = now.Add(-2 * nodeGCAfter)
	scheduleReplicas(st, now)
	if st.node("c") == nil {
		t.Fatal("a braked cluster must not forget nodes")
	}

	// One dead node out of four is a failure, not a partition.
	st2 := &ClusterState{Nodes: testNodes(now, "m", "b", "c", "d")}
	webOn(st2, 3, "c")
	st2.Nodes[2].LastSeen = now.Add(-time.Hour)
	scheduleReplicas(st2, now)
	if onNode(st2, "c") != 0 {
		t.Fatal("a single dead node's replicas must move")
	}

	// Two nodes cannot tell: a lone dead worker still fails over.
	st3 := &ClusterState{Nodes: testNodes(now, "m", "w")}
	webOn(st3, 2, "w")
	st3.Nodes[1].LastSeen = now.Add(-time.Hour)
	scheduleReplicas(st3, now)
	if onNode(st3, "w") != 0 {
		t.Fatal("the brake needs at least three nodes")
	}
}

func TestRemovedNodeIsNotHeldOrCapped(t *testing.T) {
	now := time.Now()
	st := &ClusterState{Nodes: testNodes(now, "a", "b")}
	webOn(st, 8, "gone") // node no longer exists (cluster node rm)
	scheduleReplicas(st, now)
	if onNode(st, "gone") != 0 {
		t.Fatal("replicas of a node that was removed must be rescheduled at once")
	}
}

func TestAutoCordonLiftsOnlyItsOwnCordon(t *testing.T) {
	now := time.Now()
	st := &ClusterState{Nodes: testNodes(now, "a", "b", "c")}
	sick := now.Add(-time.Minute)
	st.Nodes[0].Conditions, st.Nodes[0].CondSince = []string{CondDiskPressure}, sick
	st.Nodes[1].Conditions, st.Nodes[1].CondSince = []string{CondContainerdDown}, now.Add(-time.Second)       // too fresh
	st.Nodes[2].Conditions, st.Nodes[2].CondSince, st.Nodes[2].Cordoned = []string{CondMeshError}, sick, true // admin cordon

	healPass(st, now)
	if !st.Nodes[0].Cordoned || !st.Nodes[0].AutoCordon {
		t.Fatal("a persisting condition cordons the node")
	}
	if st.Nodes[1].Cordoned {
		t.Fatal("a condition younger than the grace must not cordon (containerd restarts take seconds)")
	}
	if !st.Nodes[2].Cordoned || st.Nodes[2].AutoCordon {
		t.Fatal("an admin's cordon is theirs: never flagged auto")
	}

	for i := range st.Nodes {
		st.Nodes[i].Conditions, st.Nodes[i].CondSince = nil, time.Time{}
	}
	healPass(st, now)
	if st.Nodes[0].Cordoned || st.Nodes[0].AutoCordon {
		t.Fatal("the auto-cordon must lift when the conditions clear")
	}
	if !st.Nodes[2].Cordoned {
		t.Fatal("the admin's cordon must survive recovery")
	}
	if k := healKinds(st); !slices.Equal(k, []string{"cordon", "uncordon"}) {
		t.Fatalf("actions: %v", k)
	}

	// A silent node's conditions are stale: no new cordon on them.
	st.Nodes[1].Conditions, st.Nodes[1].CondSince, st.Nodes[1].LastSeen = []string{CondDiskPressure}, sick, now.Add(-time.Hour)
	healPass(st, now)
	if st.Nodes[1].Cordoned {
		t.Fatal("conditions of a NotReady node must be ignored")
	}

	// Healing off: no cordons.
	st.Heal.Disabled = true
	st.Nodes[0].Conditions, st.Nodes[0].CondSince = []string{CondDiskPressure}, sick
	healPass(st, now)
	if st.Nodes[0].Cordoned {
		t.Fatal("disabled healing must not cordon")
	}
}

func TestAutoRemoveIsOptInAndRespectsMastersAndTheBrake(t *testing.T) {
	now := time.Now()
	mk := func() *ClusterState {
		st := &ClusterState{Nodes: testNodes(now, "m", "a", "b", "c")}
		st.Nodes[0].Role = "master"
		st.NodeTokens = map[string]string{"c": "x", "m": "y"}
		return st
	}
	st := mk()
	st.Nodes[3].LastSeen = now.Add(-5 * time.Hour)
	healPass(st, now)
	if st.node("c") == nil {
		t.Fatal("auto-remove is off by default")
	}

	st.Heal.RemoveAfter = int((2 * time.Hour).Seconds())
	healPass(st, now)
	if st.node("c") != nil || st.NodeTokens["c"] != "" {
		t.Fatal("a worker dead past remove-after must be removed and its token revoked")
	}
	if k := healKinds(st); !slices.Equal(k, []string{"remove"}) {
		t.Fatalf("actions: %v", k)
	}

	st = mk()
	st.Heal.RemoveAfter = int((2 * time.Hour).Seconds())
	st.Nodes[0].LastSeen = now.Add(-5 * time.Hour) // the master itself
	healPass(st, now)
	if st.node("m") == nil {
		t.Fatal("a master is never auto-removed")
	}

	st = mk()
	st.Heal.RemoveAfter = int((2 * time.Hour).Seconds())
	st.Nodes[2].LastSeen, st.Nodes[3].LastSeen = now.Add(-5*time.Hour), now.Add(-5*time.Hour)
	healPass(st, now)
	if st.node("b") == nil || st.node("c") == nil {
		t.Fatal("nothing is removed while the partition brake holds")
	}
}

func TestMasterLossAndQuorumReports(t *testing.T) {
	now := time.Now()
	st := &ClusterState{Nodes: testNodes(now, "m1", "m2", "m3", "w")}
	for i := 0; i < 3; i++ {
		st.Nodes[i].Role = "master"
	}
	st.Nodes[2].LastSeen = now.Add(-healMasterWarn / 2)
	healPass(st, now)
	if len(st.Heal.Actions) != 1 || st.Heal.Actions[0].Kind != "quorum-risk" {
		// a master that just went quiet is not yet "master-down", but 2 of 3 up is at the quorum edge
		t.Fatalf("2 of 3 masters up: quorum-risk only, got %v", st.Heal.Actions)
	}

	st.Nodes[2].LastSeen = now.Add(-2 * healMasterWarn)
	healPass(st, now)
	if k := healKinds(st); !slices.Equal(k, []string{"quorum-risk", "master-down"}) {
		t.Fatalf("a master down past the warn time is reported: %v", k)
	}
	if st.node("m3") == nil || st.Nodes[2].Role != "master" {
		t.Fatal("a master is never demoted or removed by the heal pass")
	}
	healPass(st, now)
	if len(st.Heal.Actions) != 2 {
		t.Fatalf("the same report must not repeat within the window: %v", st.Heal.Actions)
	}

	st.Nodes[1].LastSeen = now.Add(-2 * healMasterWarn) // 1 of 3 up: quorum lost
	healPass(st, now)
	if last := st.Heal.Actions[len(st.Heal.Actions)-1]; last.Kind != "quorum-lost" || !strings.Contains(last.Detail, "1 of 3") {
		t.Fatalf("escalating from at-risk to lost must not be swallowed by the earlier report: %v", st.Heal.Actions)
	}

	// A single master has no quorum to lose.
	one := &ClusterState{Nodes: testNodes(now, "m1")}
	one.Nodes[0].Role = "master"
	one.Nodes[0].LastSeen = now.Add(-time.Hour)
	healPass(one, now)
	if slices.Contains(healKinds(one), "quorum-risk") {
		t.Fatal("a single-master cluster has no quorum risk report")
	}
}

func TestHealRecordDedupeAndRing(t *testing.T) {
	now := time.Now()
	var c HealConfig
	if !c.record(HealAction{Kind: "hold"}, now, true) || c.record(HealAction{Kind: "hold"}, now.Add(time.Minute), true) {
		t.Fatal("a repeated report inside the window must be dropped")
	}
	if !c.record(HealAction{Kind: "hold"}, now.Add(healReportEvery+time.Minute), true) {
		t.Fatal("the report returns after the window")
	}
	for i := 0; i < 2; i++ {
		if !c.record(HealAction{Kind: "reschedule", Node: "x"}, now, false) {
			t.Fatalf("events are never deduplicated (repeat %d dropped)", i)
		}
	}
	for i := 0; i < 3*healHistory; i++ {
		c.record(HealAction{Kind: "cordon", Node: "n"}, now, false)
	}
	if len(c.Actions) != healHistory || c.Actions[len(c.Actions)-1].Seq != c.Next {
		t.Fatalf("history must be a ring of %d ending at the newest: %d", healHistory, len(c.Actions))
	}
	for i := 1; i < len(c.Actions); i++ {
		if c.Actions[i].Seq != c.Actions[i-1].Seq+1 {
			t.Fatal("sequence numbers must be consecutive")
		}
	}
}

func TestEmitHealActionsAnnouncesOnce(t *testing.T) {
	alertConfigPath = filepath.Join(t.TempDir(), "alerting.json")
	alertSpoolDir = t.TempDir()
	clusterDir = t.TempDir()
	old := auditPath
	auditPath = filepath.Join(t.TempDir(), "audit.log")
	t.Cleanup(func() { auditPath = old })

	var c HealConfig
	c.record(HealAction{Kind: "cordon", Node: "a", Detail: "d"}, time.Now(), false)
	c.record(HealAction{Kind: "quorum-risk", Detail: "q"}, time.Now(), false)
	seq := emitHealActions(c, 1) // the first was announced earlier
	if seq != 2 {
		t.Fatalf("high-water mark %d", seq)
	}
	log, _ := os.ReadFile(auditPath)
	if strings.Count(string(log), "cluster heal") != 1 || !strings.Contains(string(log), "cluster heal quorum-risk") {
		t.Fatalf("exactly the new action is audited:\n%s", log)
	}
	if again := emitHealActions(c, seq); again != seq {
		t.Fatal("nothing new to announce")
	}
	if healSeverity["quorum-risk"] != "critical" || healSeverity["quorum-lost"] != "critical" {
		t.Fatal("losing quorum is a critical alert")
	}
	for k := range healSeverity {
		if _, ok := alertSeverities[healSeverity[k]]; !ok {
			t.Fatalf("%s has an invalid alert severity %q", k, healSeverity[k])
		}
	}
}

func TestNodeHealerPolicy(t *testing.T) {
	now := time.Now()
	up, restarts, pct, prunes := false, 0, 91, 0
	h := &nodeHealer{
		containerdUp:      func() bool { return up },
		restartContainerd: func() error { restarts++; return nil },
		diskPercent:       func() (int, bool) { return pct, true },
		prune:             func() error { prunes++; pct = 70; return nil },
	}

	conds, did := h.check(now, "")
	if !slices.Equal(conds, []string{CondContainerdDown}) || restarts != 1 || prunes != 1 || len(did) != 2 {
		t.Fatalf("containerd restarted, disk pruned (and relieved): conds %v did %v restarts %d prunes %d", conds, did, restarts, prunes)
	}
	conds, _ = h.check(now.Add(10*time.Second), "")
	if restarts != 1 || !slices.Equal(conds, []string{CondContainerdDown}) {
		t.Fatalf("a restart inside the cooldown must not repeat, the condition stays: %v %d", conds, restarts)
	}
	up = true
	if conds, _ = h.check(now.Add(20*time.Second), ""); len(conds) != 0 {
		t.Fatalf("containerd answers again: %v", conds)
	}
	up = false
	h.check(now.Add(healRestartCooldown+time.Second), "")
	if restarts != 2 {
		t.Fatal("after the cooldown a dead containerd is restarted again")
	}

	// Disk that pruning cannot relieve raises DiskPressure, with hysteresis.
	up = true
	h.prune = func() error { prunes++; return errors.New("busy") }
	pct = 90
	conds, did = h.check(now.Add(time.Hour), "")
	if !slices.Equal(conds, []string{CondDiskPressure}) || len(did) != 1 || !strings.Contains(did[0], "failed") {
		t.Fatalf("an unfixable disk is reported: %v %v", conds, did)
	}
	before := prunes
	pct = 82 // below on, above off: still pressure, and no second prune inside the cooldown
	if conds, _ = h.check(now.Add(time.Hour+time.Minute), ""); !slices.Equal(conds, []string{CondDiskPressure}) || prunes != before {
		t.Fatalf("hysteresis: %v prunes %d", conds, prunes-before)
	}
	pct = 79
	if conds, _ = h.check(now.Add(time.Hour+2*time.Minute), ""); len(conds) != 0 {
		t.Fatalf("pressure clears below the off level: %v", conds)
	}

	// The mesh error rides along, in a stable order.
	pct, h.diskHigh = 95, false
	h.prune = func() error { return nil }
	conds, _ = h.check(now.Add(3*time.Hour), "policy: nft failed")
	if !slices.Equal(conds, []string{CondDiskPressure, CondMeshError}) {
		t.Fatalf("conditions: %v", conds)
	}
}

func TestCleanConditionsOnlyKnownOnceInOrder(t *testing.T) {
	got := cleanConditions([]string{"<script>", CondMeshError, CondMeshError, CondContainerdDown, strings.Repeat("x", 1000)})
	if !slices.Equal(got, []string{CondContainerdDown, CondMeshError}) {
		t.Fatalf("%v", got)
	}
	if cleanConditions(nil) != nil {
		t.Fatal("no conditions stay nil")
	}
}

// The heartbeat handler stores sanitized conditions, stamps when they appeared and clears the stamp
// with the last one; the heal pass then cordons only once they persisted.
func TestHeartbeatConditionsToAutoCordon(t *testing.T) {
	clusterDir = t.TempDir()
	defer func() { clusterDir = "/etc/ziro/cluster" }()
	srv := httptest.NewTLSServer(newClusterServer().handler())
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "https://")
	sum := sha256.Sum256(srv.Certificate().Raw)
	caHash := "sha256:" + hex.EncodeToString(sum[:])
	if err := saveClusterConfig(&ClusterConfig{ClusterID: "c", Role: "master", NodeID: "m1", MasterAddr: addr,
		JoinToken: "jt", NodeToken: "mt", CAHash: caHash}); err != nil {
		t.Fatal(err)
	}
	_ = withState(func(st *ClusterState) error {
		st.NodeTokens["m1"] = hashToken("mt")
		st.Nodes = []ClusterNode{{ID: "m1", Role: "master", LastSeen: time.Now()}}
		return ensureCA(st)
	})
	var jr joinResponse
	if err := clusterPost(addr, caHash, "/cluster/v1/join", "Bearer jt", joinRequest{Hostname: "w1"}, &jr); err != nil {
		t.Fatal(err)
	}
	auth := "Bearer " + jr.NodeID + "." + jr.NodeToken
	beat := func(conds ...string) {
		t.Helper()
		if err := clusterPost(addr, caHash, "/cluster/v1/heartbeat", auth, heartbeatRequest{Conditions: conds}, nil); err != nil {
			t.Fatal(err)
		}
	}

	beat(CondDiskPressure, "evil", CondDiskPressure)
	st, _ := readState()
	n := st.node(jr.NodeID)
	if !slices.Equal(n.Conditions, []string{CondDiskPressure}) || n.CondSince.IsZero() {
		t.Fatalf("stored conditions %v since %v", n.Conditions, n.CondSince)
	}
	since := n.CondSince
	beat(CondDiskPressure, CondMeshError) // another one: the clock keeps running
	st, _ = readState()
	if n = st.node(jr.NodeID); !n.CondSince.Equal(since) || len(n.Conditions) != 2 {
		t.Fatalf("the persistence clock must not restart: %v %v", n.Conditions, n.CondSince)
	}

	// Persisted past the grace: the leader's pass cordons.
	_ = withState(func(st *ClusterState) error {
		st.node(jr.NodeID).CondSince = time.Now().Add(-time.Minute)
		healPass(st, time.Now())
		return nil
	})
	st, _ = readState()
	if n = st.node(jr.NodeID); !n.Cordoned || !n.AutoCordon {
		t.Fatalf("persisting conditions must cordon: %+v", n)
	}

	beat() // recovered
	st, _ = readState()
	if n = st.node(jr.NodeID); len(n.Conditions) != 0 || !n.CondSince.IsZero() {
		t.Fatalf("conditions and the clock clear together: %+v", n)
	}
	_ = withState(func(st *ClusterState) error { healPass(st, time.Now()); return nil })
	st, _ = readState()
	if n = st.node(jr.NodeID); n.Cordoned || n.AutoCordon {
		t.Fatal("recovery lifts the auto-cordon")
	}

	// An admin cordon while the heal's cordon is active takes it over for good.
	beat(CondContainerdDown)
	_ = withState(func(st *ClusterState) error {
		st.node(jr.NodeID).CondSince = time.Now().Add(-time.Minute)
		healPass(st, time.Now())
		return nil
	})
	if err := clusterNodeAction(jr.NodeID, "cordon"); err != nil {
		t.Fatal(err)
	}
	beat()
	_ = withState(func(st *ClusterState) error { healPass(st, time.Now()); return nil })
	st, _ = readState()
	if n = st.node(jr.NodeID); !n.Cordoned || n.AutoCordon {
		t.Fatalf("an admin's cordon must outlive recovery: %+v", n)
	}
}

func TestHealSettingsAndStatus(t *testing.T) {
	clusterDir = t.TempDir()
	defer func() { clusterDir = "/etc/ziro/cluster" }()
	if err := saveClusterConfig(&ClusterConfig{ClusterID: "c", Role: "master", NodeID: "m1"}); err != nil {
		t.Fatal(err)
	}
	_ = withState(func(st *ClusterState) error {
		st.Nodes = testNodes(time.Now(), "m1", "w1")
		st.Nodes[1].LastSeen = time.Now().Add(-5 * time.Minute)
		return nil
	})
	v, err := clusterHealStatus()
	if err != nil || !v.Enabled || len(v.Unhealthy) != 1 || v.Unhealthy[0].ID != "w1" || v.Unhealthy[0].Status != "NotReady" {
		t.Fatalf("status %+v %v", v, err)
	}

	short := time.Minute
	if clusterHealSet(true, &short) == nil {
		t.Fatal("a one-minute remove-after would evict nodes on a blip: reject it")
	}
	two := 2 * time.Hour
	if err := clusterHealSet(false, &two); err != nil {
		t.Fatal(err)
	}
	v, _ = clusterHealStatus()
	if v.Enabled || v.RemoveAfter != "2h0m0s" {
		t.Fatalf("settings not saved: %+v", v)
	}
	zero := time.Duration(0)
	if err := clusterHealSet(true, &zero); err != nil {
		t.Fatal(err)
	}
	if v, _ = clusterHealStatus(); !v.Enabled || v.RemoveAfter != "" {
		t.Fatalf("0 turns auto-removal off: %+v", v)
	}
	if err := clusterHealSet(true, nil); err != nil {
		t.Fatal(err)
	}
}

func TestClusterDoctorChecks(t *testing.T) {
	now := time.Now()
	st := &ClusterState{Nodes: testNodes(now, "m1", "w1", "w2", "w3")}
	for i, h := range []string{"master", "alpha", "beta", "gamma"} {
		st.Nodes[i].Hostname = h
	}
	st.Nodes[0].Role = "master"
	cfg := &ClusterConfig{NodeID: "m1", Role: "master"}

	checks := clusterDoctorChecks(cfg, st, now)
	if len(checks) != 1 || !checks[0].Passed || checks[0].Details != "4/4 ready" {
		t.Fatalf("a healthy cluster is one passing row: %+v", checks)
	}

	st.Nodes[1].LastSeen = now.Add(-3 * time.Minute)
	st.Nodes[2].Conditions, st.Nodes[2].AutoCordon, st.Nodes[2].Cordoned = []string{CondDiskPressure}, true, true
	checks = clusterDoctorChecks(cfg, st, now)
	by := map[string]doctorCheck{}
	for _, c := range checks {
		by[c.Name] = c
	}
	if c := by["Cluster nodes ready"]; c.Passed || c.fix == nil || c.Details != "3/4 ready" {
		t.Fatalf("summary: %+v", c)
	}
	if c := by["Node alpha"]; c.Passed || !strings.Contains(c.Details, "NotReady 3m0s") || c.fix != nil || !strings.Contains(c.Fix, "on alpha") {
		t.Fatalf("a remote node's row has advice, not a local fix: %+v", c)
	}
	if c := by["Node beta"]; c.Passed || !strings.Contains(c.Details, "DiskPressure") || !strings.Contains(c.Details, "cordoned by heal") {
		t.Fatalf("conditions row: %+v", c)
	}
	if _, ok := by["Node gamma"]; ok {
		t.Fatal("healthy nodes get no row")
	}

	st.Nodes[0].LastSeen = now.Add(-3 * time.Minute) // this host's own node is down
	if c := clusterDoctorChecks(cfg, st, now); c[1].Name != "Node master" || c[1].fix == nil {
		t.Fatalf("the local node's row can restart the agent: %+v", c)
	}

	st.Heal.Disabled = true
	if c := clusterDoctorChecks(cfg, st, now)[0]; !strings.Contains(c.Details, "disabled") {
		t.Fatalf("disabled healing must be visible: %s", c.Details)
	}
}

func TestAgentDoctorCheck(t *testing.T) {
	old := agentStatusFile
	agentStatusFile = filepath.Join(t.TempDir(), "run", "agent.json")
	t.Cleanup(func() { agentStatusFile = old })
	now := time.Now()

	if _, ok := agentDoctorCheck(now); ok {
		t.Fatal("no status file: no row (the agent never ran here)")
	}
	writeAgentStatus(now, nil)
	if c, ok := agentDoctorCheck(now.Add(time.Second)); !ok || !c.Passed {
		t.Fatalf("healthy heartbeat: %+v", c)
	}
	writeAgentStatus(now.Add(-time.Minute), errors.New("dial tcp: refused"))
	if c, _ := agentDoctorCheck(now.Add(time.Second)); c.Passed || !strings.Contains(c.Details, "refused") || !strings.Contains(c.Details, "last ok") || c.fix == nil {
		t.Fatalf("failing heartbeat: %+v", c)
	}
	writeAgentStatus(now, nil)
	if c, _ := agentDoctorCheck(now.Add(2 * agentFresh)); c.Passed || !strings.Contains(c.Details, "silent") {
		t.Fatalf("an agent that stopped looping is down: %+v", c)
	}
}
