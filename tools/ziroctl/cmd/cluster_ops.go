package cmd

import (
	"fmt"
	"strings"
	"time"
)

// Cluster operations shared by the CLI (`ziroctl cluster ...`) and the API. Each runs on the
// master, under the state lock, and reschedules replicas.

func clusterScale(name string, replicas int) error { return clusterScaleApp(name, replicas, false) }

// scaleRefusal explains why an app's replicas cannot be raised: every replica keeps its own data
// on its own node, so unless the app replicates itself, a second replica would be an independent,
// empty database that the app's DNS name then mixes in with the first. An app that already runs
// several replicas was set up on purpose and may grow.
func scaleRefusal(cur ClusteredApp, replicas int) error {
	if len(cur.Data) == 0 || cur.Replicated || replicas <= max(cur.Replicas, 1) || cur.Replicas > 1 {
		return nil
	}
	return fmt.Errorf("%s keeps data on its node and does not replicate it: a second replica would be an independent, empty copy. Use an app that replicates (for Postgres: ziroctl pg), or --force to scale anyway", cur.Name)
}

func clusterScaleApp(name string, replicas int, force bool) error {
	if _, err := requireMaster(); err != nil {
		return err
	}
	return deployApp(func(st *ClusterState) (*ClusteredApp, error) {
		cur := st.app(name)
		if cur == nil {
			return nil, errNotFound(fmt.Sprintf("app %q not found", name))
		}
		if !force {
			if err := scaleRefusal(*cur, replicas); err != nil {
				return nil, err
			}
		}
		a := *cur
		a.Replicas = replicas
		return &a, nil
	})
}

// clusterRollback restores an app's previous spec; its scale and network policy stay current
// (an older revision could carry a looser policy).
func clusterRollback(name string) error {
	if _, err := requireMaster(); err != nil {
		return err
	}
	return deployApp(func(st *ClusterState) (*ClusteredApp, error) {
		cur := st.app(name)
		h := st.History[name]
		if cur == nil || len(h) == 0 {
			return nil, errNotFound(fmt.Sprintf("no previous revision of %q", name))
		}
		prev := h[len(h)-1]
		st.History[name] = h[:len(h)-1]
		prev.Replicas, prev.AllowFrom = cur.Replicas, cur.AllowFrom
		return &prev, nil
	})
}

func clusterRemoveApp(name string) error {
	if _, err := requireMaster(); err != nil {
		return err
	}
	return withState(func(st *ClusterState) error {
		var kept []ClusteredApp
		for _, a := range st.Apps {
			if a.Name != name {
				kept = append(kept, a)
			}
		}
		if len(kept) == len(st.Apps) {
			return errNotFound(fmt.Sprintf("app %q not found", name))
		}
		st.Apps = kept
		delete(st.History, name)
		scheduleReplicas(st, time.Now())
		return nil
	})
}

// clusterApply creates or replaces an app from a full spec (revision bookkeeping is the
// master's).
func clusterApply(a ClusteredApp) error {
	if _, err := requireMaster(); err != nil {
		return err
	}
	return deployApp(func(st *ClusterState) (*ClusteredApp, error) {
		a.Revision, a.CreatedAt = 0, ""
		return &a, nil
	})
}

// clusterNodeAction cordons, uncordons, drains (cordon and move its replicas) or removes a node.
func clusterNodeAction(id, action string) error {
	return nodeOp(id, func(st *ClusterState, n *ClusterNode) error {
		switch action {
		case "cordon":
			n.Cordoned, n.AutoCordon = true, false // now the admin's: the heal pass never lifts it
		case "uncordon":
			n.Cordoned, n.AutoCordon = false, false
		case "drain", "force-drain":
			var stuck []string
			for _, r := range st.Replicas {
				if a := st.app(r.App); r.Node == n.ID && a != nil && a.stickyData() {
					stuck = append(stuck, fmt.Sprintf("%s/%d", r.App, r.Index))
				}
			}
			if len(stuck) > 0 && action != "force-drain" {
				return fmt.Errorf("%s holds data that does not move with its replicas (%s); a replica moved away starts empty. Move the data first, or drain with --force-move", n.ID, strings.Join(stuck, ", "))
			}
			n.Cordoned, n.AutoCordon = true, false
			for i := range st.Replicas {
				if st.Replicas[i].Node == n.ID {
					st.Replicas[i].Node = ""
				}
			}
		case "remove":
			if n.Role == "master" {
				return fmt.Errorf("the master cannot be removed")
			}
			removeNode(st, n.ID)
		default:
			return errNotFound("unknown node action " + action)
		}
		return nil
	})
}

// clusterSecretSet creates or replaces a secret (KEY=VALUE pairs, single-line values).
func clusterSecretSet(name string, kv map[string]string) error {
	if _, err := requireMaster(); err != nil {
		return err
	}
	if err := validName(name); err != nil {
		return err
	}
	if len(kv) == 0 {
		return fmt.Errorf("a secret needs at least one KEY=VALUE")
	}
	for k, v := range kv {
		if !envKeyRe.MatchString(k) || strings.ContainsAny(v, "\x00\r\n") {
			return fmt.Errorf("invalid secret entry %q (want KEY=VALUE, single line)", k)
		}
	}
	return withState(func(st *ClusterState) error {
		st.Secrets[name] = kv
		return nil
	})
}

// clusterSecretRm deletes a secret no app uses.
func clusterSecretRm(name string) error {
	if _, err := requireMaster(); err != nil {
		return err
	}
	return withState(func(st *ClusterState) error {
		for _, a := range st.Apps {
			for _, s := range a.Secrets {
				if s == name {
					return fmt.Errorf("secret %q is used by app %q", s, a.Name)
				}
			}
		}
		if _, ok := st.Secrets[name]; !ok {
			return errNotFound(fmt.Sprintf("secret %q not found", name))
		}
		delete(st.Secrets, name)
		return nil
	})
}
