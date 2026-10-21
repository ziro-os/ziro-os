package cmd

import (
	"fmt"
	"time"
)

// Citus sharding (filled in below the controller): commands the coordinator's agent may run.

func citusSteps(o PGOrder) ([][]string, error) { return nil, fmt.Errorf("unknown order %q", o.Op) }

func validCitusCommand(op, arg string) error { return fmt.Errorf("unknown order %q", op) }

func pgCitusPass(st *ClusterState, c *PGCluster, now time.Time) {}

func pgCitusSettle(c *PGCluster, g *PGGroup, m *PGMember, cmd *PGCommand, now time.Time) {}
