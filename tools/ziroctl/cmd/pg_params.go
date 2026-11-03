package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Server parameters an operator may change (ziroctl pg set). The list is closed and every value is
// checked by type and range, so a value can never smuggle another setting into the file. Parameters
// the controller owns (replication, TLS, the standby list, listen addresses) are not on it.
//
// A parameter Postgres reloads goes to "params.conf", a dynamic file the agent keeps current in the
// running container; the controller then has each member reload, without a restart. A parameter that
// needs a restart goes into the member's postgresql.conf, a change to which restarts the members one at
// a time with the primary last (pgMayRoll). Settings a standby must have at least as high as its
// primary may only grow: a replica restarts first and would not start below its primary.

type pgParamKind int

const (
	pgReload pgParamKind = iota
	pgRestart
)

type pgParamDef struct {
	kind     pgParamKind
	typ      string // int, real, bool, size, duration, enum
	min      float64
	max      float64
	enum     []string
	growOnly bool // a standby needs at least the primary's value
}

var pgParamDefs = map[string]pgParamDef{
	"work_mem":                            {kind: pgReload, typ: "size", min: 64 << 10, max: 2 << 30},
	"maintenance_work_mem":                {kind: pgReload, typ: "size", min: 1 << 20, max: 16 << 30},
	"effective_cache_size":                {kind: pgReload, typ: "size", min: 8 << 20, max: 1 << 42},
	"temp_buffers":                        {kind: pgReload, typ: "size", min: 800 << 10, max: 1 << 30},
	"random_page_cost":                    {kind: pgReload, typ: "real", min: 0.1, max: 100},
	"seq_page_cost":                       {kind: pgReload, typ: "real", min: 0.1, max: 100},
	"effective_io_concurrency":            {kind: pgReload, typ: "int", min: 0, max: 1000},
	"maintenance_io_concurrency":          {kind: pgReload, typ: "int", min: 0, max: 1000},
	"default_statistics_target":           {kind: pgReload, typ: "int", min: 1, max: 10000},
	"max_parallel_workers":                {kind: pgReload, typ: "int", min: 0, max: 32},
	"max_parallel_workers_per_gather":     {kind: pgReload, typ: "int", min: 0, max: 32},
	"max_parallel_maintenance_workers":    {kind: pgReload, typ: "int", min: 0, max: 32},
	"jit":                                 {kind: pgReload, typ: "bool"},
	"statement_timeout":                   {kind: pgReload, typ: "duration", min: 0, max: 7 * 24 * 3600e3},
	"lock_timeout":                        {kind: pgReload, typ: "duration", min: 0, max: 24 * 3600e3},
	"idle_in_transaction_session_timeout": {kind: pgReload, typ: "duration", min: 0, max: 7 * 24 * 3600e3},
	"idle_session_timeout":                {kind: pgReload, typ: "duration", min: 0, max: 7 * 24 * 3600e3},
	"log_min_duration_statement":          {kind: pgReload, typ: "duration", min: -1, max: 24 * 3600e3},
	"log_statement":                       {kind: pgReload, typ: "enum", enum: []string{"none", "ddl", "mod", "all"}},
	"log_lock_waits":                      {kind: pgReload, typ: "bool"},
	"log_temp_files":                      {kind: pgReload, typ: "size", min: -1, max: 1 << 40},
	"checkpoint_timeout":                  {kind: pgReload, typ: "duration", min: 30e3, max: 24 * 3600e3},
	"checkpoint_completion_target":        {kind: pgReload, typ: "real", min: 0, max: 1},
	"max_wal_size":                        {kind: pgReload, typ: "size", min: 64 << 20, max: 1 << 42},
	"min_wal_size":                        {kind: pgReload, typ: "size", min: 32 << 20, max: 1 << 42},
	"wal_compression":                     {kind: pgReload, typ: "enum", enum: []string{"off", "on", "pglz", "lz4", "zstd"}},
	"max_slot_wal_keep_size":              {kind: pgReload, typ: "size", min: -1, max: 1 << 42},
	"autovacuum_vacuum_scale_factor":      {kind: pgReload, typ: "real", min: 0, max: 100},
	"autovacuum_analyze_scale_factor":     {kind: pgReload, typ: "real", min: 0, max: 100},
	"autovacuum_vacuum_cost_limit":        {kind: pgReload, typ: "int", min: -1, max: 10000},
	"autovacuum_naptime":                  {kind: pgReload, typ: "duration", min: 1e3, max: 86400e3},
	"auto_explain.log_min_duration":       {kind: pgReload, typ: "duration", min: -1, max: 24 * 3600e3},
	"pg_stat_statements.track":            {kind: pgReload, typ: "enum", enum: []string{"none", "top", "all"}},
	"shared_buffers":                      {kind: pgRestart, typ: "size", min: 128 << 10, max: 1 << 41},
	"huge_pages":                          {kind: pgRestart, typ: "enum", enum: []string{"try", "on", "off"}},
	"wal_buffers":                         {kind: pgRestart, typ: "size", min: 32 << 10, max: 1 << 30},
	"autovacuum_max_workers":              {kind: pgRestart, typ: "int", min: 1, max: 64},
	"max_connections":                     {kind: pgRestart, typ: "int", min: 20, max: 10000, growOnly: true},
	"max_worker_processes":                {kind: pgRestart, typ: "int", min: 8, max: 256, growOnly: true},
	"max_locks_per_transaction":           {kind: pgRestart, typ: "int", min: 64, max: 10000, growOnly: true},
	"pg_stat_statements.max":              {kind: pgRestart, typ: "int", min: 100, max: 1000000},
}

var (
	pgSizeRe = regexp.MustCompile(`^(-?[0-9]+)(B|kB|MB|GB|TB)?$`)
	pgDurRe  = regexp.MustCompile(`^(-?[0-9]+)(us|ms|s|min|h|d)?$`)
)

// pgParamNumber reads a value of a numeric parameter in its base unit (bytes, milliseconds).
func pgParamNumber(d pgParamDef, v string) (float64, error) {
	switch d.typ {
	case "int":
		n, err := strconv.ParseInt(v, 10, 64)
		return float64(n), err
	case "real":
		return strconv.ParseFloat(v, 64)
	case "size":
		m := pgSizeRe.FindStringSubmatch(v)
		if m == nil {
			return 0, fmt.Errorf("a size such as 64MB")
		}
		n, _ := strconv.ParseFloat(m[1], 64)
		mult := map[string]float64{"": 1024, "B": 1, "kB": 1 << 10, "MB": 1 << 20, "GB": 1 << 30, "TB": 1 << 40}[m[2]] // a bare number is kB
		if n < 0 {
			return n, nil
		}
		return n * mult, nil
	case "duration":
		m := pgDurRe.FindStringSubmatch(v)
		if m == nil {
			return 0, fmt.Errorf("a duration such as 30s")
		}
		n, _ := strconv.ParseFloat(m[1], 64)
		if n < 0 {
			return n, nil
		}
		return n * map[string]float64{"": 1, "us": 0.001, "ms": 1, "s": 1e3, "min": 60e3, "h": 3600e3, "d": 86400e3}[m[2]], nil
	}
	return 0, fmt.Errorf("not a number")
}

// pgCheckParam validates one setting; cur is the value in force ("" = the default), for grow-only ones.
func pgCheckParam(name, value, cur string) error {
	d, ok := pgParamDefs[name]
	if !ok {
		return fmt.Errorf("%s cannot be set (see `ziroctl pg set --help` for the list)", name)
	}
	switch d.typ {
	case "bool":
		if value != "on" && value != "off" {
			return fmt.Errorf("%s: on or off", name)
		}
		return nil
	case "enum":
		for _, e := range d.enum {
			if value == e {
				return nil
			}
		}
		return fmt.Errorf("%s: one of %s", name, strings.Join(d.enum, ", "))
	}
	n, err := pgParamNumber(d, value)
	if err != nil {
		return fmt.Errorf("%s: %v", name, err)
	}
	if n < d.min || n > d.max {
		return fmt.Errorf("%s: %s is out of range", name, value)
	}
	if d.growOnly && cur != "" {
		if c, err := pgParamNumber(d, cur); err == nil && n < c {
			return fmt.Errorf("%s can only grow (from %s): a replica restarts first and would not start below its primary", name, cur)
		}
	}
	return nil
}

// pgParamNames lists the parameters pg set takes, for the help text.
func pgParamNames() string {
	names := make([]string, 0, len(pgParamDefs))
	for n := range pgParamDefs {
		names = append(names, n)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// pgParamLines renders the parameters of one kind as postgresql.conf lines.
func pgParamLines(c *PGCluster, kind pgParamKind) string {
	names := make([]string, 0, len(c.Params))
	for n := range c.Params {
		if d, ok := pgParamDefs[n]; ok && d.kind == kind {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	var b strings.Builder
	for _, n := range names {
		fmt.Fprintf(&b, "%s = '%s'\n", n, c.Params[n])
	}
	return b.String()
}

// pgRestartParams is appended to the member's postgresql.conf (a change restarts the members in turn).
func pgRestartParams(c *PGCluster) string {
	lines := pgParamLines(c, pgRestart)
	if lines == "" {
		return ""
	}
	return "# Set with ziroctl pg set (applied with a restart, one member at a time).\n" + lines
}

// pgReloadParams is the dynamic params.conf; its hash is what a reload order checks it has in place.
func pgReloadParams(c *PGCluster) (content, hash string) {
	content = "# Set with ziroctl pg set (applied with a reload).\n" + pgParamLines(c, pgReload)
	sum := sha256.Sum256([]byte(content))
	return content, hex.EncodeToString(sum[:8])
}

// pgSetParams changes parameters ("" value = back to the default).
func pgSetParams(st *ClusterState, name string, set map[string]string) error {
	c, err := pgCluster(st, name)
	if err != nil {
		return err
	}
	for k, v := range set {
		if v == "" {
			if _, ok := pgParamDefs[k]; !ok {
				return fmt.Errorf("%s cannot be set", k)
			}
			if pgParamDefs[k].growOnly {
				return fmt.Errorf("%s can only grow: it cannot go back to the default", k)
			}
			continue
		}
		if err := pgCheckParam(k, v, c.Params[k]); err != nil {
			return err
		}
	}
	if c.Params == nil {
		c.Params = map[string]string{}
	}
	for k, v := range set {
		if v == "" {
			delete(c.Params, k)
		} else {
			c.Params[k] = v
		}
	}
	return nil
}

// pgReloadPass has each member reload once its params.conf is the current one.
func pgReloadPass(c *PGCluster, g *PGGroup, now time.Time) {
	_, hash := pgReloadParams(c)
	for i := range g.Members {
		m := &g.Members[i]
		if m.Params == hash || m.Cmd != nil || !m.fresh(now) {
			continue
		}
		m.issue(opReload, hash, g.Epoch, now)
	}
}

// pgParamsInPlace reports whether a member's container has the params.conf of the given hash (the agent
// writes dynamic files and runs orders independently: a reload before the file is there would be lost).
func pgParamsInPlace(container, hash string) bool {
	b, err := os.ReadFile(filepath.Join(configDir(container), "params.conf"))
	if err != nil {
		return false
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8]) == hash
}
