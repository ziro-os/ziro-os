package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/ziro-os/ziro-os/sdk/schema"
)

// Stacks: several apps deployed together, in dependency order, from one YAML/JSON file. `stack up`
// plans first (create / update / unchanged / remove), then applies only the differences, so
// running it again with the same file changes nothing. Each app is an ordinary app instance
// named <stack>-<key>: `apps list`, `apps credentials` and the gateway work on it as usual.

type (
	Stack    = schema.Stack
	StackApp = schema.StackApp
)

var stackStateDir = "/var/lib/ziro/stacks"

// stackState is what `stack up` last applied.
type stackState struct {
	Stack   Stack             `json:"stack"`
	Hashes  map[string]string `json:"hashes"` // app key -> spec hash
	Applied string            `json:"applied"`
}

// StackChange is one line of a plan.
type StackChange struct {
	Key      string `json:"key"`
	Instance string `json:"instance"`
	Action   string `json:"action"` // create, update, unchanged, remove
	App      string `json:"app,omitempty"`
}

func stackStatePath(name string) string { return filepath.Join(stackStateDir, name+".json") }

func loadStackState(name string) (*stackState, error) {
	if err := validName(name); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(stackStatePath(name))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errNotFound("no stack " + name)
		}
		return nil, err
	}
	var st stackState
	return &st, json.Unmarshal(b, &st)
}

func listStacks() []stackState {
	out := []stackState{}
	files, _ := filepath.Glob(filepath.Join(stackStateDir, "*.json"))
	for _, f := range files {
		if st, err := loadStackState(strings.TrimSuffix(filepath.Base(f), ".json")); err == nil {
			out = append(out, *st)
		}
	}
	return out
}

// resolvedApp is a stack app with its definition loaded.
type resolvedApp struct {
	schema.StackApp
	Def     AppDef
	Version string
	Secrets map[string]string // input secrets given now (--secret app.KEY=...); never stored or hashed
}

// resolveStackApps loads every app definition: catalog apps from the signed catalogs, local
// files from dir (opened through os.Root, so a path can't leave the stack's directory). dir ""
// refuses local files (stacks received over the API).
func resolveStackApps(s Stack, dir string) (map[string]resolvedApp, error) {
	out := map[string]resolvedApp{}
	var root *os.Root
	for key, a := range s.Apps {
		r := resolvedApp{StackApp: a}
		if schema.IsLocalRef(a.App) {
			if dir == "" {
				return nil, fmt.Errorf("app %s: local definitions (%s) are only accepted from a stack file on the host", key, a.App)
			}
			if root == nil {
				var err error
				if root, err = os.OpenRoot(dir); err != nil {
					return nil, err
				}
				defer root.Close()
			}
			b, err := root.ReadFile(filepath.Clean(a.App))
			if err != nil {
				return nil, fmt.Errorf("app %s: %w", key, err)
			}
			if r.Def, err = parseAppDef(b); err != nil {
				return nil, fmt.Errorf("app %s (%s): %w", key, a.App, err)
			}
		} else {
			name, version := parseAppRef(a.App)
			d, ok := loadAppDefsFn()[name]
			if !ok {
				refreshStaleCatalogs("app")
				if d, ok = loadAppDefsFn()[name]; !ok {
					return nil, fmt.Errorf("app %s: unknown catalog app %q (see: ziroctl apps search)", key, name)
				}
			}
			r.Def, r.Version = d, version
		}
		if r.Version == "" {
			r.Version = r.Def.Default
		}
		if _, ok := r.Def.Versions[r.Version]; !ok {
			return nil, fmt.Errorf("app %s: %s has no version %q", key, r.Def.Name, r.Version)
		}
		if a.Resources != nil { // the stack's limits apply to every component
			comps := append([]AppComponent(nil), r.Def.Components...)
			for i := range comps {
				comps[i].Resources = a.Resources
			}
			r.Def.Components = comps
		}
		out[key] = r
	}
	for key, r := range out {
		for env, ref := range r.Links {
			from, output, _ := strings.Cut(ref, ".")
			if _, ok := out[from].Def.Outputs[output]; !ok {
				return nil, fmt.Errorf("app %s: link %s: %s has no output %q", key, env, out[from].Def.Name, output)
			}
			for _, c := range r.Def.Components {
				if _, clash := c.Env[env]; clash || slices.Contains(c.Secrets, env) {
					return nil, fmt.Errorf("app %s: link %s clashes with the app's own %s", key, env, env)
				}
			}
		}
	}
	return out, nil
}

// specHash identifies what an app is deployed with; a different hash means redeploy.
func (r resolvedApp) specHash() string {
	b, _ := json.Marshal(struct {
		Def     AppDef
		Version string
		App     schema.StackApp
	}{r.Def, r.Version, r.StackApp})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}

// planStack compares the stack with what is deployed.
func planStack(s Stack, apps map[string]resolvedApp, prev *stackState) ([]StackChange, error) {
	order, err := s.Order()
	if err != nil {
		return nil, err
	}
	var plan []StackChange
	for _, key := range order {
		c := StackChange{Key: key, Instance: s.Instance(key), App: apps[key].Def.Name + ":" + apps[key].Version}
		in, err := loadAppInstance(c.Instance)
		switch {
		case err != nil:
			c.Action = "create"
		case in.App != apps[key].Def.Name:
			return nil, fmt.Errorf("app %s: instance %s already runs %s, not %s", key, c.Instance, in.App, apps[key].Def.Name)
		case prev == nil || prev.Hashes[key] != apps[key].specHash() || len(apps[key].Secrets) > 0:
			c.Action = "update"
		default:
			c.Action = "unchanged"
		}
		plan = append(plan, c)
	}
	if prev != nil { // apps dropped from the stack, removed after the rest is up
		var gone []string
		for key := range prev.Stack.Apps {
			if _, ok := s.Apps[key]; !ok {
				gone = append(gone, key)
			}
		}
		sort.Strings(gone)
		for _, key := range gone {
			plan = append(plan, StackChange{Key: key, Instance: prev.Stack.Instance(key), Action: "remove"})
		}
	}
	return plan, nil
}

// applyStack deploys the plan in order (each app waits until healthy before its dependents
// start) and records the result. A failure stops the run; what succeeded is kept and recorded.
func applyStack(s Stack, apps map[string]resolvedApp, plan []StackChange, prev *stackState) error {
	st := &stackState{Stack: s, Hashes: map[string]string{}}
	if prev != nil {
		for k, h := range prev.Hashes {
			if _, ok := s.Apps[k]; ok {
				st.Hashes[k] = h
			}
		}
	}
	save := func() error {
		st.Applied = time.Now().UTC().Format(time.RFC3339)
		b, _ := json.MarshalIndent(st, "", "  ")
		if err := os.MkdirAll(stackStateDir, 0700); err != nil {
			return err
		}
		return writeFileAtomic(stackStatePath(s.Stack), b, 0600)
	}
	network := stackNetwork(s.Stack)
	if !isClusterMaster() {
		if err := ensureStackNetwork(network); err != nil {
			return err
		}
	}
	for _, c := range plan {
		switch c.Action {
		case "create", "update":
			a := apps[c.Key]
			links, err := stackLinkValues(s, a)
			if err != nil {
				_ = save()
				return fmt.Errorf("%s: %w", c.Key, err)
			}
			allow, internal := stackDependents(s, apps, c.Key)
			err = deployAppDef(a.Def, a.Version, appDeployOpts{Name: c.Instance, Set: a.Set, Replicas: a.Replicas,
				Publish: a.Publish, Expose: a.Expose, ExposeTLS: a.ExposeTLS, Links: links, Network: network,
				AllowFrom: allow, Internal: internal && a.Publish == 0 && a.Expose == "", Secrets: a.Secrets})
			if err != nil {
				_ = save()
				return fmt.Errorf("%s (%s): %w", c.Key, c.Instance, err)
			}
			st.Hashes[c.Key] = a.specHash()
		case "remove":
			if err := removeAppInstance(c.Instance, false); err != nil {
				fmt.Fprintf(os.Stderr, "warning: remove %s: %v\n", c.Instance, err)
			}
		}
	}
	return save()
}

// stackDependents are the cluster apps of every stack app that depends on key (allowed through
// the app network policy, so links work in a cluster) and whether any app depends on it at all
// (then, unless it publishes or exposes, it isn't given a host port on a single host).
func stackDependents(s Stack, apps map[string]resolvedApp, key string) (allow []string, depended bool) {
	keys := make([]string, 0, len(s.Apps))
	for k := range s.Apps {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !slices.Contains(s.Apps[k].DependsOn, key) {
			continue
		}
		depended = true
		for _, c := range apps[k].Def.Components {
			allow = append(allow, componentApp(s.Instance(k), apps[k].Def, c))
		}
	}
	return allow, depended
}

// setStackSecrets assigns --secret app.KEY=... values to the stack's apps.
func setStackSecrets(apps map[string]resolvedApp, flags []string) error {
	for _, f := range flags {
		key, rest, ok := strings.Cut(f, ".")
		a, known := apps[key]
		if !ok || !known {
			return fmt.Errorf("--secret %q: want <app>.KEY=..., where <app> is one of the stack's apps", f)
		}
		vals, err := parseSecretFlags([]string{rest})
		if err != nil {
			return err
		}
		if a.Secrets == nil {
			a.Secrets = map[string]string{}
		}
		maps.Copy(a.Secrets, vals)
		apps[key] = a
	}
	return nil
}

// stackNetwork is the local network a stack's containers share (they reach each other by name).
func stackNetwork(stack string) string { return "ziro-stack-" + stack }

func ensureStackNetwork(name string) error {
	if appNerdctl("network", "inspect", name) == nil {
		return nil
	}
	return appNerdctl("network", "create", "--label", "ziro.stack=true", name)
}

// stackLinkValues renders an app's links from its (already deployed) dependencies' outputs, as
// seen from inside a container.
func stackLinkValues(s Stack, a resolvedApp) (map[string]string, error) {
	if len(a.Links) == 0 {
		return nil, nil
	}
	out := map[string]string{}
	for env, ref := range a.Links {
		from, output, _ := strings.Cut(ref, ".")
		in, err := loadAppInstance(s.Instance(from))
		if err != nil {
			return nil, fmt.Errorf("link %s: %s is not deployed", env, from)
		}
		outs, err := appOutputsFor(in, true)
		if err != nil {
			return nil, err
		}
		v, ok := outs[output]
		if !ok {
			return nil, fmt.Errorf("link %s: %s has no output %q", env, from, output)
		}
		out[env] = v
	}
	return out, nil
}

// stackDown removes every app of a stack, dependents first.
func stackDown(name string, purge bool) error {
	st, err := loadStackState(name)
	if err != nil {
		return err
	}
	order, err := st.Stack.Order()
	if err != nil {
		return err
	}
	var errs []error
	for i := len(order) - 1; i >= 0; i-- {
		inst := st.Stack.Instance(order[i])
		if _, err := loadAppInstance(inst); err != nil {
			continue
		}
		if err := removeAppInstance(inst, purge); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", inst, err))
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	_ = appNerdctl("network", "rm", stackNetwork(name)) // local stacks only; harmless otherwise
	return os.Remove(stackStatePath(name))
}

// loadCatalogStacks returns the stacks published in the signed app catalogs (official repos
// first; a name is never shadowed). They only use catalog apps.
func loadCatalogStacks() map[string]Stack {
	items, errs := catalogItems("app")
	out := map[string]Stack{}
	for _, it := range items {
		if it.Type != "stack" {
			continue
		}
		s, err := schema.ParseStack(it.Data)
		if err == nil && s.Stack != it.Name {
			err = fmt.Errorf("stack name %q differs from its index entry", s.Stack)
		}
		if err == nil {
			for key, a := range s.Apps {
				if schema.IsLocalRef(a.App) {
					err = fmt.Errorf("app %s uses a local definition", key)
				}
			}
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("repo %s: stack %s: %w", it.Repo, it.Name, err))
			continue
		}
		if _, taken := out[s.Stack]; !taken {
			out[s.Stack] = s
		}
	}
	for _, err := range errs {
		fmt.Fprintf(os.Stderr, "warning: %v\n", err)
	}
	return out
}

// loadStackFile reads and validates a stack file; local app paths resolve next to it.
func loadStackFile(path string) (Stack, map[string]resolvedApp, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Stack{}, nil, err
	}
	s, err := schema.ParseStack(b)
	if err != nil {
		return s, nil, fmt.Errorf("%s: %w", path, err)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return s, nil, err
	}
	apps, err := resolveStackApps(s, filepath.Dir(abs))
	return s, apps, err
}

func printPlan(plan []StackChange) {
	sym := map[string]string{"create": "+", "update": "~", "unchanged": "=", "remove": "-"}
	for _, c := range plan {
		fmt.Printf("  %s %-14s %-22s %s\n", sym[c.Action], c.Key, c.Instance, c.App)
	}
}

var (
	stackFile        string
	stackDryRun      bool
	stackSecretFlags []string
	stackPurge       bool
)

var stackCmd = &cobra.Command{
	Use:   "stack",
	Short: "Deploy several apps together from one file",
	Example: `  ziroctl stack up -f shop.yaml --dry-run
  ziroctl stack up -f shop.yaml
  ziroctl stack status shop`,
	Long: `A stack deploys apps in dependency order and keeps them as described:

  stack: shop
  version: 1
  apps:
    db:  { app: "postgres:18", set: { database: shop }, resources: { memory: 1Gi } }
    web: { app: ./apps/web/app.yaml, expose: shop.example.com, depends_on: [db] }

ziroctl stack up -f shop.yaml shows the plan and applies it; running it again changes nothing.`,
}

var stackUpCmd = &cobra.Command{
	Use:   "up <catalog-stack> | -f <stack.yaml>",
	Short: "Create, update or remove apps to match a stack",
	Example: `  ziroctl stack up -f shop.yaml --dry-run
  ziroctl stack up -f shop.yaml
  ziroctl stack up analytics
  ziroctl stack up openclaw --secret openclaw.ANTHROPIC_API_KEY=@anthropic.key`,
	Args: func(cmd *cobra.Command, args []string) error {
		if (stackFile == "") == (len(args) == 0) || len(args) > 1 {
			return errors.New("give a catalog stack name or -f <file>")
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		var s Stack
		var apps map[string]resolvedApp
		var err error
		if stackFile != "" {
			s, apps, err = loadStackFile(stackFile)
		} else {
			cs, ok := loadCatalogStacks()[args[0]]
			if !ok {
				refreshStaleCatalogs("app")
				if cs, ok = loadCatalogStacks()[args[0]]; !ok {
					return fmt.Errorf("unknown stack %q (see: ziroctl stack search)", args[0])
				}
			}
			s = cs
			apps, err = resolveStackApps(s, "")
		}
		if err != nil {
			return err
		}
		if err := setStackSecrets(apps, stackSecretFlags); err != nil {
			return err
		}
		prev, err := loadStackState(s.Stack)
		var nf errNotFound
		if err != nil && !errors.As(err, &nf) {
			return err
		}
		plan, err := planStack(s, apps, prev)
		if err != nil {
			return err
		}
		if stackDryRun || jsonOutput {
			if err := printResult(map[string]any{"stack": s.Stack, "plan": plan, "applied": false}, func() {
				fmt.Printf("Plan for stack %s:\n", s.Stack)
				printPlan(plan)
			}); err != nil || stackDryRun {
				return err
			}
		} else {
			fmt.Printf("Plan for stack %s:\n", s.Stack)
			printPlan(plan)
		}
		if err := applyStack(s, apps, plan, prev); err != nil {
			return err
		}
		if !jsonOutput {
			fmt.Printf("✓ stack %s is up\n", s.Stack)
		}
		return nil
	},
}

var stackInitOut string

var stackInitCmd = &cobra.Command{
	Use:   "init <catalog-stack>",
	Short: "Write a catalog stack to a file you can edit",
	Long: `Write a stack from the signed catalog to <dir>/stack.yaml (default: ./<stack>/), to change
hostnames, versions, settings or resources before deploying it with stack up -f.`,
	Example: `  ziroctl stack init wordpress
  ziroctl stack init wordpress -o blog && ziroctl stack up -f blog/stack.yaml --dry-run`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cs, ok := loadCatalogStacks()[args[0]]
		if !ok {
			refreshStaleCatalogs("app")
			if cs, ok = loadCatalogStacks()[args[0]]; !ok {
				return fmt.Errorf("unknown stack %q (see: ziroctl stack search)", args[0])
			}
		}
		out := stackInitOut
		if out == "" {
			out = cs.Stack
		}
		b, err := schema.ToYAML(cs)
		if err != nil {
			return err
		}
		p := filepath.Join(out, "stack.yaml")
		if err := writeNew(p, b, false); err != nil {
			return err
		}
		fmt.Printf("Wrote %s\n  next: ziroctl stack up -f %s --dry-run\n", p, p)
		return nil
	},
}

var stackSearchCmd = &cobra.Command{
	Use:   "search [query]",
	Short: "Search stacks in the app catalogs",
	Example: `  ziroctl stack search
  ziroctl stack search analytics`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		refreshStaleCatalogs("app")
		q := ""
		if len(args) == 1 {
			q = strings.ToLower(args[0])
		}
		var hits []Stack
		for _, s := range loadCatalogStacks() {
			if strings.Contains(s.Stack, q) || strings.Contains(strings.ToLower(s.Description), q) {
				hits = append(hits, s)
			}
		}
		sort.Slice(hits, func(i, j int) bool { return hits[i].Stack < hits[j].Stack })
		return printResult(hits, func() {
			for _, s := range hits {
				keys := make([]string, 0, len(s.Apps))
				for k, a := range s.Apps {
					keys = append(keys, k+"="+a.App)
				}
				sort.Strings(keys)
				fmt.Printf("%-18s %s\n%18s apps: %s\n", s.Stack, s.Description, "", strings.Join(keys, " "))
			}
			fmt.Println("\nDeploy: ziroctl stack up <stack>")
		})
	},
}

var stackLsCmd = &cobra.Command{
	Use:     "ls",
	Short:   "List stacks",
	Example: `  ziroctl stack ls`,
	RunE: func(cmd *cobra.Command, args []string) error {
		stacks := listStacks()
		return printResult(stacks, func() {
			fmt.Printf("%-20s %-5s %s\n", "STACK", "APPS", "APPLIED")
			for _, s := range stacks {
				fmt.Printf("%-20s %-5d %s\n", s.Stack.Stack, len(s.Stack.Apps), s.Applied)
			}
		})
	},
}

// stackStatus is each app of a stack with its live status.
func stackStatus(name string) (map[string]any, error) {
	st, err := loadStackState(name)
	if err != nil {
		return nil, err
	}
	live := map[string]appStatus{}
	for _, a := range appsStatus() {
		live[a.Name] = a
	}
	apps := []map[string]any{}
	order, _ := st.Stack.Order()
	for _, key := range order {
		inst := st.Stack.Instance(key)
		a, ok := live[inst]
		apps = append(apps, map[string]any{"key": key, "instance": inst, "deployed": ok, "status": a})
	}
	return map[string]any{"stack": st.Stack.Stack, "applied": st.Applied, "apps": apps}, nil
}

var stackStatusCmd = &cobra.Command{
	Use:     "status <stack>",
	Short:   "Show a stack's apps and their state",
	Example: `  ziroctl stack status shop`,
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := stackStatus(args[0])
		if err != nil {
			return err
		}
		return printResult(s, func() {
			fmt.Printf("stack %s (applied %s)\n", s["stack"], s["applied"])
			for _, a := range s["apps"].([]map[string]any) {
				st := a["status"].(appStatus)
				fmt.Printf("  %-14s %-22s %-8s %s\n", a["key"], a["instance"], st.Running, st.Publish)
			}
		})
	},
}

var stackDownCmd = &cobra.Command{
	Use:   "down <stack>",
	Short: "Remove a stack's apps",
	Example: `  ziroctl stack down shop
  ziroctl stack down shop --purge`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := stackDown(args[0], stackPurge); err != nil {
			return err
		}
		fmt.Printf("✓ stack %s removed\n", args[0])
		return nil
	},
}

func init() {
	stackUpCmd.Flags().StringVarP(&stackFile, "file", "f", "", "Stack file (YAML or JSON)")
	stackUpCmd.Flags().BoolVar(&stackDryRun, "dry-run", false, "Only show the plan")
	stackUpCmd.Flags().StringArrayVar(&stackSecretFlags, "secret", nil, "Input secret for one app: <app>.KEY=@file, <app>.KEY (from $KEY) or <app>.KEY=value")
	stackDownCmd.Flags().BoolVar(&stackPurge, "purge", false, "Also delete the apps' data and credentials")
	stackInitCmd.Flags().StringVarP(&stackInitOut, "output", "o", "", "Directory to write (default: the stack name)")
	stackCmd.AddCommand(stackUpCmd, stackInitCmd, stackSearchCmd, stackLsCmd, stackStatusCmd, stackDownCmd)
	rootCmd.AddCommand(stackCmd)
}
