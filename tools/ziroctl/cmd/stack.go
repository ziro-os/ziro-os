package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
		case prev == nil || prev.Hashes[key] != apps[key].specHash():
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
	for _, c := range plan {
		switch c.Action {
		case "create", "update":
			a := apps[c.Key]
			err := deployAppDef(a.Def, a.Version, appDeployOpts{Name: c.Instance, Set: a.Set, Replicas: a.Replicas,
				Publish: a.Publish, Expose: a.Expose, ExposeTLS: a.ExposeTLS})
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
	return os.Remove(stackStatePath(name))
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
	stackFile   string
	stackDryRun bool
	stackPurge  bool
)

var stackCmd = &cobra.Command{
	Use:   "stack",
	Short: "Deploy several apps together from one YAML/JSON file (plan, apply, status, down)",
	Long: `A stack deploys apps in dependency order and keeps them as described:

  stack: shop
  version: 1
  apps:
    db:  { app: "postgres:18", set: { database: shop }, resources: { memory: 1Gi } }
    web: { app: ./apps/web/app.yaml, expose: shop.example.com, depends_on: [db] }

ziroctl stack up -f shop.yaml shows the plan and applies it; running it again changes nothing.`,
}

var stackUpCmd = &cobra.Command{
	Use:   "up -f <stack.yaml>",
	Short: "Plan and apply a stack (create, update and remove apps to match the file)",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		s, apps, err := loadStackFile(stackFile)
		if err != nil {
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

var stackLsCmd = &cobra.Command{
	Use:   "ls",
	Short: "List stacks",
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
	Use:   "status <stack>",
	Short: "Show a stack's apps and their status",
	Args:  cobra.ExactArgs(1),
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
	Short: "Remove a stack's apps (--purge also deletes their data and credentials)",
	Args:  cobra.ExactArgs(1),
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
	_ = stackUpCmd.MarkFlagRequired("file")
	stackUpCmd.Flags().BoolVar(&stackDryRun, "dry-run", false, "Only show the plan")
	stackDownCmd.Flags().BoolVar(&stackPurge, "purge", false, "Also delete the apps' data and credentials")
	stackCmd.AddCommand(stackUpCmd, stackLsCmd, stackStatusCmd, stackDownCmd)
	rootCmd.AddCommand(stackCmd)
}
