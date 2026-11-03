package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// Compose health checks on nerdctl. nerdctl compose 2.2.1 ignores a service's `healthcheck:` and
// starts every service without waiting for `depends_on: condition: service_healthy`, and `up --wait`
// does not wait. The wrapper reads the resolved compose file (`nerdctl compose config`), puts each
// service's health check on its containers (nerdctl's health label, which `ziroctl container health
// serve` and `docker inspect` use), and, when a dependency must be healthy or --wait is given, runs
// `up -d` as create, then start service by service in dependency order, waiting where asked.

// composeProjectHealth is what the wrapper needs from a resolved compose file.
type composeProjectHealth struct {
	Name     string
	Health   map[string]healthConfig      // service -> its health check (Test ["NONE"] when disabled)
	Depends  map[string]map[string]string // service -> dependency -> condition
	Services []string                     // in file order
}

func (p composeProjectHealth) needsOrderedStart() bool {
	for _, deps := range p.Depends {
		for _, cond := range deps {
			if cond == "service_healthy" {
				return true
			}
		}
	}
	return false
}

// composeDuration reads a compose duration: "1m30s", "10s" or a number of seconds.
func composeDuration(v any) time.Duration {
	switch x := v.(type) {
	case string:
		if d, err := time.ParseDuration(x); err == nil {
			return d
		}
		if n, err := strconv.ParseFloat(x, 64); err == nil {
			return time.Duration(n * float64(time.Second))
		}
	case int:
		return time.Duration(x) * time.Second
	case float64:
		return time.Duration(x * float64(time.Second))
	}
	return 0
}

// parseComposeHealth reads the services, health checks and dependencies of a compose file.
func parseComposeHealth(b []byte) (composeProjectHealth, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return composeProjectHealth{}, err
	}
	var raw struct {
		Name     string `yaml:"name"`
		Services map[string]struct {
			Healthcheck *struct {
				Test        any `yaml:"test"`
				Interval    any `yaml:"interval"`
				Timeout     any `yaml:"timeout"`
				Retries     int `yaml:"retries"`
				StartPeriod any `yaml:"start_period"`
				Disable     bool
			} `yaml:"healthcheck"`
			DependsOn yaml.Node `yaml:"depends_on"`
		} `yaml:"services"`
	}
	if err := doc.Decode(&raw); err != nil {
		return composeProjectHealth{}, err
	}
	p := composeProjectHealth{Name: raw.Name, Health: map[string]healthConfig{}, Depends: map[string]map[string]string{}}
	// file order of services, for a stable start order among equals
	if len(doc.Content) > 0 {
		root := doc.Content[0]
		for i := 0; i+1 < len(root.Content); i += 2 {
			if root.Content[i].Value == "services" {
				svcs := root.Content[i+1]
				for j := 0; j+1 < len(svcs.Content); j += 2 {
					p.Services = append(p.Services, svcs.Content[j].Value)
				}
			}
		}
	}
	for name, s := range raw.Services {
		if hc := s.Healthcheck; hc != nil {
			c := healthConfig{Interval: composeDuration(hc.Interval), Timeout: composeDuration(hc.Timeout), Retries: hc.Retries,
				StartPeriod: composeDuration(hc.StartPeriod)}
			switch t := hc.Test.(type) {
			case string:
				c.Test = []string{"CMD-SHELL", t}
			case []any:
				for _, x := range t {
					c.Test = append(c.Test, fmt.Sprint(x))
				}
			}
			if hc.Disable {
				c.Test = []string{"NONE"}
			}
			if len(c.Test) > 0 {
				p.Health[name] = c
			}
		}
		deps := map[string]string{}
		switch s.DependsOn.Kind {
		case yaml.SequenceNode:
			for _, d := range s.DependsOn.Content {
				deps[d.Value] = "service_started"
			}
		case yaml.MappingNode:
			for i := 0; i+1 < len(s.DependsOn.Content); i += 2 {
				var v struct {
					Condition string `yaml:"condition"`
				}
				_ = s.DependsOn.Content[i+1].Decode(&v)
				if v.Condition == "" {
					v.Condition = "service_started"
				}
				deps[s.DependsOn.Content[i].Value] = v.Condition
			}
		}
		if len(deps) > 0 {
			p.Depends[name] = deps
		}
	}
	return p, nil
}

// composeStartOrder orders services so each comes after its dependencies (Kahn's algorithm, ties in
// file order). A dependency cycle is an error, as in Compose.
func composeStartOrder(p composeProjectHealth, only []string) ([]string, error) {
	want := map[string]bool{}
	var add func(s string)
	add = func(s string) {
		if want[s] {
			return
		}
		want[s] = true
		for d := range p.Depends[s] {
			add(d)
		}
	}
	if len(only) == 0 {
		only = p.Services
	}
	for _, s := range only {
		add(s)
	}
	var order []string
	done := map[string]bool{}
	for len(order) < len(want) {
		progressed := false
		for _, s := range p.Services {
			if !want[s] || done[s] {
				continue
			}
			ready := true
			for d := range p.Depends[s] {
				if want[d] && !done[d] {
					ready = false
				}
			}
			if ready {
				order = append(order, s)
				done[s] = true
				progressed = true
			}
		}
		if !progressed {
			return nil, fmt.Errorf("dependency cycle between the services %v", slices.Collect(func(yield func(string) bool) {
				for _, s := range p.Services {
					if want[s] && !done[s] && !yield(s) {
						return
					}
				}
			}))
		}
	}
	return order, nil
}

// composeContainers lists the containers of one service of a project.
func composeContainers(ctx context.Context, c *ctrdClient, project, service string) ([]ctrdContainer, error) {
	return c.Containers(ctx, ctrdLabelFilter("com.docker.compose.project", project)+","+ctrdLabelFilter("com.docker.compose.service", service))
}

// applyComposeHealth puts each service's health check on its containers.
func applyComposeHealth(ctx context.Context, c *ctrdClient, p composeProjectHealth) error {
	for svc, hc := range p.Health {
		cts, err := composeContainers(ctx, c, p.Name, svc)
		if err != nil {
			return err
		}
		b, _ := json.Marshal(hc)
		for _, ct := range cts {
			if ct.Labels[healthLabel] == string(b) {
				continue
			}
			if err := c.UpdateLabel(ctx, ct.ID, healthLabel, string(b)); err != nil {
				return err
			}
		}
	}
	return nil
}

// serviceHealth is the health of a service's containers: "healthy" when every one is, "unhealthy"
// when one is, otherwise "starting".
func serviceHealth(cts []ctrdContainer) string {
	if len(cts) == 0 {
		return "starting"
	}
	all := true
	for _, ct := range cts {
		var st struct{ Status string }
		_ = json.Unmarshal([]byte(ct.Labels[healthStateLabel]), &st)
		switch st.Status {
		case "unhealthy":
			return "unhealthy"
		case "healthy":
		default:
			all = false
		}
	}
	if all {
		return "healthy"
	}
	return "starting"
}

// waitHealthy waits until the services are healthy, running their checks itself meanwhile (so it
// works whether or not the container-health service runs). A service with no health check counts as
// healthy once it runs.
func waitHealthy(ctx context.Context, c *ctrdClient, p composeProjectHealth, services []string, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}
	deadline := time.Now().Add(timeout)
	sched := newHealthScheduler()
	for {
		pending := ""
		var targets []healthTarget
		for _, svc := range services {
			cts, err := composeContainers(ctx, c, p.Name, svc)
			if err != nil {
				return err
			}
			hc, has := p.Health[svc]
			if !has || !hc.enabled() {
				continue
			}
			switch serviceHealth(cts) {
			case "unhealthy":
				return fmt.Errorf("dependency failed to start: service %s is unhealthy", svc)
			case "starting":
				pending = svc
				for _, ct := range cts {
					if t, err := c.Task(ctx, ct.ID); err == nil && t.Status == ctrdTaskRunning {
						targets = append(targets, healthTarget{ID: ct.ID, Pid: t.Pid, HC: hc})
					}
				}
			}
		}
		if pending == "" {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out after %s waiting for service %s to be healthy", timeout, pending)
		}
		for _, t := range sched.due(time.Now(), targets) {
			_ = runHealthcheck(ctx, t.ID, t.HC)
			sched.done(t.ID, t.HC, time.Now())
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

// composeUpOrdered is `compose up -d` for a project whose services wait for each other: create every
// container, put the health checks on them, then start each service once the dependencies it waits for
// are healthy. With wait, it then waits for all the started services. createArgs is the `compose …
// create …` command line; services are the ones named on the command line (none: all).
func composeUpOrdered(ctx context.Context, run nerdctlRunner, p composeProjectHealth, globals, createArgs, services []string, wait bool, waitTimeout time.Duration) error {
	order, err := composeStartOrder(p, services)
	if err != nil {
		return err
	}
	if _, err := run(createArgs...); err != nil {
		return err
	}
	c := newCtrdClient(containerdSocket, containerdNamespace())
	if err := applyComposeHealth(ctx, c, p); err != nil {
		return err
	}
	for _, svc := range order {
		var healthyDeps []string
		for d, cond := range p.Depends[svc] {
			if cond == "service_healthy" {
				healthyDeps = append(healthyDeps, d)
			}
		}
		slices.Sort(healthyDeps)
		if len(healthyDeps) > 0 {
			if err := waitHealthy(ctx, c, p, healthyDeps, waitTimeout); err != nil {
				return err
			}
		}
		if _, err := run(append(append([]string{"compose"}, globals...), "start", svc)...); err != nil {
			return err
		}
	}
	if wait {
		return waitHealthy(ctx, c, p, order, waitTimeout)
	}
	return nil
}

// composeUpFlags splits `compose up` arguments into the create flags, the services, and --wait.
func composeUpFlags(rest []string) (services []string, detached, wait bool, waitTimeout time.Duration) {
	for j := 0; j < len(rest); j++ {
		a := rest[j]
		name, val, hasValue := strings.Cut(a, "=")
		switch {
		case a == "--":
			return append(services, rest[j+1:]...), detached, wait, waitTimeout
		case a == "-d" || a == "--detach":
			detached = true
		case a == "--wait" || (name == "--wait" && val != "false"):
			wait = true
		case name == "--wait-timeout":
			if !hasValue && j+1 < len(rest) {
				val = rest[j+1]
				j++
			}
			if n, err := strconv.Atoi(val); err == nil {
				waitTimeout = time.Duration(n) * time.Second
			}
		case composeUpValue[name] && !hasValue:
			j++
		case !strings.HasPrefix(a, "-"):
			services = append(services, a)
		}
	}
	return services, detached, wait, waitTimeout
}

// composeHealthLabels reads the resolved compose file and puts the health checks on the containers.
func composeHealthLabels(globals []string, run nerdctlRunner) error {
	cfg, err := run(append(append([]string{"compose"}, globals...), "config")...)
	if err != nil {
		return err
	}
	p, err := parseComposeHealth(cfg)
	if err != nil || len(p.Health) == 0 {
		return err
	}
	if p.Name == "" {
		wd, _ := os.Getwd()
		p.Name = composeProject(globals, os.Getenv, wd)
	}
	return applyComposeHealth(context.Background(), newCtrdClient(containerdSocket, containerdNamespace()), p)
}

// composeUpNative is `compose up -d`: nerdctl's own up when no service waits for a healthy one and
// --wait is not given (then the health checks are put on the containers), the ordered start otherwise.
func composeUpNative(globals, rest, upArgs, services []string, wait bool, waitTimeout time.Duration, run nerdctlRunner) error {
	cfg, err := run(append(append([]string{"compose"}, globals...), "config")...)
	p, perr := parseComposeHealth(cfg)
	if err != nil || perr != nil {
		// Without the resolved file there is nothing to order or check: nerdctl's own up, as before.
		_, err := run(upArgs...)
		return err
	}
	if p.Name == "" {
		wd, _ := os.Getwd()
		p.Name = composeProject(globals, os.Getenv, wd)
	}
	ctx := context.Background()
	if !wait && !p.needsOrderedStart() {
		if _, err := run(upArgs...); err != nil {
			return err
		}
		if len(p.Health) == 0 {
			return nil
		}
		return applyComposeHealth(ctx, newCtrdClient(containerdSocket, containerdNamespace()), p)
	}
	if slices.Contains(rest, "--remove-orphans") {
		if err := removeComposeOrphans(globals, run); err != nil {
			fmt.Fprintln(os.Stderr, "docker: warning: "+err.Error())
		}
	}
	createArgs := composeUpNoStart(append([]string{"compose"}, globals...), rest)
	return composeUpOrdered(ctx, run, p, globals, createArgs, services, wait, waitTimeout)
}
