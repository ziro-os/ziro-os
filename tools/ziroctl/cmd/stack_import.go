package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/ziro-os/ziro-os/sdk/schema"
)

// `ziroctl stack import compose.yaml`: turn a docker-compose project into a stack and one app
// definition per service, ready for `stack up`. Images are pinned by digest (resolved from the
// registry), named volumes become persistent data, ports and health checks carry over. What
// has no safe equivalent (bind mounts, build, privileged, credentials typed into the file) is
// reported, never silently dropped.

var secretLikeRe = regexp.MustCompile(`(?i)(pass(word)?|secret|token|api_?key|private)`)

// resolveDigest pins an image reference by digest (a reference that has one is kept).
var resolveDigest = func(image string) (string, error) {
	if strings.Contains(image, "@sha256:") {
		r, err := parseImageRef(image)
		if err != nil {
			return "", err
		}
		return r.name() + "@" + r.Digest, nil
	}
	r, err := parseImageRef(image)
	if err != nil {
		return "", err
	}
	d, err := newRegistryClient(r).resolve(r.Tag)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", image, err)
	}
	return r.name() + ":" + r.Tag + "@" + d, nil
}

// composeName makes a compose service name a valid Ziro name.
func composeName(s string) string {
	s = strings.ToLower(strings.NewReplacer("_", "-", ".", "-").Replace(s))
	return strings.Trim(s, "-")
}

// importCompose converts services into a stack and app definitions, with warnings.
func importCompose(stack string, services []ComposeService) (Stack, map[string]AppDef, []string, error) {
	var warn []string
	st := Stack{Stack: stack, Version: 1, Description: "Imported from docker-compose", Apps: map[string]StackApp{}}
	defs := map[string]AppDef{}
	for _, svc := range services {
		name := composeName(svc.Name)
		if err := validName(name); err != nil {
			return st, nil, warn, fmt.Errorf("service %q: %w", svc.Name, err)
		}
		if svc.Image == "" {
			return st, nil, warn, fmt.Errorf("service %s has no image (build: is not supported; publish the image first)", svc.Name)
		}
		for _, u := range svc.Unsupported {
			warn = append(warn, fmt.Sprintf("%s: %q has no Ziro equivalent and was not imported", svc.Name, u))
		}
		img, err := resolveDigest(svc.Image)
		if err != nil {
			return st, nil, warn, fmt.Errorf("service %s: %w", svc.Name, err)
		}
		c := AppComponent{Name: name, Args: svc.Command, Health: svc.Health, Env: map[string]string{}}
		sa := StackApp{App: "./apps/" + name + "/app.yaml"}
		for i, p := range svc.Ports {
			p = strings.TrimSuffix(strings.TrimSuffix(p, "/tcp"), "/udp")
			parts := strings.Split(p, ":")
			cport, err := strconv.Atoi(parts[len(parts)-1])
			if err != nil {
				warn = append(warn, fmt.Sprintf("%s: port %q not understood; skipped", svc.Name, p))
				continue
			}
			if i > 0 {
				warn = append(warn, fmt.Sprintf("%s: only the first port is published (%s skipped)", svc.Name, p))
				continue
			}
			c.Port = cport
			if len(parts) >= 2 {
				if hp, err := strconv.Atoi(parts[len(parts)-2]); err == nil {
					sa.Publish = hp
				}
			}
		}
		for _, v := range svc.Volumes {
			parts := strings.Split(v, ":")
			if len(parts) < 2 {
				continue // an anonymous volume: container-local
			}
			if strings.HasPrefix(parts[0], "/") || strings.HasPrefix(parts[0], ".") || strings.HasPrefix(parts[0], "~") {
				warn = append(warn, fmt.Sprintf("%s: bind mount %s skipped: host paths are not portable (use data or a cluster share)", svc.Name, v))
				continue
			}
			c.Data = append(c.Data, parts[1])
		}
		for _, e := range svc.Environment {
			k, v, _ := strings.Cut(e, "=")
			if !schema.EnvKeyRe.MatchString(k) || strings.HasPrefix(k, "ZIRO_") {
				warn = append(warn, fmt.Sprintf("%s: env %s skipped (invalid name)", svc.Name, k))
				continue
			}
			if secretLikeRe.MatchString(k) && v != "" {
				warn = append(warn, fmt.Sprintf("%s: %s holds a credential typed into the compose file: move it to secrets (generated per host) or a stack link", svc.Name, k))
			}
			if strings.Contains(v, "${") {
				warn = append(warn, fmt.Sprintf("%s: %s uses compose interpolation (%s): set the value explicitly", svc.Name, k, v))
			}
			c.Env[k] = v
		}
		if len(c.Env) == 0 {
			c.Env = nil
		}
		if len(c.Health) == 0 {
			warn = append(warn, fmt.Sprintf("%s: no healthcheck: add one so deploys can wait for readiness", svc.Name))
		}
		d := AppDef{Schema: 1, Name: name, Description: svc.Name + " (imported from docker-compose)", Default: "1",
			Versions: map[string]AppVersion{"1": {Images: map[string]string{name: img}}}, Components: []AppComponent{c}}
		if err := d.Validate(); err != nil {
			return st, nil, warn, fmt.Errorf("service %s: %w", svc.Name, err)
		}
		defs[name] = d
		for _, dep := range svc.DependsOn {
			sa.DependsOn = append(sa.DependsOn, composeName(dep))
		}
		sort.Strings(sa.DependsOn)
		st.Apps[name] = sa
	}
	return st, defs, warn, st.Validate()
}

var (
	importOut  string
	importName string
)

var stackImportCmd = &cobra.Command{
	Use:     "import <docker-compose.yaml>",
	Short:   "Convert a compose project into a stack",
	Example: `  ziroctl stack import docker-compose.yml --name shop --output shop/`,
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		services, err := parseComposeFile(args[0])
		if err != nil {
			return err
		}
		if len(services) == 0 {
			return fmt.Errorf("%s defines no services", args[0])
		}
		name := importName
		if name == "" {
			name = composeName(getProjectName(args[0]))
		}
		st, defs, warn, err := importCompose(name, services)
		if err != nil {
			return err
		}
		out := importOut
		if out == "" {
			out = name
		}
		write := func(rel string, v any) error {
			b, err := schema.ToYAML(v)
			if err != nil {
				return err
			}
			return writeNew(filepath.Join(out, rel), b, false)
		}
		for n, d := range defs {
			if err := write(filepath.Join("apps", n, "app.yaml"), d); err != nil {
				return err
			}
		}
		if err := write("stack.yaml", st); err != nil {
			return err
		}
		for _, w := range warn {
			fmt.Fprintln(os.Stderr, "warning:", w)
		}
		fmt.Printf("✓ %s/stack.yaml and %d app definition(s)\n  next: ziroctl dev validate %s && ziroctl stack up -f %s/stack.yaml --dry-run\n",
			out, len(defs), out, out)
		return nil
	},
}

func init() {
	stackImportCmd.Flags().StringVarP(&importOut, "output", "o", "", "Directory to write (default: the stack name)")
	stackImportCmd.Flags().StringVar(&importName, "name", "", "Stack name (default: the compose project directory)")
	stackCmd.AddCommand(stackImportCmd)
}
