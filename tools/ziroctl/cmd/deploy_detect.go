package cmd

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"strconv"
	"strings"
	"text/template"

	"go.yaml.in/yaml/v3"
)

// How ziroctld builds a repository. A Dockerfile is used as is; otherwise the project type is
// detected and a Dockerfile is generated from an embedded template (base images pinned by
// digest, non-root runtime). ziro.yaml in the repo overrides any of it.

//go:embed deploy_templates/*.Dockerfile
var deployTemplates embed.FS

// DeployConfig is ziro.yaml, all optional.
type DeployConfig struct {
	Build      string            `yaml:"build" json:"build,omitempty"`           // dockerfile, node, next, static, go, python
	Dockerfile string            `yaml:"dockerfile" json:"dockerfile,omitempty"` // path, for build: dockerfile
	Port       int               `yaml:"port" json:"port,omitempty"`
	Start      string            `yaml:"start" json:"start,omitempty"`   // command (node, python)
	Output     string            `yaml:"output" json:"output,omitempty"` // static build output dir (default dist)
	Health     string            `yaml:"health" json:"health,omitempty"` // HTTP path checked before going live
	Env        map[string]string `yaml:"env" json:"env,omitempty"`
}

// BuildPlan is what detection decided.
type BuildPlan struct {
	Kind       string            `json:"kind"`
	Port       int               `json:"port"`
	Health     string            `json:"health,omitempty"`
	Dockerfile string            `json:"-"` // generated content ("" = use the repo's)
	File       string            `json:"dockerfile,omitempty"`
	Env        map[string]string `json:"-"`
}

var (
	exposeRe    = regexp.MustCompile(`(?im)^\s*EXPOSE\s+([0-9]{1,5})`)
	mainPkgRe   = regexp.MustCompile(`(?m)^package main\b`)
	relPathRe   = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,200}$`)
	startCmdRe  = regexp.MustCompile(`^[^\x00\r\n]{1,1000}$`)
	errNoDetect = errors.New("can't tell how to build this repository: add a Dockerfile, or ziro.yaml with build: node|next|static|go|python")
)

// detectBuild reads the project in root (opened with os.Root, so a symlink in the repository
// can't make the daemon read outside it).
func detectBuild(root *os.Root) (BuildPlan, error) {
	exists := func(p string) bool { _, err := root.Stat(p); return err == nil }
	var cfg DeployConfig
	if b, err := root.ReadFile("ziro.yaml"); err == nil {
		dec := yaml.NewDecoder(bytes.NewReader(b))
		dec.KnownFields(true)
		if err := dec.Decode(&cfg); err != nil {
			return BuildPlan{}, fmt.Errorf("ziro.yaml: %w", err)
		}
		if err := cfg.validate(); err != nil {
			return BuildPlan{}, fmt.Errorf("ziro.yaml: %w", err)
		}
	}
	plan := BuildPlan{Kind: cfg.Build, Health: cfg.Health, Env: cfg.Env}
	if plan.Kind == "" {
		switch {
		case exists("Dockerfile") || cfg.Dockerfile != "":
			plan.Kind = "dockerfile"
		case exists("package.json"):
			plan.Kind = "node"
		case exists("go.mod"):
			plan.Kind = "go"
		case exists("requirements.txt") || exists("pyproject.toml"):
			plan.Kind = "python"
		case exists("index.html"):
			plan.Kind = "static"
		case exists("compose.yaml") || exists("docker-compose.yml") || exists("compose.yml") || exists("docker-compose.yaml"):
			return plan, errors.New("this is a Compose project: run it with ziroctl compose up, or convert it with ziroctl stack import")
		default:
			return plan, errNoDetect
		}
	}
	var err error
	switch plan.Kind {
	case "dockerfile":
		plan.File = cfg.Dockerfile
		if plan.File == "" {
			plan.File = "Dockerfile"
		}
		b, rerr := root.ReadFile(plan.File)
		if rerr != nil {
			return plan, fmt.Errorf("%s: %w", plan.File, rerr)
		}
		plan.Port = 8080
		if m := exposeRe.FindSubmatch(b); m != nil {
			plan.Port, _ = strconv.Atoi(string(m[1]))
		}
	case "static":
		if !exists("package.json") { // plain files, served as they are
			plan.Port = 8080
			plan.Dockerfile, err = renderTemplate("static", map[string]any{})
			break
		}
		err = planNode(root, &plan, cfg)
	case "node", "next":
		err = planNode(root, &plan, cfg)
	case "go":
		err = planGo(root, &plan)
	case "python":
		err = planPython(root, &plan, cfg)
	default:
		return plan, fmt.Errorf("unknown build %q", plan.Kind)
	}
	if err != nil {
		return plan, err
	}
	if cfg.Port > 0 {
		plan.Port = cfg.Port
	}
	return plan, nil
}

func (c DeployConfig) validate() error {
	if c.Dockerfile != "" && (!relPathRe.MatchString(c.Dockerfile) || strings.Contains(c.Dockerfile, "..")) {
		return errors.New("dockerfile: a relative path inside the repository")
	}
	if c.Output != "" && (!relPathRe.MatchString(c.Output) || strings.Contains(c.Output, "..")) {
		return errors.New("output: a relative path inside the repository")
	}
	if c.Port < 0 || c.Port > 65535 {
		return errors.New("port: 1..65535")
	}
	if c.Start != "" && !startCmdRe.MatchString(c.Start) {
		return errors.New("start: one line")
	}
	if c.Health != "" && (!healthPathRe.MatchString(c.Health) || strings.HasPrefix(c.Health, "//")) {
		return errors.New("health: an HTTP path such as /healthz")
	}
	for k, v := range c.Env {
		if !envKeyRe.MatchString(k) || strings.HasPrefix(k, "ZIRO_") || strings.ContainsAny(v, "\x00\r\n") {
			return fmt.Errorf("env %q: bad name or value", k)
		}
	}
	return nil
}

type packageJSON struct {
	Scripts         map[string]string `json:"scripts"`
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

func planNode(root *os.Root, plan *BuildPlan, cfg DeployConfig) error {
	b, err := root.ReadFile("package.json")
	if err != nil {
		return err
	}
	var pkg packageJSON
	if err := json.Unmarshal(b, &pkg); err != nil {
		return fmt.Errorf("package.json: %w", err)
	}
	exists := func(p string) bool { _, err := root.Stat(p); return err == nil }
	has := func(dep string) bool { _, a := pkg.Dependencies[dep]; _, b := pkg.DevDependencies[dep]; return a || b }

	pm, setup, install := "npm", "", "npm install"
	switch {
	case exists("pnpm-lock.yaml"):
		pm, setup, install = "pnpm", "corepack enable && ", "pnpm install --frozen-lockfile"
	case exists("yarn.lock"):
		pm, setup, install = "yarn", "corepack enable && ", "yarn install"
	case exists("package-lock.json"):
		install = "npm ci"
	}
	vars := map[string]any{"Setup": setup, "Install": install, "Port": 3000}
	if _, ok := pkg.Scripts["build"]; ok {
		vars["Build"] = pm + " run build"
	}
	if plan.Kind == "node" { // refine: a framework that builds to static files, or Next.js
		switch {
		case has("next"):
			plan.Kind = "next"
		case (has("vite") || has("astro")) && pkg.Scripts["start"] == "" && vars["Build"] != nil:
			plan.Kind = "static"
		}
	}
	tmpl := "node"
	switch plan.Kind {
	case "static":
		if vars["Build"] == nil {
			return errors.New("static build: package.json has no build script")
		}
		out := cfg.Output
		if out == "" {
			out = "dist"
		}
		vars["Output"], tmpl, plan.Port = out, "static", 8080
	default:
		start := cfg.Start
		if start == "" {
			if _, ok := pkg.Scripts["start"]; !ok {
				return errors.New("package.json has no start script: add one, or start: in ziro.yaml")
			}
			start = pm + " start"
		}
		vars["Start"] = shellForm(start)
		plan.Port = 3000
	}
	plan.Dockerfile, err = renderTemplate(tmpl, vars)
	return err
}

func planGo(root *os.Root, plan *BuildPlan) error {
	main := "."
	if !hasMainPackage(root, ".") {
		cmds, _ := fs.ReadDir(root.FS(), "cmd")
		var found []string
		for _, e := range cmds {
			if e.IsDir() && hasMainPackage(root, "cmd/"+e.Name()) {
				found = append(found, "./cmd/"+e.Name())
			}
		}
		if len(found) != 1 {
			return errors.New("can't find the main package (expected in the repository root or a single cmd/<name>): set build: dockerfile")
		}
		main = found[0]
	}
	plan.Port = 8080
	var err error
	plan.Dockerfile, err = renderTemplate("go", map[string]any{"Main": main, "Port": plan.Port})
	return err
}

func hasMainPackage(root *os.Root, dir string) bool {
	ents, err := fs.ReadDir(root.FS(), dir)
	if err != nil {
		return false
	}
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".go") && !strings.HasSuffix(e.Name(), "_test.go") {
			if b, err := root.ReadFile(dir + "/" + e.Name()); err == nil && mainPkgRe.Match(b) {
				return true
			}
		}
	}
	return false
}

func planPython(root *os.Root, plan *BuildPlan, cfg DeployConfig) error {
	install := "pip install ."
	if _, err := root.Stat("requirements.txt"); err == nil {
		install = "pip install -r requirements.txt"
	}
	start := cfg.Start
	if start == "" {
		if b, err := root.ReadFile("Procfile"); err == nil {
			for _, l := range strings.Split(string(b), "\n") {
				if c, ok := strings.CutPrefix(strings.TrimSpace(l), "web:"); ok {
					start = strings.TrimSpace(c)
				}
			}
		}
	}
	if start == "" || !startCmdRe.MatchString(start) {
		return errors.New("python: say how to start it: a Procfile with web: <command>, or start: in ziro.yaml")
	}
	plan.Port = 8000
	var err error
	plan.Dockerfile, err = renderTemplate("python", map[string]any{"Install": install, "Start": shellForm(start), "Port": plan.Port})
	return err
}

// shellForm runs a start command through sh (so $PORT expands), as JSON exec form.
func shellForm(cmd string) string {
	b, _ := json.Marshal([]string{"sh", "-c", "exec " + cmd})
	return string(b)
}

func renderTemplate(name string, vars map[string]any) (string, error) {
	t, err := template.ParseFS(deployTemplates, "deploy_templates/"+name+".Dockerfile")
	if err != nil {
		return "", err
	}
	var b bytes.Buffer
	if err := t.Execute(&b, vars); err != nil {
		return "", err
	}
	return b.String(), nil
}
