package cmd

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

// `ziroctl dev`: the developer toolchain for plugins, apps, catalogs and kernel modules. It works
// on any Linux or macOS machine with Docker and QEMU, inside or outside a Ziro host.

var devCmd = &cobra.Command{
	Use:   "dev",
	Short: "Developer toolchain: scaffold, validate and run plugins and apps; build catalogs, kernel modules, eBPF",
	Long: `Build on Ziro OS:

  ziroctl dev new plugin hello                 # a catalog repo with a plugin, README and CI workflow
  ziroctl dev new app web
  ziroctl dev validate modules/hello/manifest.json apps/web/app.json
  ziroctl dev run modules/hello/manifest.json  # boots a throwaway Ziro VM and enables it
  ziroctl dev run apps/web/app.json --forward 8080:8080 --check 'curl -s http://127.0.0.1:8080/'
  ziroctl dev catalog keygen acme              # signing key for your own catalog
  ziroctl dev kmod build ./mydriver            # out-of-tree kernel module against the Ziro kernel
  ziroctl dev bpf build probe.bpf.c            # CO-RE eBPF program (BTF from the Ziro kernel)

See docs/sdk.md.`,
}

// ---- dev new ----

var devNewDir string

// appScaffold is a small, valid app to start from: a static web server running as a non-root user.
func appScaffold(name string) AppDef {
	return AppDef{
		Schema: 1, Name: name, Description: "What " + name + " does, in one line", Default: "1",
		Versions: map[string]AppVersion{"1": {Images: map[string]string{
			"web": "docker.io/nginxinc/nginx-unprivileged:1.29-alpine@sha256:0c79d56aee561a1d81c63f00eee5fb5fe29279560cdc55e91425133104c7fbe6",
		}}},
		Components: []AppComponent{{Name: "web", Port: 8080,
			Health: []string{"wget", "-qO-", "http://127.0.0.1:8080/"}}},
		Outputs: map[string]string{"url": "http://{{host}}:{{port}}/"},
	}
}

// catalogWorkflow is a GitHub Actions workflow for a third-party catalog: it verifies a released
// ziroctl, validates every definition on pull requests, and on main builds, signs and publishes
// the catalog to GitHub Pages.
func catalogWorkflow(kind, repo string) string {
	return strings.NewReplacer("{{KIND}}", kind, "{{REPO}}", repo).Replace(`name: catalog

on:
  pull_request:
  push:
    branches: [main]
  schedule:
    - cron: "17 3 * * 1" # re-sign weekly: hosts refuse an index past its 30-day expiry
  workflow_dispatch:

permissions:
  contents: read

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - name: Install ziroctl (verified against the release SHA256SUMS)
        run: |
          base=https://github.com/ziro-os/ziro-os/releases/latest/download
          curl -fsSLO "$base/ziroctl-x86_64" -O "$base/SHA256SUMS"
          grep ' ziroctl-x86_64$' SHA256SUMS | sha256sum -c -
          install -m 0755 ziroctl-x86_64 /usr/local/bin/ziroctl
      - name: Validate and build the catalog
        run: |
          ziroctl dev validate --strict .
          ziroctl catalog build . --repo {{REPO}} --kind {{KIND}} --out public
          cp catalog.pub public/
      - name: Sign
        if: github.event_name != 'pull_request'
        env:
          ZIRO_CATALOG_KEY: ${{ secrets.ZIRO_CATALOG_KEY }}
        run: |
          ziroctl catalog sign public
          ziroctl catalog verify public --repo {{REPO}} --kind {{KIND}} --key catalog.pub
      - uses: actions/upload-pages-artifact@v3
        if: github.event_name != 'pull_request'
        with:
          path: public

  deploy:
    if: github.event_name != 'pull_request' && github.ref == 'refs/heads/main'
    needs: build
    runs-on: ubuntu-latest
    permissions:
      pages: write
      id-token: write
    environment:
      name: github-pages
      url: ${{ steps.deploy.outputs.page_url }}
    steps:
      - id: deploy
        uses: actions/deploy-pages@v4
`)
}

// writeNew writes a file, refusing to overwrite unless it's a shared catalog file that exists.
func writeNew(path string, data []byte, keepExisting bool) error {
	if fileExists(path) {
		if keepExisting {
			return nil
		}
		return fmt.Errorf("%s exists", path)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

var devNewCmd = &cobra.Command{
	Use:   "new plugin|app <name>",
	Short: "Scaffold a plugin or app in a catalog repository (definition, README, signing CI)",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		kind, name := args[0], args[1]
		if err := validName(name); err != nil {
			return err
		}
		dir := devNewDir
		if dir == "" {
			dir = "."
		}
		var path string
		var def []byte
		switch kind {
		case "plugin", "module":
			m := scaffoldPlugin(name)
			if err := m.Validate(); err != nil {
				return err
			}
			path = filepath.Join(dir, "modules", name, "manifest.json")
			def, _ = json.MarshalIndent(m, "", "  ")
			kind = "module"
		case "app":
			d := appScaffold(name)
			if err := d.Validate(); err != nil {
				return err
			}
			path = filepath.Join(dir, "apps", name, "app.json")
			def, _ = json.MarshalIndent(d, "", "  ")
		default:
			return fmt.Errorf("kind must be plugin or app")
		}
		if err := writeNew(path, append(def, '\n'), false); err != nil {
			return err
		}
		abs, _ := filepath.Abs(dir)
		repo := filepath.Base(abs)
		if validName(repo) != nil {
			repo = "my-catalog"
		}
		_ = writeNew(filepath.Join(dir, ".github", "workflows", "catalog.yml"), []byte(catalogWorkflow(kind, repo)), true)
		_ = writeNew(filepath.Join(dir, "README.md"), []byte("# "+repo+"\n\nA Ziro OS "+kind+" catalog. Hosts trust it with:\n\n"+
			"    ziroctl plugin repo add "+repo+" https://<owner>.github.io/<repo> --key catalog.pub --kind "+kind+"\n\n"+
			"Develop: `ziroctl dev validate .`, `ziroctl dev run <definition>`. Signing: `ziroctl dev catalog keygen "+repo+"`,\n"+
			"then store the private key as the ZIRO_CATALOG_KEY repository secret and commit catalog.pub.\n"), true)
		fmt.Printf("✓ created %s\n  next: ziroctl dev validate %s && ziroctl dev run %s\n", path, path, path)
		return nil
	},
}

// ---- dev validate ----

// lintFinding is a validation error (blocks publishing) or a warning (a security or reliability
// smell the schema allows).
type lintFinding struct {
	File    string `json:"file"`
	Level   string `json:"level"` // error, warning
	Message string `json:"message"`
}

// definitionKind tells a plugin manifest from an app definition by its shape.
func definitionKind(b []byte) string {
	var probe map[string]json.RawMessage
	if json.Unmarshal(b, &probe) != nil {
		return ""
	}
	if _, ok := probe["components"]; ok {
		return "app"
	}
	return "module"
}

func lintDefinition(path string, b []byte) []lintFinding {
	var out []lintFinding
	add := func(level, msg string) { out = append(out, lintFinding{path, level, msg}) }
	switch definitionKind(b) {
	case "app":
		d, err := parseAppDef(b)
		if err != nil {
			add("error", err.Error())
			return out
		}
		for _, c := range d.Components {
			if len(c.Health) == 0 {
				add("warning", "component "+c.Name+" has no health command: deploys can't wait for readiness")
			}
			if len(c.Args) > 0 && (c.Args[0] == "sh" || c.Args[0] == "bash" || strings.HasSuffix(c.Args[0], "/sh")) {
				joined := strings.Join(c.Args, " ")
				if !strings.Contains(joined, "setpriv") && !strings.Contains(joined, "gosu") && !strings.Contains(joined, "su-exec") &&
					!strings.Contains(joined, "docker-entrypoint") {
					add("warning", "component "+c.Name+" wraps its command in a shell without dropping privileges (setpriv/gosu): it may run as root")
				}
			}
		}
	case "module":
		m, err := parseManifest(b)
		if err != nil {
			add("error", err.Error())
			return out
		}
		for _, s := range m.Services {
			if s.User == "" || s.User == "root" {
				add("warning", "service "+s.Name+" runs as root: set \"user\" to an unprivileged account")
			}
		}
		if len(m.Services) > 0 && m.Health == nil {
			add("warning", "no health check: enable can't tell a broken service from a working one")
		}
		for _, st := range m.Settings {
			if (st.Name == "bind" || strings.HasSuffix(st.Name, "_bind")) && st.Default != "127.0.0.1" && st.Default != "::1" {
				add("warning", "setting "+st.Name+" defaults to "+st.Default+": bind to loopback by default and let operators expose it")
			}
		}
		for _, a := range m.Artifacts {
			if a.Arch == "" && (strings.Contains(a.URL, "amd64") || strings.Contains(a.URL, "x86_64") || strings.Contains(a.URL, "arm64")) {
				add("warning", "artifact "+a.Path+" looks architecture-specific: set \"arch\"")
			}
		}
	default:
		add("error", "not a plugin manifest or app definition (invalid JSON)")
	}
	return out
}

// definitionFiles expands directories into the catalog layout's definition files.
func definitionFiles(paths []string) ([]string, error) {
	var out []string
	for _, p := range paths {
		fi, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		if !fi.IsDir() {
			out = append(out, p)
			continue
		}
		for _, pat := range []string{"modules/*/manifest.json", "apps/*/app.json", "examples/*/manifest.json"} {
			m, _ := filepath.Glob(filepath.Join(p, pat))
			out = append(out, m...)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no plugin manifests or app definitions found")
	}
	return out, nil
}

var devStrict bool

var devValidateCmd = &cobra.Command{
	Use:   "validate <file|catalog-dir...>",
	Short: "Validate plugin manifests and app definitions (the host's rules) and lint them",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		files, err := definitionFiles(args)
		if err != nil {
			return err
		}
		var all []lintFinding
		for _, f := range files {
			b, err := os.ReadFile(f)
			if err != nil {
				return err
			}
			all = append(all, lintDefinition(f, b)...)
		}
		errs, warns := 0, 0
		for _, l := range all {
			if l.Level == "error" {
				errs++
			} else {
				warns++
			}
		}
		perr := printResult(map[string]any{"files": files, "findings": all}, func() {
			for _, l := range all {
				fmt.Printf("%s: %s: %s\n", l.File, l.Level, l.Message)
			}
			fmt.Printf("%d file(s): %d error(s), %d warning(s)\n", len(files), errs, warns)
		})
		if perr != nil {
			return perr
		}
		if errs > 0 || devStrict && warns > 0 {
			return fmt.Errorf("validation failed")
		}
		return nil
	},
}

// ---- dev catalog ----

var devCatalogCmd = &cobra.Command{Use: "catalog", Short: "Your own catalog's signing key (build, sign and verify with `ziroctl catalog`)"}

var devKeygenCmd = &cobra.Command{
	Use:   "keygen <name>",
	Short: "Create an ed25519 catalog signing key: <name>.key (keep secret) and <name>.pub (commit it)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := validName(args[0]); err != nil {
			return err
		}
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		pb, _ := x509.MarshalPKIXPublicKey(pub)
		sb, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return err
		}
		keyPath, pubPath := args[0]+".key", args[0]+".pub"
		if fileExists(keyPath) || fileExists(pubPath) {
			return fmt.Errorf("%s or %s exists", keyPath, pubPath)
		}
		f, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		if err := pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: sb}); err != nil {
			f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		var pubPEM bytes.Buffer
		_ = pem.Encode(&pubPEM, &pem.Block{Type: "PUBLIC KEY", Bytes: pb})
		if err := os.WriteFile(pubPath, pubPEM.Bytes(), 0644); err != nil {
			return err
		}
		fmt.Printf("✓ %s (private, 0600: store it as the ZIRO_CATALOG_KEY CI secret, then delete it here)\n✓ %s (public: commit it as catalog.pub)\n", keyPath, pubPath)
		return nil
	},
}

func init() {
	devNewCmd.Flags().StringVar(&devNewDir, "dir", ".", "Catalog repository directory")
	devValidateCmd.Flags().BoolVar(&devStrict, "strict", false, "Treat warnings as errors (CI)")
	devCatalogCmd.AddCommand(devKeygenCmd) // build/sign/verify: `ziroctl catalog ...`
	devCmd.AddCommand(devNewCmd, devValidateCmd, devCatalogCmd)
	rootCmd.AddCommand(devCmd)
}
