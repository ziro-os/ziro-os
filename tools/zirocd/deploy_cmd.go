package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/ziro-os/ziro-os/sdk/api"
	"github.com/ziro-os/ziro-os/sdk/client"
	"github.com/ziro-os/ziro-os/sdk/schema"
	"github.com/ziro-os/zirocd/pack"
)

const maxUploadBytes = 256 << 20 // the server's limit for an archive

var nameRe = regexp.MustCompile(`[^a-z0-9]+`)

// `zirocd deploy`: pack a directory or file, push it to a Ziro OS host, follow the build. The
// token (a "deployer" API token) comes from a file or the environment, never argv.
func deployCmd() *cobra.Command {
	var host, tokenFile, caFile, name, subdir string
	var insecure bool
	var port int
	var envs []string
	var noFollow bool
	c := &cobra.Command{
		Use:   "deploy <dir|file>",
		Short: "Build and run a directory or file on a Ziro OS host",
		Long: `Packs the directory (or single file), uploads it to the host's API and follows the build.
Inside a git work tree it sends what git tracks or could add, so .gitignore is honoured; .env*
files and links are never sent. The host builds it like a repository (Dockerfile, Node, Go,
Python or static files) and releases it, keeping the previous build for rollback.

Create the token on the host: ziroctl api token create ci --role deployer`,
		Example: `  export ZIROCD_DEPLOY_HOST=https://ziro.example.com:8443 ZIROCD_DEPLOY_TOKEN=ziro_...
  zirocd deploy ./mynextjs-app
  zirocd deploy index.html --name landing
  zirocd deploy . --host https://10.0.0.5:8443 --ca-file ziro-api.crt --token-file ~/.ziro-token --port 3000 --env NODE_ENV=production
  zirocd deploy ./site --no-follow --json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if host == "" {
				host = os.Getenv("ZIROCD_DEPLOY_HOST")
			}
			token := os.Getenv("ZIROCD_DEPLOY_TOKEN")
			if tokenFile != "" {
				b, err := os.ReadFile(tokenFile)
				if err != nil {
					return err
				}
				token = strings.TrimSpace(string(b))
			}
			if host == "" || token == "" {
				return errors.New("set --host and a token (--token-file, or ZIROCD_DEPLOY_HOST and ZIROCD_DEPLOY_TOKEN)")
			}
			src, err := filepath.Abs(args[0])
			if err != nil {
				return err
			}
			if name == "" {
				name = defaultName(src)
			}
			if err := schema.ValidName(name); err != nil {
				return fmt.Errorf("--name: %w", err)
			}
			spec := api.SourceSpec{Path: subdir, Port: port}
			for _, kv := range envs {
				k, v, ok := strings.Cut(kv, "=")
				if !ok {
					return fmt.Errorf("--env %q: want KEY=VALUE", kv)
				}
				if spec.Env == nil {
					spec.Env = map[string]string{}
				}
				spec.Env[k] = v
			}
			opts := []client.Option{client.WithUserAgent("zirocd/" + Version)}
			switch {
			case insecure:
				fmt.Fprintln(os.Stderr, "! --insecure: the host's certificate is not checked; anyone on the path can read the token")
				opts = append(opts, client.WithInsecureSkipVerify())
			case caFile != "":
				opts = append(opts, client.WithCAFile(caFile))
			default:
				if pem := trustedCert(host); pem != nil { // saved by zirocd trust
					opts = append(opts, client.WithCAPEM(pem))
				}
			}
			cl, err := client.New(host, token, opts...)
			if err != nil {
				return err
			}

			tmp, err := os.CreateTemp("", "zirocd-deploy-*.tar.gz") // 0600; the upload needs its digest first
			if err != nil {
				return err
			}
			defer os.Remove(tmp.Name())
			defer tmp.Close()
			files, err := pack.Pack(src, tmp, 100000)
			if err != nil {
				return err
			}
			if st, err := tmp.Stat(); err != nil || st.Size() > maxUploadBytes {
				return fmt.Errorf("the archive is over %d MiB: is a build directory in the way?", maxUploadBytes>>20)
			}
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			if !jsonOut {
				fmt.Printf("==> uploading %d files to %s as %s\n", files, host, name)
			}
			b, err := cl.PushSource(ctx, name, spec, tmp)
			if err != nil {
				if client.IsForbidden(err) {
					return fmt.Errorf("%w (the token needs the deployer role)", err)
				}
				return trustHint(err, host)
			}
			id, _ := b["id"].(string)
			if !noFollow && !jsonOut {
				if err := cl.StreamBuildLog(ctx, name, id, os.Stdout); err != nil {
					return err
				}
			}
			res := map[string]any{"app": name, "build": id}
			if !noFollow {
				d, err := cl.Deployment(ctx, name)
				if err != nil {
					return err
				}
				res["url"], res["status"] = d["url"], buildStatus(d, id)
			}
			if err := show(res, func() {
				if noFollow {
					fmt.Printf("✓ queued %s (zirocd deploy follows the log by default)\n", id)
				} else if res["status"] == "live" {
					fmt.Printf("✓ live: %v\n", res["url"])
				}
			}); err != nil {
				return err
			}
			if !noFollow && res["status"] != "live" {
				return fmt.Errorf("build %s %v", id, res["status"])
			}
			return nil
		},
	}
	f := c.Flags()
	f.StringVar(&host, "host", "", "API URL of the Ziro OS host (or set ZIROCD_DEPLOY_HOST)")
	f.StringVar(&tokenFile, "token-file", "", "file holding a deployer API token (or set ZIROCD_DEPLOY_TOKEN)")
	f.StringVar(&caFile, "ca-file", "", "PEM certificate (or CA) that signs the host's API")
	f.BoolVar(&insecure, "insecure", false, "skip certificate checks (prefer: zirocd trust <url>)")
	f.StringVar(&name, "name", "", "app name (default: the directory's name)")
	f.StringVar(&subdir, "path", "", "subdirectory to build (monorepos)")
	f.IntVar(&port, "port", 0, "container port (default: detected)")
	f.StringArrayVar(&envs, "env", nil, "KEY=VALUE for the app (repeatable)")
	f.BoolVar(&noFollow, "no-follow", false, "queue the build and return")
	return c
}

// defaultName names the app after its directory (a file's parent): lower case, dashes.
func defaultName(src string) string {
	if st, err := os.Stat(src); err == nil && !st.IsDir() {
		src = filepath.Dir(src)
	}
	n := strings.Trim(nameRe.ReplaceAllString(strings.ToLower(filepath.Base(src)), "-"), "-")
	if len(n) > 40 {
		n = strings.Trim(n[:40], "-")
	}
	return n
}

// buildStatus is the status of build id in a GET /deployments/{app} answer.
func buildStatus(d map[string]any, id string) any {
	bs, _ := d["builds"].([]any)
	for _, b := range bs {
		if m, _ := b.(map[string]any); m["id"] == id {
			return m["status"]
		}
	}
	return "unknown"
}
