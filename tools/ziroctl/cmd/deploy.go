package cmd

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

// `ziroctl deploy`: build an app from a git repository and run it, the way Vercel or Render do.
// The work happens in ziroctld (the deploy daemon, enabled by the builder plugin); this is its
// command line.

var (
	deployName, deployRef, deployPath, deployExpose, deployExposeTLS, deployTokenFile string
	deployPort, deployPublish                                                         int
	deployEnv, deploySecrets                                                          []string
	deployMemory                                                                      string
	deployCPUs                                                                        float64
	deployNoFollow, deployPurge                                                       bool
	deployBuildID                                                                     string
)

var deployCmd = &cobra.Command{
	Use:   "deploy <https-git-url>",
	Short: "Build and run an app from a git repository",
	Long: `Build an app from a git repository and run it on this host, then keep its builds for
rollback. ziroctld (the deploy daemon, from the builder plugin) clones the branch, picks the
build, builds the image with BuildKit and releases it once it answers on its port:

  Dockerfile                 used as is
  package.json               Next.js, Node (npm/pnpm/yarn start), or a static Vite/Astro build
  go.mod                     a static binary on distroless
  requirements.txt/pyproject Python, started by the Procfile's web command
  index.html                 served as static files

ziro.yaml in the repository can set build, dockerfile, port, start, output, health and env.
The app runs like a catalog app: hardened container, secrets in env files, and published on
127.0.0.1 (or through the gateway with --expose). A release that doesn't answer is replaced
by the previous build.`,
	Example: `  ziroctl module enable builder
  ziroctl deploy https://github.com/acme/web --expose web.example.com
  ziroctl deploy https://github.com/acme/api --branch release --env LOG_LEVEL=info --secret DATABASE_URL=@db.url
  ziroctl deploy https://gitlab.com/acme/mono --path apps/site --git-token-file ~/.gitlab-token
  ziroctl deploy ls
  ziroctl deploy logs web -f
  ziroctl deploy rollback web`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		env, err := parseSetFlags(deployEnv)
		if err != nil {
			return fmt.Errorf("--env: %w", err)
		}
		secrets, err := parseSecretFlags(deploySecrets)
		if err != nil {
			return err
		}
		name := deployName
		if name == "" {
			name = nameFromRepo(args[0])
		}
		req := DeployRequest{Deployment: Deployment{Name: name, Repo: args[0], Ref: deployRef, Path: deployPath,
			Port: deployPort, Publish: deployPublish, Env: env, Expose: deployExpose, ExposeTLS: deployExposeTLS},
			SecretValues: secrets}
		if deployMemory != "" || deployCPUs > 0 {
			req.Resources = &Resources{Memory: deployMemory, CPUs: deployCPUs}
		}
		if deployTokenFile != "" {
			b, err := os.ReadFile(deployTokenFile)
			if err != nil {
				return err
			}
			req.GitToken = strings.TrimSpace(string(b))
		}
		var b Build
		if err := deployCall("POST", "/v1/deployments", req, &b); err != nil {
			return err
		}
		return afterQueued(b)
	},
}

// afterQueued prints the queued build and, unless --no-follow (or --json), streams its log.
func afterQueued(b Build) error {
	if jsonOutput {
		return printResult(b, nil)
	}
	fmt.Printf("Queued %s build %s\n", b.App, b.ID)
	if deployNoFollow {
		fmt.Printf("  follow it: ziroctl deploy logs %s -f\n", b.App)
		return nil
	}
	return followBuild(b.App, b.ID)
}

func followBuild(app, id string) error {
	resp, err := deployRaw("GET", "/v1/deployments/"+app+"/builds/"+id+"/log?follow=true", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if _, err := io.Copy(os.Stdout, resp.Body); err != nil {
		return err
	}
	var st struct {
		Builds []Build `json:"builds"`
		URL    string  `json:"url"`
	}
	if err := deployCall("GET", "/v1/deployments/"+app, nil, &st); err != nil {
		return err
	}
	for _, b := range st.Builds {
		if b.ID == id {
			if b.Status == "failed" {
				return fmt.Errorf("build %s failed: %s", id, b.Error)
			}
			fmt.Printf("%s is live at %s\n", app, st.URL)
		}
	}
	return nil
}

// nameFromRepo is the app name a repository gets by default: its last path element, cleaned.
func nameFromRepo(repo string) string {
	u, err := url.Parse(repo)
	if err != nil {
		return ""
	}
	n := strings.ToLower(strings.TrimSuffix(path.Base(u.Path), ".git"))
	var b strings.Builder
	for _, r := range n {
		switch {
		case r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-':
			b.WriteRune(r)
		case r == '_' || r == '.':
			b.WriteRune('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

var deployLsCmd = &cobra.Command{
	Use:     "ls",
	Short:   "List deployments and their latest build",
	Example: `  ziroctl deploy ls`,
	Args:    cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		var rows []struct {
			Deployment Deployment `json:"deployment"`
			URL        string     `json:"url"`
			Latest     *Build     `json:"latest"`
		}
		if err := deployCall("GET", "/v1/deployments", nil, &rows); err != nil {
			return err
		}
		return printResult(rows, func() {
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "NAME\tLIVE\tLATEST\tSTATUS\tCOMMIT\tURL\tREPO")
			for _, r := range rows {
				id, st, commit := "-", "-", "-"
				if r.Latest != nil {
					id, st, commit = r.Latest.ID, r.Latest.Status, shortCommit(r.Latest.Commit)
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", r.Deployment.Name, orDash(r.Deployment.Live), id, st, commit, r.URL, r.Deployment.Repo)
			}
			tw.Flush()
		})
	},
}

var deployStatusCmd = &cobra.Command{
	Use:     "status <app>",
	Short:   "Show a deployment and its builds",
	Example: `  ziroctl deploy status web`,
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		var st struct {
			Deployment Deployment `json:"deployment"`
			URL        string     `json:"url"`
			Builds     []Build    `json:"builds"`
		}
		if err := deployCall("GET", "/v1/deployments/"+args[0], nil, &st); err != nil {
			return err
		}
		return printResult(st, func() {
			d := st.Deployment
			fmt.Printf("%s  %s\n  repo   %s %s%s\n  live   %s\n", d.Name, st.URL, d.Repo, orDash(d.Ref), map[bool]string{true: " (" + d.Path + ")", false: ""}[d.Path != ""], orDash(d.Live))
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "\nBUILD\tSTATUS\tKIND\tCOMMIT\tQUEUED\tTOOK\tERROR")
			for _, b := range st.Builds {
				took := "-"
				if !b.Finished.IsZero() && !b.Started.IsZero() {
					took = b.Finished.Sub(b.Started).Round(time.Second).String()
				}
				kind := b.Kind
				if b.Rollback {
					kind = "rollback"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", b.ID, b.Status, orDash(kind), shortCommit(b.Commit),
					b.Queued.Local().Format("Jan 2 15:04"), took, b.Error)
			}
			tw.Flush()
		})
	},
}

var deployLogsFollow bool

var deployLogsCmd = &cobra.Command{
	Use:   "logs <app>",
	Short: "Show the log of a build",
	Example: `  ziroctl deploy logs web
  ziroctl deploy logs web --build b3
  ziroctl deploy logs web -f`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		id := deployBuildID
		if id == "" {
			var st struct {
				Builds []Build `json:"builds"`
			}
			if err := deployCall("GET", "/v1/deployments/"+args[0], nil, &st); err != nil {
				return err
			}
			if len(st.Builds) == 0 {
				return errors.New("no builds yet")
			}
			id = st.Builds[0].ID
		}
		resp, err := deployRaw("GET", "/v1/deployments/"+args[0]+"/builds/"+id+"/log?follow="+fmt.Sprint(deployLogsFollow), nil)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		_, err = io.Copy(os.Stdout, resp.Body)
		return err
	},
}

var deployRedeployCmd = &cobra.Command{
	Use:   "redeploy <app>",
	Short: "Build the latest commit again and release it",
	Example: `  ziroctl deploy redeploy web
  ziroctl deploy redeploy web --branch hotfix`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		var b Build
		if err := deployCall("POST", "/v1/deployments/"+args[0]+"/redeploy", map[string]string{"ref": deployRef}, &b); err != nil {
			return err
		}
		return afterQueued(b)
	},
}

var deployRollbackCmd = &cobra.Command{
	Use:   "rollback <app> [build]",
	Short: "Release an earlier build again, without rebuilding",
	Example: `  ziroctl deploy rollback web
  ziroctl deploy rollback web b4`,
	Args: cobra.RangeArgs(1, 2),
	RunE: func(cmd *cobra.Command, args []string) error {
		body := map[string]string{}
		if len(args) == 2 {
			body["build"] = args[1]
		}
		var b Build
		if err := deployCall("POST", "/v1/deployments/"+args[0]+"/rollback", body, &b); err != nil {
			return err
		}
		return afterQueued(b)
	},
}

var deployRmCmd = &cobra.Command{
	Use:   "rm <app>",
	Short: "Remove a deployment, its builds and its app",
	Example: `  ziroctl deploy rm web
  ziroctl deploy rm web --purge`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		q := ""
		if deployPurge {
			q = "?purge=true"
		}
		if err := deployCall("DELETE", "/v1/deployments/"+args[0]+q, nil, nil); err != nil {
			return err
		}
		fmt.Printf("Removed %s\n", args[0])
		return nil
	},
}

var deployServeCmd = &cobra.Command{
	Use:    "serve",
	Short:  "Run the deploy daemon (ziroctld)",
	Hidden: true,
	Args:   cobra.NoArgs,
	RunE:   func(cmd *cobra.Command, args []string) error { return serveDeployDaemon() },
}

func shortCommit(c string) string {
	if len(c) > 7 {
		return c[:7]
	}
	return orDash(c)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func init() {
	f := deployCmd.Flags()
	f.StringVar(&deployName, "name", "", "App name (default: the repository name)")
	f.StringVar(&deployRef, "branch", "", "Branch or tag (default: the repository's default branch)")
	f.StringVar(&deployPath, "path", "", "Subdirectory to build (monorepos)")
	f.IntVar(&deployPort, "port", 0, "Port the app listens on (default: detected; PORT is set to it)")
	f.IntVar(&deployPublish, "publish", 0, "Host port on 127.0.0.1 (default: a free one from 20000)")
	f.StringArrayVar(&deployEnv, "env", nil, "Environment variable KEY=value (repeatable)")
	f.StringArrayVar(&deploySecrets, "secret", nil, "Secret env var: KEY=@file, KEY (from $KEY) or KEY=value (repeatable)")
	f.StringVar(&deployExpose, "expose", "", "Publish it through the gateway on this hostname (HTTPS)")
	f.StringVar(&deployExposeTLS, "expose-tls", "", "TLS for --expose: auto (ACME), internal, off or cert:<name>")
	f.StringVar(&deployTokenFile, "git-token-file", "", "File with an access token for a private repository")
	f.StringVar(&deployMemory, "memory", "", "Memory limit, e.g. 512Mi")
	f.Float64Var(&deployCPUs, "cpus", 0, "CPU limit, e.g. 1.5")
	for _, c := range []*cobra.Command{deployCmd, deployRedeployCmd, deployRollbackCmd} {
		c.Flags().BoolVar(&deployNoFollow, "no-follow", false, "Return once the build is queued")
	}
	deployRedeployCmd.Flags().StringVar(&deployRef, "branch", "", "Build this branch or tag from now on")
	deployLogsCmd.Flags().StringVar(&deployBuildID, "build", "", "Build to show (default: the latest)")
	deployLogsCmd.Flags().BoolVarP(&deployLogsFollow, "follow", "f", false, "Keep streaming until the build finishes")
	deployRmCmd.Flags().BoolVar(&deployPurge, "purge", false, "Also delete the app's data and secrets")
	deployCmd.AddCommand(deployLsCmd, deployStatusCmd, deployLogsCmd, deployRedeployCmd, deployRollbackCmd, deployRmCmd, deployServeCmd)
	rootCmd.AddCommand(deployCmd)
}
