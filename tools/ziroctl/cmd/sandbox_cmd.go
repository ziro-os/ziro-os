package cmd

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	sdkapi "github.com/ziro-os/ziro-os/sdk/api"
	"github.com/ziro-os/ziro-os/sdk/schema"
)

var sandboxCmd = &cobra.Command{
	Use:     "sandbox",
	Aliases: []string{"sandboxes", "sbx"},
	Short:   "Isolated gVisor sandboxes for untrusted code and AI agents",
	Long: `Sandboxes run untrusted code (AI agents, code interpreters, CI steps) under gVisor, with every
privilege the host doesn't grant removed, no network, resource limits and a lifetime. Enable the
module first: ziroctl module enable sandbox. Guide: docs/sandbox.md.`,
	Example: `  ziroctl sandbox create python:3.13-slim --timeout 30m
  ziroctl sandbox exec <id> -- python3 -c 'print(6*7)'
  ziroctl sandbox ls
  ziroctl sandbox rm <id>`,
}

var (
	sbxSpec    schema.SandboxSpec
	sbxEnv     []string
	sbxMeta    []string
	sbxMemory  string
	sbxCPUs    float64
	sbxPIDs    int
	sbxRenew   string
	sbxExec    sdkapi.SandboxExecRequest
	sbxExecEnv []string
	sbxNet     schema.SandboxNetwork
)

// netFlags reads --net/--allow: nil when neither is set (no network).
func netFlags() *schema.SandboxNetwork {
	n := sbxNet
	if n.Mode == "" && len(n.Allow) > 0 {
		n.Mode = schema.SandboxNetAllowlist
	}
	if n.Mode == "" {
		return nil
	}
	return &n
}

func kvFlags(list []string, what string) (map[string]string, error) {
	if len(list) == 0 {
		return nil, nil
	}
	m := map[string]string{}
	for _, kv := range list {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return nil, fmt.Errorf("%s %q: want KEY=VALUE", what, kv)
		}
		m[k] = v
	}
	return m, nil
}

var sandboxCreateCmd = &cobra.Command{
	Use:   "create <image> [-- command...]",
	Short: "Create a sandbox and wait until it runs",
	Example: `  ziroctl sandbox create python:3.13-slim
  ziroctl sandbox create node:22 --memory 2Gi --cpus 2 --timeout 2h --idle-timeout 15m --meta agent=claude
  ziroctl sandbox create python:3.13-slim --allow pypi.org --allow files.pythonhosted.org`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		spec := sbxSpec
		spec.Image, spec.Command = args[0], args[1:]
		var err error
		if spec.Env, err = kvFlags(sbxEnv, "env"); err != nil {
			return err
		}
		if spec.Metadata, err = kvFlags(sbxMeta, "meta"); err != nil {
			return err
		}
		spec.Network = netFlags()
		if sbxMemory != "" || sbxCPUs != 0 || sbxPIDs != 0 {
			spec.Resources = &schema.Resources{Memory: sbxMemory, CPUs: sbxCPUs, PIDs: sbxPIDs}
		}
		if err := spec.Validate(); err != nil {
			return err
		}
		var sb sdkapi.Sandbox
		if err := sandboxCall("POST", "/v1/sandboxes", spec, &sb); err != nil {
			return err
		}
		return printResult(sb, func() {
			fmt.Println(sb.ID)
			fmt.Fprintf(os.Stderr, "✓ sandbox %s running (%s, %s), expires %s\n", sb.ID, sb.Spec.Image, sb.Spec.Runtime, sb.Expires.Local().Format(time.RFC3339))
		})
	},
}

var sandboxLsCmd = &cobra.Command{
	Use: "ls", Aliases: []string{"list"}, Short: "List sandboxes", Example: "  ziroctl sandbox ls",
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		var list []sdkapi.Sandbox
		if err := sandboxCall("GET", "/v1/sandboxes", nil, &list); err != nil {
			return err
		}
		return printResult(list, func() {
			fmt.Printf("%-13s %-8s %-7s %-28s %-10s %-12s %s\n", "ID", "STATE", "RUNTIME", "IMAGE", "NETWORK", "OWNER", "EXPIRES")
			for _, sb := range list {
				net := "none"
				if sb.Spec.Network != nil && sb.Spec.Network.Mode != "" {
					net = sb.Spec.Network.Mode
				}
				fmt.Printf("%-13s %-8s %-7s %-28s %-10s %-12s %s\n", sb.ID, sb.State, sb.Spec.Runtime, sb.Spec.Image, net, sb.Owner,
					time.Until(sb.Expires).Round(time.Second))
			}
		})
	},
}

var sandboxGetCmd = &cobra.Command{
	Use: "get <id>", Short: "Show a sandbox", Example: "  ziroctl sandbox get <id> --json", Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		var sb sdkapi.Sandbox
		if err := sandboxCall("GET", "/v1/sandboxes/"+args[0], nil, &sb); err != nil {
			return err
		}
		return printResult(sb, func() {
			b, _ := json.MarshalIndent(sb, "", "  ")
			fmt.Println(string(b))
		})
	},
}

// sandboxAction is a command that POSTs to /v1/sandboxes/<id>/<verb> for each id.
func sandboxAction(use, verb, short string) *cobra.Command {
	return &cobra.Command{
		Use: use + " <id>...", Short: short, Example: "  ziroctl sandbox " + use + " <id>", Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			for _, id := range args {
				var body any
				if verb == "renew" && sbxRenew != "" {
					body = map[string]string{"timeout": sbxRenew}
				}
				method, path := "POST", "/v1/sandboxes/"+id+"/"+verb
				if verb == "" {
					method, path = "DELETE", "/v1/sandboxes/"+id
				}
				if err := sandboxCall(method, path, body, nil); err != nil {
					return err
				}
				if !jsonOutput {
					fmt.Printf("✓ %s %s\n", map[string]string{"": "deleted", "pause": "paused", "resume": "resumed", "renew": "renewed"}[verb], id)
				}
			}
			return nil
		},
	}
}

var sandboxRenewCmd = sandboxAction("renew", "renew", "Extend a sandbox's lifetime from now")

var sandboxNetworkCmd = &cobra.Command{
	Use:   "network <id>",
	Short: "Change a sandbox's egress policy now",
	Example: `  ziroctl sandbox network <id> --allow pypi.org --allow '*.github.com'
  ziroctl sandbox network <id> --net open
  ziroctl sandbox network <id> --net none`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		n := netFlags()
		if n == nil {
			return errors.New("set --net or --allow")
		}
		if err := n.Validate(); err != nil {
			return err
		}
		var sb sdkapi.Sandbox
		if err := sandboxCall("PUT", "/v1/sandboxes/"+args[0]+"/network", n, &sb); err != nil {
			return err
		}
		return printResult(sb, func() { fmt.Printf("✓ %s: network %s %s\n", sb.ID, n.Mode, strings.Join(n.Allow, " ")) })
	},
}

var sandboxExecCmd = &cobra.Command{
	Use:   "exec <id> -- <command>...",
	Short: "Run a command in a sandbox and stream its output",
	Example: `  ziroctl sandbox exec <id> -- uname -a
  echo 'print(42)' | ziroctl sandbox exec <id> -i -- python3`,
	Args: cobra.MinimumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		req := sbxExec
		req.Command = args[1:]
		var err error
		if req.Env, err = kvFlags(sbxExecEnv, "env"); err != nil {
			return err
		}
		if stdin, _ := cmd.Flags().GetBool("stdin"); stdin {
			b, err := io.ReadAll(io.LimitReader(os.Stdin, sandboxExecMaxStdin+1))
			if err != nil {
				return err
			}
			req.Stdin = string(b)
		}
		resp, err := sandboxRaw(context.Background(), "POST", "/v1/sandboxes/"+args[0]+"/exec", req)
		if err != nil {
			return err
		}
		if resp.StatusCode >= 300 {
			return daemonDecode("ziro-sandboxd", resp, nil)
		}
		defer resp.Body.Close()
		return printExecStream(resp.Body, os.Stdout, os.Stderr)
	},
}

// exitCodeError makes ziroctl exit with a command's own exit code (after the audit record).
type exitCodeError int

func (e exitCodeError) Error() string { return fmt.Sprintf("exit status %d", int(e)) }

// printExecStream copies an exec's NDJSON events to stdout/stderr (or, with --json, prints
// them as they are) and returns the command's exit status.
func printExecStream(r io.Reader, stdout, stderr io.Writer) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 8<<20)
	for sc.Scan() {
		if jsonOutput {
			fmt.Fprintln(stdout, sc.Text())
		}
		var ev sdkapi.SandboxExecEvent
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			return fmt.Errorf("bad exec stream: %w", err)
		}
		switch {
		case ev.Error != "":
			return errors.New(ev.Error)
		case ev.ExitCode != nil:
			if *ev.ExitCode != 0 {
				return exitCodeError(*ev.ExitCode)
			}
			return nil
		case jsonOutput:
		case ev.Stream == "stderr":
			_, _ = io.WriteString(stderr, ev.Data)
		default:
			_, _ = io.WriteString(stdout, ev.Data)
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	return errors.New("the exec stream ended without an exit code")
}

var sandboxServeCmd = &cobra.Command{
	Use: "serve", Short: "Run the sandbox daemon (ziro-sandboxd)", Hidden: true, Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error { return serveSandboxDaemon() },
}

func init() {
	f := sandboxCreateCmd.Flags()
	f.StringVar(&sbxSpec.Runtime, "runtime", "", "gvisor (default) or runc (operators, when the host allows it)")
	f.StringArrayVarP(&sbxEnv, "env", "e", nil, "Environment variable KEY=VALUE (repeatable)")
	f.StringVarP(&sbxSpec.User, "user", "u", "", "Run as uid[:gid] (default: the image's user)")
	f.StringVarP(&sbxSpec.Workdir, "workdir", "w", "", "Working directory (default /workspace)")
	f.StringVar(&sbxMemory, "memory", "", "Memory limit, e.g. 2Gi (default from the host config)")
	f.Float64Var(&sbxCPUs, "cpus", 0, "CPU limit, e.g. 0.5 or 2")
	f.IntVar(&sbxPIDs, "pids", 0, "Process limit")
	f.StringVar(&sbxSpec.Timeout, "timeout", "", "Lifetime, e.g. 30m (default 1h)")
	f.StringVar(&sbxSpec.IdleTimeout, "idle-timeout", "", "Delete after this long without an exec")
	f.StringArrayVar(&sbxMeta, "meta", nil, "Metadata key=value (repeatable)")
	for _, fs := range []*cobra.Command{sandboxCreateCmd, sandboxNetworkCmd} {
		fs.Flags().StringVar(&sbxNet.Mode, "net", "", "Network: none (default), allowlist or open (public internet only)")
		fs.Flags().StringArrayVar(&sbxNet.Allow, "allow", nil, "Allowed domain (subdomains included), IPv4 address or CIDR; implies --net allowlist")
	}
	sandboxRenewCmd.Flags().StringVar(&sbxRenew, "timeout", "", "New lifetime from now (default: the sandbox's own timeout)")
	e := sandboxExecCmd.Flags()
	e.StringArrayVarP(&sbxExecEnv, "env", "e", nil, "Environment variable KEY=VALUE (repeatable)")
	e.StringVarP(&sbxExec.Workdir, "workdir", "w", "", "Working directory")
	e.StringVarP(&sbxExec.User, "user", "u", "", "Run as uid[:gid]")
	e.StringVar(&sbxExec.Timeout, "timeout", "", "Stop the command after this long (default 5m, max 1h)")
	e.BoolP("stdin", "i", false, "Send this command's stdin (up to 1 MiB)")
	sandboxCmd.AddCommand(sandboxCreateCmd, sandboxLsCmd, sandboxGetCmd, sandboxExecCmd, sandboxRenewCmd, sandboxNetworkCmd,
		sandboxAction("rm", "", "Delete sandboxes and their workspaces"),
		sandboxAction("pause", "pause", "Freeze a sandbox's processes"),
		sandboxAction("resume", "resume", "Thaw a paused sandbox"),
		sandboxServeCmd)
	rootCmd.AddCommand(sandboxCmd)
}
