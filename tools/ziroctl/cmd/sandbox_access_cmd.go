package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	sdkapi "github.com/ziro-os/ziro-os/sdk/api"
)

var (
	sbxAccess    sdkapi.SandboxAccessRequest
	sbxAccessKey string
	sbxFileMode  string
)

var sandboxAccessCmd = &cobra.Command{
	Use:   "access",
	Short: "SSH session tokens for a sandbox",
	Example: `  ziroctl sandbox access create <id> --ttl 30m
  ziroctl sandbox access create <id> --public-key ~/.ssh/id_ed25519.pub --single-use
  ziroctl sandbox access ls <id>
  ziroctl sandbox access rm <id> <token-id>`,
}

var sandboxAccessCreateCmd = &cobra.Command{
	Use:   "create <id>",
	Short: "Create an SSH session token and print the ssh command",
	Example: `  ziroctl sandbox access create <id> --ttl 30m
  ziroctl sandbox access create <id> --public-key ~/.ssh/id_ed25519.pub`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		req := sbxAccess
		if sbxAccessKey != "" {
			b, err := os.ReadFile(sbxAccessKey)
			if err != nil {
				return err
			}
			req.PublicKey = strings.TrimSpace(string(b))
		}
		var v sdkapi.SandboxAccess
		if err := sandboxCall("POST", "/v1/sandboxes/"+args[0]+"/access", req, &v); err != nil {
			return err
		}
		return printResult(v, func() {
			fmt.Println(v.SSH)
			fmt.Fprintf(os.Stderr, "✓ token %s expires %s%s. It is shown once; the gateway's host key:\n  %s\n",
				v.ID, v.Expires.Local().Format(time.RFC3339), map[bool]string{true: ", single use", false: ""}[v.SingleUse], v.HostKey)
		})
	},
}

var sandboxAccessLsCmd = &cobra.Command{
	Use: "ls <id>", Short: "List a sandbox's SSH session tokens", Example: "  ziroctl sandbox access ls <id>", Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		var list []sdkapi.SandboxAccess
		if err := sandboxCall("GET", "/v1/sandboxes/"+args[0]+"/access", nil, &list); err != nil {
			return err
		}
		return printResult(list, func() {
			fmt.Printf("%-9s %-21s %-21s %-6s %s\n", "ID", "CREATED", "EXPIRES", "USED", "KEY")
			for _, a := range list {
				fmt.Printf("%-9s %-21s %-21s %-6v %s\n", a.ID, a.Created.Local().Format(time.DateTime), a.Expires.Local().Format(time.DateTime),
					a.Used, orDash(a.KeyFingerprint))
			}
		})
	},
}

var sandboxAccessRmCmd = &cobra.Command{
	Use: "rm <id> <token-id>", Short: "Revoke an SSH session token", Example: "  ziroctl sandbox access rm <id> 1a2b3c4d", Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := sandboxCall("DELETE", "/v1/sandboxes/"+args[0]+"/access/"+args[1], nil, nil); err != nil {
			return err
		}
		fmt.Printf("✓ token %s revoked\n", args[1])
		return nil
	},
}

// sandboxSSHCmd opens a shell in a sandbox through the gateway with a single-use token, checking
// the gateway's host key against the one the daemon reports.
var sandboxSSHCmd = &cobra.Command{
	Use:   "ssh <id> [-- command...]",
	Short: "Open a shell in a sandbox over the SSH gateway",
	Example: `  ziroctl sandbox ssh <id>
  ziroctl sandbox ssh <id> -- uname -a`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		sshBin, err := exec.LookPath("ssh")
		if err != nil {
			return errors.New("no ssh client on this host; use `ziroctl sandbox access create` from another machine")
		}
		var v sdkapi.SandboxAccess
		if err := sandboxCall("POST", "/v1/sandboxes/"+args[0]+"/access", sdkapi.SandboxAccessRequest{TTL: "5m", SingleUse: true}, &v); err != nil {
			return err
		}
		cfg, err := loadSandboxConfig()
		if err != nil {
			return err
		}
		f, err := os.CreateTemp("", "ziro-sbx-known-hosts-")
		if err != nil {
			return err
		}
		defer os.Remove(f.Name())
		// The token was made for the configured host name: pin its key for 127.0.0.1 too.
		key := v.HostKey[strings.Index(v.HostKey, " ")+1:]
		fmt.Fprintf(f, "[127.0.0.1]:%d %s\n", cfg.SSHPort, key)
		f.Close()
		argv := []string{"ssh", "-p", fmt.Sprint(cfg.SSHPort), "-o", "UserKnownHostsFile=" + f.Name(), "-o", "StrictHostKeyChecking=yes",
			"-o", "PubkeyAuthentication=no", "-o", "PasswordAuthentication=no", "-o", "LogLevel=ERROR"}
		if len(args) == 1 {
			argv = append(argv, "-t")
		}
		argv = append(argv, v.Username+"@127.0.0.1")
		argv = append(argv, args[1:]...)
		c := exec.Command(sshBin, argv[1:]...)
		c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
		if err := c.Run(); err != nil {
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				return exitCodeError(ee.ExitCode())
			}
			return err
		}
		return nil
	},
}

// sandboxCpCmd copies a file into or out of a sandbox's /workspace (<id>:<path> names the
// sandbox side; - is stdin or stdout).
var sandboxCpCmd = &cobra.Command{
	Use:   "cp <src> <dst>",
	Short: "Copy a file into or out of a sandbox's /workspace",
	Example: `  ziroctl sandbox cp ./main.py <id>:/workspace/main.py
  ziroctl sandbox cp <id>:/workspace/out.csv ./out.csv
  ziroctl sandbox cp <id>:report.txt -`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		srcID, srcPath, srcRemote := splitSandboxPath(args[0])
		dstID, dstPath, dstRemote := splitSandboxPath(args[1])
		switch {
		case srcRemote == dstRemote:
			return errors.New("exactly one side must be <sandbox-id>:<path>")
		case dstRemote:
			var in io.Reader = os.Stdin
			if srcPath != "-" {
				f, err := os.Open(srcPath)
				if err != nil {
					return err
				}
				defer f.Close()
				in = f
				if strings.HasSuffix(dstPath, "/") {
					dstPath += filepath.Base(srcPath)
				}
			}
			q := url.Values{"path": {dstPath}}
			if sbxFileMode != "" {
				q.Set("mode", sbxFileMode)
			}
			resp, err := sandboxStream(http.MethodPut, "/v1/sandboxes/"+dstID+"/files?"+q.Encode(), in)
			if err != nil {
				return err
			}
			return daemonDecode("ziro-sandboxd", resp, nil)
		default:
			resp, err := sandboxStream(http.MethodGet, "/v1/sandboxes/"+srcID+"/files?"+url.Values{"path": {srcPath}}.Encode(), nil)
			if err != nil {
				return err
			}
			if resp.StatusCode >= 300 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/octet-stream") {
				if resp.StatusCode < 300 {
					resp.Body.Close()
					return errors.New(srcPath + " is a directory (ziroctl sandbox files lists it)")
				}
				return daemonDecode("ziro-sandboxd", resp, nil)
			}
			defer resp.Body.Close()
			var out io.Writer = os.Stdout
			if dstPath != "-" {
				f, err := os.OpenFile(dstPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
				if err != nil {
					return err
				}
				defer f.Close()
				out = f
			}
			_, err = io.Copy(out, resp.Body)
			return err
		}
	},
}

var sandboxFilesCmd = &cobra.Command{
	Use: "files <id> [path]", Short: "List a directory of a sandbox's /workspace",
	Example: "  ziroctl sandbox files <id>\n  ziroctl sandbox files <id> /workspace/src", Args: cobra.RangeArgs(1, 2),
	RunE: func(cmd *cobra.Command, args []string) error {
		p := "/workspace"
		if len(args) == 2 {
			p = args[1]
		}
		var list []sdkapi.SandboxFile
		if err := sandboxCall("GET", "/v1/sandboxes/"+args[0]+"/files?"+url.Values{"path": {p}}.Encode(), nil, &list); err != nil {
			return err
		}
		return printResult(list, func() {
			for _, f := range list {
				name := f.Name
				if f.Dir {
					name += "/"
				}
				fmt.Printf("%s %10d %s %s\n", f.Mode, f.Size, f.Modified.Local().Format(time.DateTime), name)
			}
		})
	},
}

// splitSandboxPath splits "<id>:<path>" (a sandbox id is 12 base32 characters).
func splitSandboxPath(s string) (id, p string, remote bool) {
	if i := strings.Index(s, ":"); i == 12 && sandboxIDRe.MatchString(s[:i]) {
		return s[:i], s[i+1:], true
	}
	return "", s, false
}

// sandboxStream sends a raw body to ziro-sandboxd (files).
func sandboxStream(method, path string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(context.Background(), method, "http://ziro-sandboxd"+path, body)
	if err != nil {
		return nil, err
	}
	resp, err := sandboxCLIHTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ziro-sandboxd isn't answering on %s (ziroctl module enable sandbox): %w", sandboxSocket, err)
	}
	return resp, nil
}

func init() {
	f := sandboxAccessCreateCmd.Flags()
	f.StringVar(&sbxAccess.TTL, "ttl", "", "Lifetime (default 1h, max 24h, never past the sandbox)")
	f.StringVar(&sbxAccessKey, "public-key", "", "Bind the token to this public key file: the client must also hold the key")
	f.BoolVar(&sbxAccess.SingleUse, "single-use", false, "Valid for one connection")
	sandboxCpCmd.Flags().StringVar(&sbxFileMode, "mode", "", "File mode for an upload, e.g. 0755")
	sandboxAccessCmd.AddCommand(sandboxAccessCreateCmd, sandboxAccessLsCmd, sandboxAccessRmCmd)
	sandboxCmd.AddCommand(sandboxAccessCmd, sandboxSSHCmd, sandboxCpCmd, sandboxFilesCmd)
}
