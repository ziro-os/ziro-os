package cmd

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	sdkapi "github.com/ziro-os/ziro-os/sdk/api"
	"github.com/ziro-os/ziro-os/sdk/schema"
)

var sandboxTemplateCmd = &cobra.Command{
	Use:   "template",
	Short: "Manage the host's sandbox templates",
	Example: `  ziroctl sandbox template ls
  ziroctl sandbox template add python python.json
  ziroctl sandbox template rm python`,
}

var sandboxTemplateLsCmd = &cobra.Command{
	Use: "ls", Short: "List sandbox templates", Example: "  ziroctl sandbox template ls", Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		ts := listTemplates()
		return printResult(ts, func() {
			names := make([]string, 0, len(ts))
			for n := range ts {
				names = append(names, n)
			}
			sort.Strings(names)
			fmt.Printf("%-16s %-32s %-10s %s\n", "NAME", "IMAGE", "RUNTIME", "NETWORK")
			for _, n := range names {
				t := ts[n]
				net := "none"
				if t.Network != nil && t.Network.Mode != "" {
					net = t.Network.Mode + " " + strings.Join(t.Network.Allow, ",")
				}
				fmt.Printf("%-16s %-32s %-10s %s\n", n, t.Image, orDash(t.Runtime), net)
			}
		})
	},
}

var sandboxTemplateAddCmd = &cobra.Command{
	Use: "add <name> <spec.json>", Short: "Add or replace a template from a sandbox spec file",
	Example: `  ziroctl sandbox template add python python.json   # {"image":"python:3.13-slim","network":{"mode":"allowlist","allow":["pypi.org"]}}`,
	Args:    cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		b, err := os.ReadFile(args[1])
		if err != nil {
			return err
		}
		var t schema.SandboxSpec
		dec := json.NewDecoder(strings.NewReader(string(b)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&t); err != nil {
			return fmt.Errorf("%s: %w", args[1], err)
		}
		if err := saveTemplate(args[0], t); err != nil {
			return err
		}
		fmt.Printf("✓ template %s saved\n", args[0])
		return nil
	},
}

var sandboxTemplateRmCmd = &cobra.Command{
	Use: "rm <name>", Short: "Remove a template", Example: "  ziroctl sandbox template rm python", Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := validName(args[0]); err != nil {
			return err
		}
		if err := os.Remove(templatePath(args[0])); err != nil {
			return errNotFound("no template " + args[0])
		}
		fmt.Printf("✓ template %s removed\n", args[0])
		return nil
	},
}

var sandboxSnapshotCmd = &cobra.Command{
	Use:   "snapshot",
	Short: "Save a sandbox's filesystem as an image for new sandboxes",
	Example: `  ziroctl sandbox snapshot create <id> deps-installed
  ziroctl sandbox snapshot ls
  ziroctl sandbox create ziro.local/sandbox/root/deps-installed:1760000000`,
}

var sandboxSnapshotCreateCmd = &cobra.Command{
	Use: "create <id> <name>", Short: "Snapshot a sandbox's filesystem", Example: "  ziroctl sandbox snapshot create <id> deps-installed",
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		var s sdkapi.SandboxSnapshot
		if err := sandboxCall("POST", "/v1/sandboxes/"+args[0]+"/snapshot", map[string]string{"name": args[1]}, &s); err != nil {
			return err
		}
		return printResult(s, func() { fmt.Println(s.Image) })
	},
}

var sandboxSnapshotLsCmd = &cobra.Command{
	Use: "ls", Short: "List snapshots", Example: "  ziroctl sandbox snapshot ls", Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		var list []sdkapi.SandboxSnapshot
		if err := sandboxCall("GET", "/v1/sandboxes/snapshots", nil, &list); err != nil {
			return err
		}
		return printResult(list, func() {
			for _, s := range list {
				fmt.Printf("%-64s %s\n", s.Image, s.Size)
			}
		})
	},
}

var sandboxSnapshotRmCmd = &cobra.Command{
	Use: "rm <image>", Short: "Delete a snapshot", Example: "  ziroctl sandbox snapshot rm ziro.local/sandbox/root/deps-installed:1760000000",
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := sandboxCall("DELETE", "/v1/sandboxes/snapshots?image="+url.QueryEscape(args[0]), nil, nil); err != nil {
			return err
		}
		fmt.Printf("✓ snapshot %s removed\n", args[0])
		return nil
	},
}

func init() {
	sandboxTemplateCmd.AddCommand(sandboxTemplateLsCmd, sandboxTemplateAddCmd, sandboxTemplateRmCmd)
	sandboxSnapshotCmd.AddCommand(sandboxSnapshotCreateCmd, sandboxSnapshotLsCmd, sandboxSnapshotRmCmd)
	sandboxCmd.AddCommand(sandboxTemplateCmd, sandboxSnapshotCmd)
}
