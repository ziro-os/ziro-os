package cmd

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/ziro-os/ziro-os/sdk/doccmd"
)

// checkDocCommand: args name a runnable command, and every flag in them exists on it.
func checkDocCommand(root *cobra.Command, args []string) error {
	cmd, rest, err := root.Find(args)
	if err != nil {
		return err
	}
	if !cmd.Runnable() {
		return fmt.Errorf("%q is not a command (unknown subcommand?)", cmd.CommandPath())
	}
	for _, a := range rest {
		if !strings.HasPrefix(a, "-") || a == "-" || a == "--" {
			continue
		}
		name, _, _ := strings.Cut(strings.TrimLeft(a, "-"), "=")
		var f *pflag.Flag
		if strings.HasPrefix(a, "--") {
			if f = cmd.Flags().Lookup(name); f == nil {
				f = cmd.InheritedFlags().Lookup(name)
			}
		} else if f = cmd.Flags().ShorthandLookup(name[:1]); f == nil {
			f = cmd.InheritedFlags().ShorthandLookup(name[:1])
		}
		if f == nil {
			return fmt.Errorf("%s has no flag %s", cmd.CommandPath(), a)
		}
	}
	return nil
}

// Every ziroctl command in these guides is a real command with real flags.
func TestDocCommands(t *testing.T) {
	for _, bad := range [][]string{{"router", "moon", "ad", "sg-1"}, {"router", "key", "create", "x", "--nope"}} {
		if checkDocCommand(rootCmd, bad) == nil {
			t.Fatalf("the check accepts ziroctl %s", strings.Join(bad, " "))
		}
	}
	for _, doc := range []string{"../../../docs/router-deploy.md", "../../../docs/router.md", "../../../docs/cloudflare-tunnel.md"} {
		md, err := os.ReadFile(doc)
		if err != nil {
			t.Fatal(err)
		}
		lines := doccmd.Lines(md, "ziroctl")
		if len(lines) == 0 {
			t.Fatalf("%s: no ziroctl commands found", doc)
		}
		t.Logf("%s: %d ziroctl commands", doc, len(lines))
		for _, args := range lines {
			if err := checkDocCommand(rootCmd, args); err != nil {
				t.Errorf("%s: ziroctl %s: %v", doc, strings.Join(args, " "), err)
			}
		}
	}
}
