package cmd

import (
	"fmt"
	"os"
	"path/filepath"
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
	if cmd.DisableFlagParsing { // passes its flags through (compose)
		return nil
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

// Every ziroctl command in the docs is a real command with real flags.
func TestDocCommands(t *testing.T) {
	for _, bad := range [][]string{{"router", "moon", "ad", "sg-1"}, {"router", "key", "create", "x", "--nope"}} {
		if checkDocCommand(rootCmd, bad) == nil {
			t.Fatalf("the check accepts ziroctl %s", strings.Join(bad, " "))
		}
	}
	docs, _ := filepath.Glob("../../../docs/*.md")
	tutorials, _ := filepath.Glob("../../../docs/tutorials/*.md")
	total := 0
	for _, doc := range append(docs, tutorials...) {
		md, err := os.ReadFile(doc)
		if err != nil {
			t.Fatal(err)
		}
		lines := doccmd.Lines(md, "ziroctl")
		total += len(lines)
		for _, args := range lines {
			if err := checkDocCommand(rootCmd, args); err != nil {
				t.Errorf("%s: ziroctl %s: %v", doc, strings.Join(args, " "), err)
			}
		}
	}
	if total < 200 {
		t.Fatalf("only %d ziroctl commands found in %d docs: is the docs path right?", total, len(docs))
	}
	t.Logf("%d ziroctl commands in %d docs", total, len(docs)+len(tutorials))
}
