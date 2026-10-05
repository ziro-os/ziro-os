package main

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

// Every zirocd command in the router guides is a real command with real flags.
func TestDocCommands(t *testing.T) {
	root := newRoot()
	check := func(args []string) error {
		cmd, rest, err := root.Find(args)
		if err != nil {
			return err
		}
		if !cmd.Runnable() {
			return fmt.Errorf("%q is not a command", cmd.CommandPath())
		}
		for _, a := range rest {
			if !strings.HasPrefix(a, "--") || a == "--" {
				continue
			}
			name, _, _ := strings.Cut(strings.TrimPrefix(a, "--"), "=")
			if lookup(cmd, name) == nil {
				return fmt.Errorf("%s has no flag %s", cmd.CommandPath(), a)
			}
		}
		return nil
	}
	if check([]string{"moon", "--nope"}) == nil || check([]string{"mon"}) == nil {
		t.Fatal("the check accepts unknown commands or flags")
	}
	docs, _ := filepath.Glob("../../docs/*.md")
	if len(docs) < 10 {
		t.Fatalf("found %d docs: is the docs path right?", len(docs))
	}
	for _, doc := range docs {
		md, err := os.ReadFile(doc)
		if err != nil {
			t.Fatal(err)
		}
		lines := doccmd.Lines(md, "zirocd")
		for _, args := range lines {
			if err := check(args); err != nil {
				t.Errorf("%s: zirocd %s: %v", doc, strings.Join(args, " "), err)
			}
		}
	}
}

func lookup(cmd *cobra.Command, name string) *pflag.Flag {
	if f := cmd.Flags().Lookup(name); f != nil {
		return f
	}
	return cmd.InheritedFlags().Lookup(name)
}
