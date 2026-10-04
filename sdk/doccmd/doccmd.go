// Package doccmd finds the command lines of a tool in Markdown code blocks, so a tool's tests can
// check that every documented command and flag exists.
package doccmd

import (
	"bufio"
	"bytes"
	"strings"
)

// Lines returns the arguments (after bin) of every `bin ...` command in md's fenced code blocks.
// It handles line continuations, `sudo`, leading VAR=value assignments, comments, and commands
// chained with |, && or ;. Placeholders such as <name> are kept as arguments.
func Lines(md []byte, bin string) [][]string {
	var out [][]string
	in, cur := false, ""
	sc := bufio.NewScanner(bytes.NewReader(md))
	for sc.Scan() {
		l := sc.Text()
		if strings.HasPrefix(strings.TrimSpace(l), "```") {
			in, cur = !in, ""
			continue
		}
		if !in {
			continue
		}
		if s, ok := strings.CutSuffix(strings.TrimRight(l, " "), "\\"); ok {
			cur += s + " "
			continue
		}
		cur += l
		for _, seg := range split(cur) {
			if args := command(seg, bin); args != nil {
				out = append(out, args)
			}
		}
		cur = ""
	}
	return out
}

func split(l string) []string {
	if i := strings.Index(l, " #"); i >= 0 {
		l = l[:i]
	}
	if strings.HasPrefix(strings.TrimSpace(l), "#") {
		return nil
	}
	for _, sep := range []string{"&&", "|", ";"} {
		l = strings.ReplaceAll(l, sep, "\n")
	}
	return strings.Split(l, "\n")
}

func command(seg, bin string) []string {
	f := fields(seg)
	for len(f) > 0 && (f[0] == "sudo" || f[0] == "$" || strings.Contains(f[0], "=") && !strings.HasPrefix(f[0], "-")) {
		f = f[1:]
	}
	if len(f) == 0 || f[0] != bin {
		return nil
	}
	return f[1:]
}

// fields splits on spaces, keeping quoted strings together.
func fields(s string) []string {
	var out []string
	var b strings.Builder
	q := rune(0)
	for _, r := range s {
		switch {
		case q != 0 && r == q:
			q = 0
		case q == 0 && (r == '"' || r == '\''):
			q = r
		case q == 0 && (r == ' ' || r == '\t'):
			if b.Len() > 0 {
				out = append(out, b.String())
				b.Reset()
			}
		default:
			b.WriteRune(r)
		}
	}
	if b.Len() > 0 {
		out = append(out, b.String())
	}
	return out
}
