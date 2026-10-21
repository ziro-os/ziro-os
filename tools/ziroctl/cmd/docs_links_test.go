package cmd

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// TestDocLinks keeps every relative link in the Markdown documents alive: the target file
// exists and, for a link to a heading, the heading exists.
func TestDocLinks(t *testing.T) {
	root := "../../.."
	var files []string
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == ".claude" || d.Name() == "node_modules") {
			return filepath.SkipDir
		}
		if !d.IsDir() && strings.HasSuffix(p, ".md") {
			files = append(files, p)
		}
		return nil
	})
	if len(files) < 20 {
		t.Fatalf("found only %d Markdown files under %s", len(files), root)
	}
	heading := regexp.MustCompile(`^#{1,6}\s+(.*?)\s*#*\s*$`)
	strip := regexp.MustCompile("<[^>]+>|`")
	nonWord := regexp.MustCompile(`[^\p{L}\p{N}_\- ]`)
	anchors := map[string]map[string]bool{}
	anchorsOf := func(path string) map[string]bool {
		if a, ok := anchors[path]; ok {
			return a
		}
		a, seen, fence := map[string]bool{}, map[string]int{}, false
		b, _ := os.ReadFile(path)
		for _, ln := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(strings.TrimSpace(ln), "```") {
				fence = !fence
			}
			if fence {
				continue
			}
			if m := heading.FindStringSubmatch(ln); m != nil {
				s := strings.ReplaceAll(nonWord.ReplaceAllString(strip.ReplaceAllString(strings.ToLower(strings.TrimSpace(m[1])), ""), ""), " ", "-")
				n := seen[s]
				seen[s]++
				if n > 0 {
					s += "-" + strconv.Itoa(n)
				}
				a[s] = true
			}
		}
		anchors[path] = a
		return a
	}
	link := regexp.MustCompile(`\[[^\]]*\]\(([^)\s]+)(?:\s+"[^"]*")?\)`)
	for _, f := range files {
		b, _ := os.ReadFile(f)
		fence := false
		for i, ln := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(strings.TrimSpace(ln), "```") {
				fence = !fence
			}
			if fence {
				continue
			}
			for _, m := range link.FindAllStringSubmatch(ln, -1) {
				target := m[1]
				if strings.HasPrefix(target, "http:") || strings.HasPrefix(target, "https:") || strings.HasPrefix(target, "mailto:") || target == "#" {
					continue
				}
				path, frag, _ := strings.Cut(target, "#")
				dest := f
				if path != "" {
					dest = filepath.Join(filepath.Dir(f), path)
				}
				if _, err := os.Stat(dest); err != nil {
					t.Errorf("%s:%d: broken link %s", f, i+1, target)
					continue
				}
				if frag != "" && strings.HasSuffix(dest, ".md") && !anchorsOf(dest)[frag] {
					t.Errorf("%s:%d: no heading #%s in %s", f, i+1, frag, dest)
				}
			}
		}
	}
}
