// Package pack turns a directory or a single file into the .tar.gz that `zirocd deploy` uploads.
package pack

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
)

// skipDirs are never uploaded when git can't say what's ignored. Builds install and compile
// inside the image, so these only slow the upload down (or leak local state).
var skipDirs = map[string]bool{".git": true, "node_modules": true, ".next": true, ".venv": true, "__pycache__": true}

// Pack writes src (a directory, or one file) to w as a .tar.gz of regular files and returns how
// many it holds. In a git work tree it uploads what git would track or could add (so .gitignore
// is honoured); elsewhere it skips skipDirs. Environment files (.env*) and links are never sent.
func Pack(src string, w io.Writer, maxFiles int) (int, error) {
	fi, err := os.Stat(src)
	if err != nil {
		return 0, err
	}
	root, files := filepath.Dir(src), []string{filepath.Base(src)}
	if fi.IsDir() {
		root = src
		if files, err = list(root); err != nil {
			return 0, err
		}
	}
	if len(files) == 0 {
		return 0, errors.New("nothing to upload")
	}
	if len(files) > maxFiles {
		return 0, fmt.Errorf("%d files (the limit is %d): is a build directory in the way?", len(files), maxFiles)
	}
	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)
	n := 0
	for _, name := range files {
		p := filepath.Join(root, name)
		st, err := os.Lstat(p) // a link or special file is skipped
		if err != nil || !st.Mode().IsRegular() {
			continue
		}
		f, err := os.Open(p)
		if err != nil {
			return n, err
		}
		h := &tar.Header{Name: filepath.ToSlash(name), Typeflag: tar.TypeReg, Size: st.Size(), Mode: 0644}
		if st.Mode()&0100 != 0 {
			h.Mode = 0755
		}
		if err = tw.WriteHeader(h); err == nil {
			_, err = io.Copy(tw, f)
		}
		f.Close()
		if err != nil {
			return n, err
		}
		n++
	}
	if err := tw.Close(); err != nil {
		return n, err
	}
	return n, gz.Close()
}

// list returns the files to upload, relative to root.
func list(root string) ([]string, error) {
	var names []string
	if out, err := exec.Command("git", "-C", root, "ls-files", "-z", "--cached", "--others", "--exclude-standard").Output(); err == nil {
		for _, n := range bytes.Split(out, []byte{0}) {
			if len(n) > 0 {
				names = append(names, string(n))
			}
		}
	} else {
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() && skipDirs[d.Name()] && p != root {
				return filepath.SkipDir
			}
			if !d.IsDir() {
				rel, _ := filepath.Rel(root, p)
				names = append(names, rel)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	keep := names[:0]
	for _, n := range names {
		if !strings.HasPrefix(path.Base(filepath.ToSlash(n)), ".env") {
			keep = append(keep, n)
		}
	}
	return keep, nil
}
