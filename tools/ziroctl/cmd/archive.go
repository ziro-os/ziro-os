package cmd

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
)

// extractTarGz unpacks a .tar.gz of source files into dst (which must exist) and is the only
// reader of archives that clients upload. It accepts directories and regular files only: no
// symlinks, hard links or devices, no absolute or ".." names, and every write goes through an
// os.Root so a name can't leave dst. The caps bound a decompression bomb: total bytes written
// and the number of entries.
func extractTarGz(dst string, r io.Reader, maxBytes int64, maxFiles int) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("not a gzip archive: %w", err)
	}
	defer gz.Close()
	root, err := os.OpenRoot(dst)
	if err != nil {
		return err
	}
	defer root.Close()
	tr := tar.NewReader(gz)
	var total int64
	for n := 0; ; n++ {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("bad archive: %w", err)
		}
		if n >= maxFiles {
			return fmt.Errorf("archive has more than %d entries", maxFiles)
		}
		name := path.Clean(strings.TrimPrefix(h.Name, "./"))
		if name == "." {
			continue
		}
		if !fs.ValidPath(name) || strings.ContainsRune(name, '\\') || strings.ContainsRune(name, 0) {
			return fmt.Errorf("member %q: bad name", h.Name)
		}
		switch h.Typeflag {
		case tar.TypeDir:
			if err := root.MkdirAll(name, 0755); err != nil {
				return err
			}
		case tar.TypeReg:
			if total += h.Size; h.Size < 0 || total > maxBytes {
				return fmt.Errorf("archive expands beyond %d MiB", maxBytes>>20)
			}
			if dir := path.Dir(name); dir != "." {
				if err := root.MkdirAll(dir, 0755); err != nil {
					return err
				}
			}
			mode := os.FileMode(0644)
			if h.Mode&0100 != 0 {
				mode = 0755
			}
			f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
			if err != nil {
				return fmt.Errorf("member %q: %w", h.Name, err)
			}
			_, err = io.Copy(f, io.LimitReader(tr, h.Size))
			if cerr := f.Close(); err == nil {
				err = cerr
			}
			if err != nil {
				return err
			}
		default:
			return fmt.Errorf("member %q: type %q isn't allowed (files and directories only)", h.Name, string(h.Typeflag))
		}
	}
}
