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
	return untarGz(dst, r, untarOpts{maxBytes: maxBytes, maxFiles: maxFiles})
}

// untarOpts: the caps, and what a trusted archive (a sandbox workspace snapshot) may also carry.
type untarOpts struct {
	maxBytes int64
	maxFiles int
	links    bool // symlinks, created verbatim (os.Root never follows one out of dst)
	owners   bool // the members' uid, gid and permission bits
}

func untarGz(dst string, r io.Reader, o untarOpts) error {
	maxBytes, maxFiles := o.maxBytes, o.maxFiles
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
		case tar.TypeSymlink:
			if !o.links || h.Linkname == "" || strings.ContainsRune(h.Linkname, 0) {
				return fmt.Errorf("member %q: type %q isn't allowed (files and directories only)", h.Name, string(h.Typeflag))
			}
			if dir := path.Dir(name); dir != "." {
				if err := root.MkdirAll(dir, 0755); err != nil {
					return err
				}
			}
			if err := root.Symlink(h.Linkname, name); err != nil {
				return fmt.Errorf("member %q: %w", h.Name, err)
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
		if o.owners {
			if h.Typeflag != tar.TypeSymlink {
				if err := root.Chmod(name, os.FileMode(h.Mode)&os.ModePerm); err != nil {
					return err
				}
			}
			if err := root.Lchown(name, h.Uid, h.Gid); err != nil {
				return err
			}
		}
	}
}

// tarGzDir writes the tree under root as a .tar.gz that untarGz with links and owners restores:
// directories, regular files (a hard link becomes a copy) and symlinks, which are stored, never
// followed. Sockets, devices and FIFOs are skipped. It fails past the caps.
func tarGzDir(root *os.Root, w io.Writer, maxBytes int64, maxFiles int) error {
	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)
	var total int64
	n := 0
	err := fs.WalkDir(root.FS(), ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil || name == "." {
			return err
		}
		if n++; n > maxFiles {
			return fmt.Errorf("more than %d entries", maxFiles)
		}
		fi, err := root.Lstat(name)
		if err != nil {
			return err
		}
		link := ""
		switch {
		case fi.Mode()&fs.ModeSymlink != 0:
			if link, err = root.Readlink(name); err != nil {
				return err
			}
		case !fi.IsDir() && !fi.Mode().IsRegular():
			return nil
		}
		h, err := tar.FileInfoHeader(fi, link)
		if err != nil {
			return err
		}
		h.Name, h.Uname, h.Gname = name, "", ""
		if fi.IsDir() {
			h.Name += "/"
		}
		if err := tw.WriteHeader(h); err != nil {
			return err
		}
		if !fi.Mode().IsRegular() {
			return nil
		}
		if total += h.Size; total > maxBytes {
			return fmt.Errorf("over %d MiB", maxBytes>>20)
		}
		f, err := root.Open(name)
		if err != nil {
			return err
		}
		defer f.Close()
		// A file that changed size since Lstat fails the archive (the sandbox is paused meanwhile).
		_, err = io.CopyN(tw, f, h.Size)
		return err
	})
	if err != nil {
		return err
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}
