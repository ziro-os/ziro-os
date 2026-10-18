package cmd

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	sdkapi "github.com/ziro-os/ziro-os/sdk/api"
)

// The files API reads and writes a sandbox's /workspace from the host side: no agent inside the
// sandbox, and nothing outside /workspace. Every path is opened through os.Root, so ".." and
// symlinks the sandbox planted can't lead out of the workspace directory.

const sandboxFileMax = 100 << 20 // one upload

// workspacePath turns "/workspace/a/b", "a/b" or "/workspace" into a path relative to the
// workspace ("." for the root).
func workspacePath(p string) (string, error) {
	if p == "" || strings.ContainsRune(p, 0) || len(p) > 4096 {
		return "", errors.New("path: required, under 4 KiB")
	}
	if path.IsAbs(p) {
		if p != "/workspace" && !strings.HasPrefix(p, "/workspace/") {
			return "", errors.New("path must be inside /workspace")
		}
		p = strings.TrimPrefix(strings.TrimPrefix(p, "/workspace"), "/")
	}
	if p = path.Clean("/" + p)[1:]; p == "" {
		p = "."
	}
	return p, nil
}

func openWorkspace(id string) (*os.Root, error) {
	return os.OpenRoot(filepath.Join(sandboxDir(id), "workspace"))
}

// serveFiles handles GET (a file's content, or a directory listing), PUT (write a file,
// creating its directories) and DELETE (?recursive=true for a directory) on ?path=.
func (m *sandboxManager) serveFiles(w http.ResponseWriter, r *http.Request, id string, c sandboxCaller) {
	sb, err := m.st.get(id, c)
	if err != nil {
		apiReply(w, err, nil)
		return
	}
	rel, err := workspacePath(r.URL.Query().Get("path"))
	if err != nil {
		apiReply(w, err, nil)
		return
	}
	root, err := openWorkspace(id)
	if err != nil {
		apiReply(w, err, nil)
		return
	}
	defer root.Close()
	switch r.Method {
	case http.MethodGet:
		fi, err := root.Stat(rel)
		if err != nil {
			apiReply(w, fileErr(err), nil)
			return
		}
		if fi.IsDir() {
			list, err := listWorkspace(root, rel)
			apiReply(w, err, list)
			return
		}
		if !fi.Mode().IsRegular() {
			apiReply(w, errors.New("not a regular file"), nil)
			return
		}
		f, err := root.Open(rel)
		if err != nil {
			apiReply(w, fileErr(err), nil)
			return
		}
		defer f.Close()
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.FormatInt(fi.Size(), 10))
		_, _ = io.Copy(w, f)
	case http.MethodPut:
		mode := os.FileMode(0644)
		if s := r.URL.Query().Get("mode"); s != "" {
			v, err := strconv.ParseUint(s, 8, 32)
			if err != nil || v&^0o777 != 0 {
				apiReply(w, errors.New("mode must be octal permissions, e.g. 0755"), nil)
				return
			}
			mode = os.FileMode(v)
		}
		if rel == "." {
			apiReply(w, errors.New("path names the workspace itself"), nil)
			return
		}
		uid, gid := -1, -1
		if sb.Spec.User != "" {
			uid, gid = sandboxUIDGID(sb.Spec.User)
		}
		err := writeWorkspaceFile(root, rel, http.MaxBytesReader(w, r.Body, sandboxFileMax), mode, uid, gid)
		apiReply(w, err, APIMessage{Status: "ok", Message: "wrote /workspace/" + rel})
	case http.MethodDelete:
		if rel == "." {
			apiReply(w, errors.New("path names the workspace itself"), nil)
			return
		}
		if r.URL.Query().Get("recursive") == "true" {
			err = root.RemoveAll(rel)
		} else {
			err = root.Remove(rel)
		}
		apiReply(w, fileErr(err), APIMessage{Status: "ok", Message: "removed /workspace/" + rel})
	}
}

func fileErr(err error) error {
	if errors.Is(err, fs.ErrNotExist) {
		return errNotFound("no such file in /workspace")
	}
	return err
}

func listWorkspace(root *os.Root, rel string) ([]sdkapi.SandboxFile, error) {
	d, err := root.Open(rel)
	if err != nil {
		return nil, fileErr(err)
	}
	defer d.Close()
	ents, err := d.ReadDir(10000)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	out := []sdkapi.SandboxFile{}
	for _, e := range ents {
		fi, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, sdkapi.SandboxFile{Name: e.Name(), Size: fi.Size(), Mode: fmt.Sprintf("%04o", fi.Mode().Perm()),
			Dir: fi.IsDir(), Modified: fi.ModTime().UTC()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// writeWorkspaceFile writes body to rel through a temporary file renamed into place, owned by
// the sandbox's user (uid -1: unchanged).
func writeWorkspaceFile(root *os.Root, rel string, body io.Reader, mode os.FileMode, uid, gid int) error {
	dir := path.Dir(rel)
	if dir != "." {
		if err := root.MkdirAll(dir, 0755); err != nil {
			return fileErr(err)
		}
		if uid >= 0 {
			for d := dir; d != "."; d = path.Dir(d) {
				_ = root.Lchown(d, uid, gid)
			}
		}
	}
	tmp := path.Join(dir, ".ziro-upload-"+randomHex(6))
	f, err := root.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return fileErr(err)
	}
	_, err = io.Copy(f, body)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = root.Chmod(tmp, mode) // past the umask
	}
	if err == nil && uid >= 0 {
		err = root.Lchown(tmp, uid, gid)
	}
	if err == nil {
		err = root.Rename(tmp, rel)
	}
	if err != nil {
		_ = root.Remove(tmp)
	}
	return err
}
