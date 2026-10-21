package cmd

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	sdkapi "github.com/ziro-os/ziro-os/sdk/api"
)

// Snapshot replication: a cluster master copies every snapshot (image + /workspace archive) to
// every sandbox node of the same architecture, so a create from a snapshot can run on any of
// them and a snapshot outlives the node that took it.
//
// Nodes export and import a snapshot as one tar ("image.tar", from nerdctl save; then
// "workspace.tar.gz" when it has one) on their mesh API only (the cluster token); the master
// streams one node's export into another's import, so nothing is held in memory.

const snapshotImageMax = 20 << 30 // one exported image

// exportSnapshot streams a snapshot this node holds.
func (m *sandboxManager) exportSnapshot(w http.ResponseWriter, r *http.Request) {
	ref, err := findSnapshot(r.Context(), r.URL.Query().Get("image"))
	if err != nil {
		apiReply(w, err, nil)
		return
	}
	tmp, err := snapshotTemp()
	if err != nil {
		apiReply(w, err, nil)
		return
	}
	defer os.Remove(tmp)
	if out, err := sandboxNerdctl(r.Context(), "save", "-o", tmp, ref); err != nil {
		apiReply(w, fmt.Errorf("save %s: %s", ref, cmdError(out, err)), nil)
		return
	}
	w.Header().Set("Content-Type", "application/x-tar")
	tw := tar.NewWriter(w)
	for _, part := range []struct{ name, path string }{{"image.tar", tmp}, {"workspace.tar.gz", snapshotArchive(ref)}} {
		if err := tarFile(tw, part.name, part.path); err != nil {
			if os.IsNotExist(err) && part.name == "workspace.tar.gz" {
				continue // a snapshot from before workspaces were kept
			}
			fmt.Printf("[sandboxd] export %s: %v\n", ref, err)
			return // the reader sees a cut tar and the import fails
		}
	}
	_ = tw.Close()
}

// tarFile writes one file into a tar stream.
func tarFile(tw *tar.Writer, name, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: fi.Size(), Typeflag: tar.TypeReg, ModTime: fi.ModTime()}); err != nil {
		return err
	}
	_, err = io.CopyN(tw, f, fi.Size())
	return err
}

// importSnapshot loads a snapshot another node exported. The image is checked before it is
// loaded: it must carry exactly one name, a snapshot's (ziro.local/sandbox/<owner>/<name>:<t>).
func (m *sandboxManager) importSnapshot(w http.ResponseWriter, r *http.Request) {
	ref, err := m.importSnapshotTar(r.Context(), http.MaxBytesReader(w, r.Body, snapshotImageMax+snapshotWorkspaceMax+(1<<20)))
	apiReply(w, err, sdkapi.SandboxSnapshot{Image: ref})
}

func (m *sandboxManager) importSnapshotTar(ctx context.Context, body io.Reader) (string, error) {
	tr := tar.NewReader(body)
	h, err := tr.Next()
	if err != nil || h.Name != "image.tar" || h.Typeflag != tar.TypeReg || h.Size > snapshotImageMax {
		return "", errors.New("import: the archive must start with image.tar")
	}
	img, err := snapshotTemp()
	if err != nil {
		return "", err
	}
	defer os.Remove(img)
	if err := copyToFile(img, io.LimitReader(tr, h.Size), h.Size); err != nil {
		return "", err
	}
	names, err := imageTarNames(img)
	if err != nil {
		return "", err
	}
	if len(names) != 1 || !snapshotImageRe.MatchString(names[0]) {
		return "", fmt.Errorf("import: not a snapshot image (names %q)", names)
	}
	if out, err := sandboxNerdctl(ctx, "load", "-i", img); err != nil {
		return "", fmt.Errorf("load: %s", cmdError(out, err))
	}
	// From here on the name is the host's own, from its image list.
	ref, err := findSnapshot(ctx, names[0])
	if err != nil {
		return "", fmt.Errorf("import: %s isn't listed after the load", names[0])
	}
	h, err = tr.Next()
	switch {
	case errors.Is(err, io.EOF):
		return ref, nil
	case err != nil:
		return ref, err
	case h.Name != "workspace.tar.gz" || h.Typeflag != tar.TypeReg || h.Size > snapshotWorkspaceMax:
		return ref, errors.New("import: unexpected archive member " + h.Name)
	}
	arc := snapshotArchive(ref)
	if err := os.MkdirAll(filepath.Dir(arc), 0700); err != nil {
		return ref, err
	}
	tmp := arc + ".part"
	if err := copyToFile(tmp, io.LimitReader(tr, h.Size), h.Size); err != nil {
		os.Remove(tmp)
		return ref, err
	}
	return ref, os.Rename(tmp, arc)
}

func snapshotTemp() (string, error) {
	dir := filepath.Join(snapshotsDir(), "tmp")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	f, err := os.CreateTemp(dir, "snap-*")
	if err != nil {
		return "", err
	}
	return f.Name(), f.Close()
}

// copyToFile writes exactly n bytes from r to path (0600).
func copyToFile(path string, r io.Reader, n int64) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	_, err = io.CopyN(f, r, n)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// imageTarNames reads the image names an image archive (nerdctl/docker save: OCI index.json
// and/or docker manifest.json) declares.
func imageTarNames(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var names []string
	tr := tar.NewReader(f)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("image archive: %w", err)
		}
		switch strings.TrimPrefix(h.Name, "./") {
		case "index.json":
			var idx struct {
				Manifests []struct {
					Annotations map[string]string `json:"annotations"`
				} `json:"manifests"`
			}
			if err := json.NewDecoder(io.LimitReader(tr, 1<<20)).Decode(&idx); err != nil {
				return nil, fmt.Errorf("index.json: %w", err)
			}
			for _, mf := range idx.Manifests {
				if n := mf.Annotations["io.containerd.image.name"]; n != "" {
					names = append(names, n)
				}
			}
		case "manifest.json":
			var mfs []struct{ RepoTags []string }
			if err := json.NewDecoder(io.LimitReader(tr, 1<<20)).Decode(&mfs); err != nil {
				return nil, fmt.Errorf("manifest.json: %w", err)
			}
			for _, mf := range mfs {
				names = append(names, mf.RepoTags...)
			}
		}
	}
	slices.Sort(names)
	return slices.Compact(names), nil
}

// ---- the master ----

// snapshotSyncEvery is how often the cluster leader converges snapshots (a pass is one list call
// per node when nothing is missing).
const snapshotSyncEvery = time.Minute

// snapshotTombstoneTTL is how long a deleted snapshot is remembered (longer than any copy).
const snapshotTombstoneTTL = 3 * time.Hour

var snapshotSyncing atomic.Bool

// syncSnapshots is the leader's pass: snapshots deleted through the master are removed wherever
// a copy remains, and every other snapshot is copied to the sandbox nodes of its architecture
// that don't hold it.
func syncSnapshots(ctx context.Context) {
	if !snapshotSyncing.CompareAndSwap(false, true) {
		return // the previous pass is still copying
	}
	defer snapshotSyncing.Store(false)
	v, ok := sandboxClusterState()
	if !ok || v.token == "" {
		return
	}
	now := time.Now()
	_ = sandboxClusterMutate(func(st *ClusterState) error {
		for img, at := range st.SnapshotTombstones {
			if now.Sub(at) > snapshotTombstoneTTL {
				delete(st.SnapshotTombstones, img)
			}
		}
		return nil
	})
	rq, _ := http.NewRequestWithContext(asHostRoot(ctx), http.MethodGet, "/", nil)
	held := map[string][]*ClusterNode{}
	for _, n := range v.sandboxNodes() {
		for _, image := range v.snapshotsOn(rq, n) {
			held[image] = append(held[image], n)
		}
	}
	for image, holders := range held {
		if _, gone := v.st.SnapshotTombstones[image]; gone {
			for _, n := range holders {
				q := "/v1/sandboxes/snapshots?" + url.Values{"image": {image}}.Encode()
				_, _, _ = v.call(rq, n, http.MethodDelete, q, nil)
			}
			continue
		}
		for _, n := range v.sandboxNodes() {
			if slices.ContainsFunc(holders, func(h *ClusterNode) bool { return h.ID == n.ID }) || n.Arch != holders[0].Arch {
				continue
			}
			err := v.copySnapshot(ctx, holders[0], n, image)
			_ = auditLog("cluster-master", "mesh", "sandbox snapshot replicate", image+" "+holders[0].ID+" -> "+n.ID, err)
			if err != nil {
				fmt.Printf("[cluster] snapshot %s to %s: %v\n", image, n.ID, err)
			}
		}
	}
}

// snapshotSyncHTTP has no overall timeout: a large image takes as long as it takes (ctx bounds it).
var snapshotSyncHTTP = &http.Client{}

// copySnapshot streams a snapshot from one node's export into another's import. image is a name
// the source node listed.
func (v *sandboxClusterView) copySnapshot(ctx context.Context, from, to *ClusterNode, image string) error {
	src, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"http://"+sandboxMeshAddr(from)+"/v1/snapshots/export?"+url.Values{"image": {image}}.Encode(), nil)
	if err != nil {
		return err
	}
	src.Header.Set("Authorization", "Bearer "+v.token)
	resp, err := snapshotSyncHTTP.Do(src)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return fmt.Errorf("export from %s: HTTP %d %s", from.ID, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	dst, err := http.NewRequestWithContext(ctx, http.MethodPut, "http://"+sandboxMeshAddr(to)+"/v1/snapshots/import", resp.Body)
	if err != nil {
		return err
	}
	dst.Header.Set("Authorization", "Bearer "+v.token)
	dst.Header.Set("Content-Type", "application/x-tar")
	out, err := snapshotSyncHTTP.Do(dst)
	if err != nil {
		return err
	}
	defer out.Body.Close()
	if out.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(out.Body, 4<<10))
		return fmt.Errorf("import on %s: HTTP %d %s", to.ID, out.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}
