package cmd

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
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
	if out, err := sandboxNerdctlLow(r.Context(), "save", "-o", tmp, ref); err != nil {
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
	// Room for the archive and the unpacked image, and some to spare: a copy never fills a node.
	if free := diskFree(snapshotsDir()); free >= 0 && free < 2*h.Size+(1<<30) {
		return "", fmt.Errorf("import: not enough disk (%d MiB free, %d MiB needed)", free>>20, (2*h.Size+(1<<30))>>20)
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
	if out, err := sandboxNerdctlLow(ctx, "load", "-i", img); err != nil {
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

// Snapshots are kept on snapshot_replicas sandbox nodes of their architecture (default 2: the node
// that took it and one more), not on every node: enough to survive the loss of a node without
// every snapshot costing every node its disk and a transfer. A create from a snapshot runs on a
// node that holds it.

// snapshotSyncEvery is how often the cluster leader checks the copies (one list call per node).
const snapshotSyncEvery = 5 * time.Minute

// snapshotTombstoneTTL is how long a deleted snapshot is remembered (longer than any copy).
const snapshotTombstoneTTL = 3 * time.Hour

var snapshotSyncing atomic.Bool

// snapshotReplication reads the copy count and bandwidth from the master's sandbox config.
func snapshotReplication() (replicas int, bytesPerSec int64) {
	cfg, _ := loadSandboxConfig()
	replicas, mbps := cfg.SnapshotReplicas, cfg.SnapshotCopyMBps
	if replicas <= 0 {
		replicas = 2
	}
	if mbps <= 0 {
		mbps = 50
	}
	return replicas, int64(mbps) << 20
}

// syncSnapshots is the leader's pass: snapshots deleted through the master are removed wherever a
// copy remains, and a snapshot held by fewer nodes than it should be is copied to the least
// loaded sandbox node of its architecture that lacks it, one transfer at a time, at a bounded
// rate and low priority on both ends.
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
	expired := false
	for _, at := range v.st.SnapshotTombstones {
		expired = expired || now.Sub(at) > snapshotTombstoneTTL
	}
	if expired { // no commit at all when there is nothing to forget
		_ = sandboxClusterMutate(func(st *ClusterState) error {
			for img, at := range st.SnapshotTombstones {
				if now.Sub(at) > snapshotTombstoneTTL {
					delete(st.SnapshotTombstones, img)
				}
			}
			return nil
		})
	}
	rq, _ := http.NewRequestWithContext(asHostRoot(ctx), http.MethodGet, "/", nil)
	nodes := v.sandboxNodes()
	held := map[string][]*ClusterNode{}
	load := map[string]int{} // node -> snapshots it holds
	for _, n := range nodes {
		for _, image := range v.snapshotsOn(rq, n) {
			held[image] = append(held[image], n)
			load[n.ID]++
		}
	}
	want, rate := snapshotReplication()
	for image, holders := range held {
		if _, gone := v.st.SnapshotTombstones[image]; gone {
			for _, n := range holders {
				q := "/v1/sandboxes/snapshots?" + url.Values{"image": {image}}.Encode()
				_, _, _ = v.call(rq, n, http.MethodDelete, q, nil)
			}
			continue
		}
		for len(holders) < want {
			to := snapshotTarget(nodes, holders, load)
			if to == nil {
				break // every node of its architecture has it
			}
			err := v.copySnapshot(ctx, holders[0], to, image, rate)
			_ = auditLog("cluster-master", "mesh", "sandbox snapshot replicate", image+" "+holders[0].ID+" -> "+to.ID, err)
			if err != nil {
				fmt.Printf("[cluster] snapshot %s to %s: %v\n", image, to.ID, err)
				break
			}
			holders = append(holders, to)
			load[to.ID]++
		}
	}
}

// snapshotTarget picks the node a snapshot is copied to: same architecture as its holders, not one
// of them, ready, and holding the fewest snapshots.
func snapshotTarget(nodes, holders []*ClusterNode, load map[string]int) *ClusterNode {
	var best *ClusterNode
	for _, n := range nodes {
		if n.Status != "Ready" || n.Arch != holders[0].Arch || slices.ContainsFunc(holders, func(h *ClusterNode) bool { return h.ID == n.ID }) {
			continue
		}
		if best == nil || load[n.ID] < load[best.ID] {
			best = n
		}
	}
	return best
}

// snapshotSyncHTTP has no overall timeout: a large image takes as long as it takes (ctx bounds it).
var snapshotSyncHTTP = &http.Client{}

// copySnapshot streams a snapshot from one node's export into another's import. image is a name
// the source node listed.
func (v *sandboxClusterView) copySnapshot(ctx context.Context, from, to *ClusterNode, image string, bytesPerSec int64) error {
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
	dst, err := http.NewRequestWithContext(ctx, http.MethodPut, "http://"+sandboxMeshAddr(to)+"/v1/snapshots/import",
		&rateReader{ctx: ctx, r: resp.Body, perSec: bytesPerSec, start: time.Now()})
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

// rateReader passes r through at most perSec bytes a second (on average since start): a snapshot
// copy never takes a node's whole disk or network.
type rateReader struct {
	ctx    context.Context
	r      io.Reader
	perSec int64
	start  time.Time
	n      int64
}

func (rr *rateReader) Read(p []byte) (int, error) {
	if len(p) > 256<<10 {
		p = p[:256<<10]
	}
	n, err := rr.r.Read(p)
	rr.n += int64(n)
	if ahead := time.Duration(rr.n*int64(time.Second)/rr.perSec) - time.Since(rr.start); ahead > 0 {
		select {
		case <-time.After(ahead):
		case <-rr.ctx.Done():
			return n, rr.ctx.Err()
		}
	}
	return n, err
}

// sandboxNerdctlLow runs nerdctl at low CPU and I/O priority (snapshot export and import).
var sandboxNerdctlLow = func(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "nerdctl", args...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	lowPriority(cmd.Process.Pid)
	err := cmd.Wait()
	return out.Bytes(), err
}

// diskFree is the space available under dir, or -1 when it can't be read.
var diskFree = func(dir string) int64 {
	var fs syscall.Statfs_t
	if err := os.MkdirAll(dir, 0700); err != nil || syscall.Statfs(dir, &fs) != nil {
		return -1
	}
	return int64(fs.Bavail) * int64(fs.Bsize)
}
