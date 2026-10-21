package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	sdkapi "github.com/ziro-os/ziro-os/sdk/api"
)

// Snapshots: a sandbox's filesystem, which new sandboxes start from: install once, fork many.
// Two parts, taken while the sandbox is paused so they agree:
//   - its rootfs, committed to a local image (nerdctl commit) named
//     ziro.local/sandbox/<owner>/<name>:<unix time>;
//   - its /workspace, a bind mount commit never sees, archived next to the sandboxes as
//     .snapshots/<owner>/<name>/<unix time>.tar.gz and unpacked into the new sandbox's workspace.
//
// A caller can start only from its own snapshots (operators from any), and they skip the host
// image policy (they come from this host). /tmp (a tmpfs) is not kept.
//
// Known limitation: filesystem only; memory (runsc checkpoint/restore) when a workload needs it.

const snapshotRepo = "ziro.local/sandbox/"

// The caps of a workspace archive.
const (
	snapshotWorkspaceMax   = 8 << 30
	snapshotWorkspaceFiles = 500_000
)

func snapshotsDir() string { return filepath.Join(sandboxRoot, ".snapshots") }

// snapshotArchive is where a snapshot image's workspace is kept. ref comes from the image list
// (findSnapshot), never from a request.
func snapshotArchive(ref string) string {
	repo, ts, _ := strings.Cut(strings.TrimPrefix(ref, snapshotRepo), ":")
	return filepath.Join(snapshotsDir(), filepath.FromSlash(repo), ts+".tar.gz")
}

var snapshotNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

// snapshotImageRe: a snapshot's image reference as snapshot() names it.
var snapshotImageRe = regexp.MustCompile(`^ziro\.local/sandbox/[a-z0-9._-]{1,64}/[a-z0-9][a-z0-9._-]{0,62}:[0-9]{1,20}$`)

// snapshotOwner turns an owner (token name, "root") into an image path segment.
func snapshotOwner(owner string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '.' || r == '_' {
			return r
		}
		return '-'
	}, strings.ToLower(owner))
}

// snapshotAllowed reports whether the caller may start a sandbox from image, and whether the
// image is a snapshot at all.
func snapshotAllowed(image string, c sandboxCaller) (snapshot bool, err error) {
	if !strings.HasPrefix(image, snapshotRepo) {
		return false, nil
	}
	if c.seesAll() || strings.HasPrefix(image, snapshotRepo+snapshotOwner(c.Owner)+"/") {
		return true, nil
	}
	return true, errNotFound("no such snapshot")
}

func (m *sandboxManager) snapshot(ctx context.Context, id string, c sandboxCaller, name string) (sdkapi.SandboxSnapshot, error) {
	sb, err := m.st.get(id, c)
	if err != nil {
		return sdkapi.SandboxSnapshot{}, err
	}
	if !snapshotNameRe.MatchString(name) {
		return sdkapi.SandboxSnapshot{}, errors.New("snapshot name: lowercase letters, digits, . _ -")
	}
	if sb.State != "running" && sb.State != "paused" {
		return sdkapi.SandboxSnapshot{}, fmt.Errorf("sandbox %s is %s", id, sb.State)
	}
	image := snapshotRepo + snapshotOwner(sb.Owner) + "/" + name + ":" + strconv.FormatInt(m.now().Unix(), 10)
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	ctr := sandboxContainer(id)
	if sb.State == "running" {
		// Flush what the sandbox wrote, then freeze it so the rootfs and the workspace agree.
		sctx, scancel := context.WithTimeout(ctx, 30*time.Second)
		_, _ = sandboxNerdctl(sctx, "exec", ctr, "sync")
		scancel()
		if out, err := sandboxNerdctl(ctx, "pause", ctr); err != nil {
			return sdkapi.SandboxSnapshot{}, fmt.Errorf("snapshot: pause: %s", cmdError(out, err))
		}
		defer func() {
			if out, err := sandboxNerdctl(context.Background(), "unpause", ctr); err != nil {
				fmt.Printf("[sandboxd] snapshot of %s: unpause: %s\n", id, cmdError(out, err))
			}
		}()
	}
	arc := snapshotArchive(image)
	size, err := archiveWorkspace(id, arc)
	if err != nil {
		return sdkapi.SandboxSnapshot{}, fmt.Errorf("snapshot: workspace: %w", err)
	}
	// The sandbox is paused by now; commit's own pause would fail on it.
	if out, err := sandboxNerdctl(ctx, "commit", "--pause=false", ctr, image); err != nil {
		_ = os.Remove(arc)
		return sdkapi.SandboxSnapshot{}, fmt.Errorf("snapshot: %s", cmdError(out, err))
	}
	return sdkapi.SandboxSnapshot{Image: image, Sandbox: id, Created: m.now().UTC(), WorkspaceSize: size}, nil
}

// archiveWorkspace writes a sandbox's workspace to arc (atomically) and returns its size.
func archiveWorkspace(id, arc string) (int64, error) {
	root, err := openWorkspace(id)
	if err != nil {
		return 0, err
	}
	defer root.Close()
	if err := os.MkdirAll(filepath.Dir(arc), 0700); err != nil {
		return 0, err
	}
	f, err := os.CreateTemp(filepath.Dir(arc), ".tmp-*")
	if err != nil {
		return 0, err
	}
	defer os.Remove(f.Name()) // a no-op after the rename
	err = tarGzDir(root, f, snapshotWorkspaceMax, snapshotWorkspaceFiles)
	if serr := f.Sync(); err == nil {
		err = serr
	}
	fi, serr := f.Stat()
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = serr
	}
	if err != nil {
		return 0, err
	}
	return fi.Size(), os.Rename(f.Name(), arc)
}

// restoreWorkspace unpacks a snapshot's workspace (if it has one: older snapshots don't) into a
// new sandbox's empty workspace.
func restoreWorkspace(ref, id string) error {
	f, err := os.Open(snapshotArchive(ref))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	return untarGz(filepath.Join(sandboxDir(id), "workspace"), f,
		untarOpts{maxBytes: snapshotWorkspaceMax, maxFiles: snapshotWorkspaceFiles, links: true, owners: true})
}

// findSnapshot returns the image list's own reference for a snapshot image, so what is used
// from here on (an archive path, a command line) comes from the host, not from the request.
func findSnapshot(ctx context.Context, image string) (string, error) {
	out, err := sandboxNerdctl(ctx, "images", "--format", "{{.Repository}}:{{.Tag}}")
	if err != nil {
		return "", fmt.Errorf("list images: %s", cmdError(out, err))
	}
	for _, ref := range strings.Fields(string(out)) {
		if ref == image && snapshotImageRe.MatchString(ref) {
			return ref, nil
		}
	}
	return "", errNotFound("no such snapshot")
}

func (m *sandboxManager) snapshots(ctx context.Context, c sandboxCaller) ([]sdkapi.SandboxSnapshot, error) {
	out, err := sandboxNerdctl(ctx, "images", "--format", "{{.Repository}}:{{.Tag}}\t{{.Size}}")
	if err != nil {
		return nil, fmt.Errorf("list images: %s", cmdError(out, err))
	}
	list := []sdkapi.SandboxSnapshot{}
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		ref, size, _ := strings.Cut(l, "\t")
		if mine, err := snapshotAllowed(ref, c); !mine || err != nil {
			continue
		}
		s := sdkapi.SandboxSnapshot{Image: ref, Size: size}
		if fi, err := os.Stat(snapshotArchive(ref)); err == nil {
			s.WorkspaceSize = fi.Size()
		}
		if i := strings.LastIndex(ref, ":"); i > 0 {
			if ts, err := strconv.ParseInt(ref[i+1:], 10, 64); err == nil {
				s.Created = time.Unix(ts, 0).UTC()
			}
		}
		list = append(list, s)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Image < list[j].Image })
	return list, nil
}

func (m *sandboxManager) removeSnapshot(ctx context.Context, c sandboxCaller, image string) error {
	if mine, err := snapshotAllowed(image, c); !mine || err != nil {
		return errNotFound("no such snapshot")
	}
	ref, err := findSnapshot(ctx, image)
	if err != nil {
		return err
	}
	if out, err := sandboxNerdctl(ctx, "rmi", ref); err != nil {
		return fmt.Errorf("remove snapshot: %s", cmdError(out, err))
	}
	if err := os.Remove(snapshotArchive(ref)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove snapshot workspace: %w", err)
	}
	return nil
}
