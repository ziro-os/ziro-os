package cmd

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	sdkapi "github.com/ziro-os/ziro-os/sdk/api"
)

// Snapshots: a sandbox's filesystem committed to a local image (nerdctl commit), which new
// sandboxes start from: install once, fork many. Images are named
// ziro.local/sandbox/<owner>/<name>:<unix time>; a caller can start only from its own snapshots
// (operators from any), and they skip the host image policy (they come from this host).
//
// ponytail: filesystem only; memory (runsc checkpoint/restore) when a workload needs it.

const snapshotRepo = "ziro.local/sandbox/"

var snapshotNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

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
	if out, err := sandboxNerdctl(ctx, "commit", sandboxContainer(id), image); err != nil {
		return sdkapi.SandboxSnapshot{}, fmt.Errorf("snapshot: %s", cmdError(out, err))
	}
	return sdkapi.SandboxSnapshot{Image: image, Sandbox: id, Created: m.now().UTC()}, nil
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
	if out, err := sandboxNerdctl(ctx, "rmi", image); err != nil {
		return fmt.Errorf("remove snapshot: %s", cmdError(out, err))
	}
	return nil
}
