// Package update keeps zirocd current from the signed tools release stream (tags tools/vX.Y.Z):
// nothing is installed unless SHA256SUMS carries the Ziro release signature and the binary
// matches it. The swap is atomic, the previous binary is kept, and a new binary that cannot
// reach "connected" within two starts is rolled back.
package update

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/ziro-os/ziro-os/sdk/release"
)

const maxBinary = 128 << 20

// AssetName is this platform's binary in a tools release.
func AssetName() string {
	n := "zirocd-" + runtime.GOOS + "-" + runtime.GOARCH
	if runtime.GOOS == "windows" {
		n += ".exe"
	}
	return n
}

type Updater struct {
	Current string // running version
	Exe     string // path of the running binary
	Dir     string // state dir (rollback marker)
	Source  *release.Source
}

type marker struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Attempts int    `json:"attempts"`
}

func (u *Updater) markerPath() string { return filepath.Join(u.Dir, "update-pending.json") }

// Target picks the version to run: the admin's pin, else the newest release. "" = stay.
func (u *Updater) Target(ctx context.Context, pinned string) (string, error) {
	if pinned != "" {
		if pinned == u.Current {
			return "", nil
		}
		return pinned, nil // an admin pin may also roll the fleet back
	}
	_, latest, err := u.Source.Tools(ctx, "")
	if err != nil {
		return "", err
	}
	if release.Compare(latest, u.Current) <= 0 {
		return "", nil
	}
	return latest, nil
}

// Install downloads and verifies version, then swaps it in place of the running binary,
// keeping the current one as <exe>.prev. The caller restarts the process afterwards.
func (u *Updater) Install(ctx context.Context, version string) error {
	rel, v, err := u.Source.Tools(ctx, version)
	if err != nil {
		return err
	}
	bin, err := u.Source.Fetch(ctx, rel, AssetName(), maxBinary)
	if err != nil {
		return err
	}
	next, prev := u.Exe+".new", u.Exe+".prev"
	if err := os.WriteFile(next, bin, 0755); err != nil {
		return err
	}
	_ = os.Remove(prev)
	// Renaming a running binary is allowed on every platform (Windows included); the new one
	// takes the old path, so the service definition never changes.
	if err := os.Rename(u.Exe, prev); err != nil {
		os.Remove(next)
		return err
	}
	if err := os.Rename(next, u.Exe); err != nil {
		_ = os.Rename(prev, u.Exe)
		return err
	}
	b, _ := json.Marshal(marker{From: u.Current, To: v})
	return os.WriteFile(u.markerPath(), b, 0600)
}

// Startup counts a start of a freshly installed binary and rolls back to <exe>.prev after two
// starts that never reached Healthy. It reports whether it rolled back (the caller then exits
// so the service manager starts the previous binary).
func (u *Updater) Startup() (rolledBack bool, err error) {
	b, err := os.ReadFile(u.markerPath())
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var m marker
	_ = json.Unmarshal(b, &m)
	m.Attempts++
	if m.Attempts <= 2 {
		b, _ = json.Marshal(m)
		return false, os.WriteFile(u.markerPath(), b, 0600)
	}
	prev := u.Exe + ".prev"
	if _, err := os.Stat(prev); err != nil {
		os.Remove(u.markerPath())
		return false, fmt.Errorf("update to %s keeps failing and no previous binary is kept", m.To)
	}
	_ = os.Remove(u.Exe + ".bad")
	if err := os.Rename(u.Exe, u.Exe+".bad"); err != nil {
		return false, err
	}
	if err := os.Rename(prev, u.Exe); err != nil {
		_ = os.Rename(u.Exe+".bad", u.Exe)
		return false, err
	}
	os.Remove(u.markerPath())
	return true, nil
}

// Healthy confirms the running binary (the first netmap arrived): no rollback needed.
func (u *Updater) Healthy() { os.Remove(u.markerPath()) }

// Loop checks every 6 hours (±1h jitter, first after 2–10 minutes). policy is "on", "notify" or
// "off"; restart is called after a successful install.
func (u *Updater) Loop(ctx context.Context, policy func() string, pinned func() string, notify func(string), restart func()) {
	wait := 2*time.Minute + rand.N(8*time.Minute)
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		wait = 5*time.Hour + rand.N(2*time.Hour)
		p := policy()
		if p == "off" || strings.Contains(u.Current, "dev") {
			continue
		}
		tctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
		v, err := u.Target(tctx, pinned())
		if err == nil && v != "" {
			if p == "notify" {
				notify(v)
			} else if err = u.Install(tctx, v); err == nil {
				cancel()
				restart()
				return
			}
		}
		cancel()
		if err != nil {
			fmt.Fprintf(os.Stderr, "zirocd: update check: %v\n", err)
		}
	}
}
