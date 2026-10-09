package cmd

import (
	"errors"
	"fmt"
	"os"
	"time"
)

// binaryUpdate describes a module whose upstream binaries the signed catalog pins and a daily
// job keeps current (cloudflared, tailscale): refresh the catalog, upgrade the module when its
// pinned version moved, restart, and put the previous binaries back if the service does not come
// back healthy.
type binaryUpdate struct {
	Module       string   // module name
	Title        string   // shown to the operator
	Binaries     []string // files the upgrade replaces: kept as <file>.prev until the new ones prove healthy
	AuditSource  string   // audit record: source (cf, tailscale)
	AuditAction  string   // audit record: action (cf update)
	Check, Cron  bool
	AutoSetting  string                // module setting that turns the daily job off when "false"
	Restart      func() (healthy bool) // restart onto the new binaries and report whether the service came back
	AlertOnError string                // alert category when a rollback was needed
}

func updateModuleBinaries(u binaryUpdate) error {
	st := enabledModules()[u.Module]
	if u.Cron {
		if st != nil && st.Settings[u.AutoSetting] == "false" {
			return nil
		}
		time.Sleep(time.Duration(time.Now().UnixNano() % int64(30*time.Minute))) // spread hosts out
	}
	repos, err := catalogRepos("module")
	if err != nil {
		return err
	}
	for _, r := range repos {
		if r.Official {
			if _, err := refreshRepo(r); err != nil {
				return fmt.Errorf("refresh catalog %s: %w", r.Name, err)
			}
		}
	}
	all, err := loadManifests()
	if err != nil {
		return err
	}
	cur, _ := installedManifest(all, u.Module)
	next, ok := all[u.Module]
	if !ok {
		return fmt.Errorf("%s is no longer in the catalog", u.Title)
	}
	avail := next.Version != cur.Version
	if u.Check {
		return printResult(map[string]any{"current": cur.Version, "available": next.Version, "update": avail}, func() {
			if avail {
				fmt.Printf("%s %s → %s available: ziroctl %s update\n", u.Title, cur.Version, next.Version, u.AuditSource)
			} else {
				fmt.Printf("= %s is up to date (%s)\n", u.Title, cur.Version)
			}
		})
	}
	if !avail {
		if !u.Cron {
			fmt.Printf("= %s is up to date (%s)\n", u.Title, cur.Version)
		}
		return nil
	}
	for _, f := range u.Binaries {
		if b, err := os.ReadFile(f); err == nil {
			_ = writeFileAtomic(f+".prev", b, 0755)
		}
	}
	if err := upgradeModule(u.Module, false); err != nil {
		return err
	}
	return restartChecked(u, next.Version)
}

// restartChecked restarts onto the new binaries and puts the previous ones back when the service
// does not come back healthy.
// ponytail: after a rollback the next boot fetches the pinned binary again (one more try); a
// held version would need state in the module.
func restartChecked(u binaryUpdate, version string) error {
	if u.Restart() {
		for _, f := range u.Binaries {
			_ = os.Remove(f + ".prev")
		}
		_ = auditLog("ziroctl", u.AuditSource, u.AuditAction, u.Title+" "+version, nil)
		fmt.Printf("✓ %s %s\n", u.Title, version)
		return nil
	}
	var rollbackErr error
	for _, f := range u.Binaries {
		b, err := os.ReadFile(f + ".prev")
		if err == nil {
			err = writeFileAtomic(f, b, 0755)
		}
		rollbackErr = errors.Join(rollbackErr, err)
	}
	if rollbackErr == nil {
		u.Restart()
	}
	msg := fmt.Sprintf("%s %s did not come back; previous version restored", u.Title, version)
	if rollbackErr != nil {
		msg = fmt.Sprintf("%s %s did not come back and the rollback failed: %v", u.Title, version, rollbackErr)
	}
	alertf("high", u.AlertOnError, msg, nil)
	return errors.New(msg)
}
