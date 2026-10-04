package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
)

const unitPath = "/etc/systemd/system/zirocd.service"

// The unit keeps only the capabilities a tunnel needs; Restart=always also starts a freshly
// updated (or rolled back) binary.
const unit = `[Unit]
Description=Ziro client daemon (zirocd)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=%s daemon
Restart=always
RestartSec=2
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_DAC_OVERRIDE
NoNewPrivileges=yes
ProtectHome=yes
PrivateTmp=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
StateDirectory=zirocd
StateDirectoryMode=0700

[Install]
WantedBy=multi-user.target
`

func runAsService() (bool, error) { return false, nil }

func installService(exe string) error {
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		if _, zerr := os.Stat("/etc/ziro-release"); zerr == nil {
			return errors.New("on Ziro OS run: ziroctl router join <key>")
		}
		return errors.New("systemd not found: run `zirocd daemon` under your init system")
	}
	if err := os.WriteFile(unitPath, []byte(fmt.Sprintf(unit, exe)), 0644); err != nil {
		return err
	}
	if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
		return err
	}
	return exec.Command("systemctl", "enable", "--now", "zirocd").Run()
}

func uninstallService() error {
	_ = exec.Command("systemctl", "disable", "--now", "zirocd").Run()
	if err := os.Remove(unitPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return exec.Command("systemctl", "daemon-reload").Run()
}
