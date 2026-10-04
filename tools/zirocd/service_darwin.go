package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const plistPath = "/Library/LaunchDaemons/com.ziro.zirocd.plist"

const plist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.ziro.zirocd</string>
  <key>ProgramArguments</key><array><string>%s</string><string>daemon</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardErrorPath</key><string>/var/log/zirocd.log</string>
</dict>
</plist>
`

func runAsService() (bool, error) { return false, nil }

func installService(exe string) error {
	_ = exec.Command("launchctl", "bootout", "system/com.ziro.zirocd").Run()
	if err := os.WriteFile(plistPath, []byte(fmt.Sprintf(plist, strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(exe))), 0644); err != nil {
		return err
	}
	return exec.Command("launchctl", "bootstrap", "system", plistPath).Run()
}

func uninstallService() error {
	_ = exec.Command("launchctl", "bootout", "system/com.ziro.zirocd").Run()
	if err := os.Remove(plistPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
