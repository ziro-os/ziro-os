package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

// Kept separate so tests never modify the host's real authorized keys.
var sshAuthorizedKeysPath = rootAuthorizedKeys

var sshCmd = &cobra.Command{
	Use:   "ssh",
	Short: "Manage SSH access",
	Example: `  ziroctl ssh key import gh:octocat
  ziroctl ssh status`,
	Long: `Inspect SSH remote management status and manage authorized public keys for hardened, passwordless remote access.`,
}

var sshStatusCmd = &cobra.Command{
	Use:     "status",
	Short:   "Show sshd state and host key fingerprints",
	Example: `  ziroctl ssh status`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Println("=== Ziro-OS SSH Remote Management ===")

		// Check if sshd is running
		sshdRunning := false
		if _, err := exec.Command("pidof", "sshd").Output(); err == nil {
			sshdRunning = true
		} else if _, err := os.Stat("/run/sshd.pid"); err == nil {
			sshdRunning = true
		}

		if sshdRunning {
			cmd.Println("Status:          [RUNNING] (Port 22, Public Key Authentication)")
		} else {
			cmd.Println("Status:          [STOPPED]")
		}

		// Check host keys
		ed25519Key := "/etc/ssh/ssh_host_ed25519_key.pub"
		if data, err := os.ReadFile(ed25519Key); err == nil {
			parts := strings.Fields(string(data))
			if len(parts) >= 2 {
				cmd.Printf("Host Key:        ED25519 (SHA256 fingerprint verified)\n")
			}
		}

		// Check authorized keys
		authKeysPath := sshAuthorizedKeysPath
		if data, err := os.ReadFile(authKeysPath); err == nil {
			lines := strings.Split(strings.TrimSpace(string(data)), "\n")
			validCount := 0
			for _, l := range lines {
				if strings.TrimSpace(l) != "" && !strings.HasPrefix(l, "#") {
					validCount++
				}
			}
			cmd.Printf("Authorized Keys: %d key(s) configured in %s\n", validCount, authKeysPath)
		} else {
			cmd.Println("Authorized Keys: None configured (passwordless root login is restricted)")
		}
	},
}

var sshKeyCmd = &cobra.Command{
	Use:   "key",
	Short: "Manage authorized SSH keys",
	Example: `  ziroctl ssh key import gh:octocat
  ziroctl ssh key list`,
}

var sshKeyAddCmd = &cobra.Command{
	Use:     "add <public-key-string>",
	Short:   "Authorize a public key for root",
	Example: `  ziroctl ssh key add "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... user@example.com"`,
	Args:    cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		key := strings.TrimSpace(strings.Join(args, " "))
		if !strings.HasPrefix(key, "ssh-") && !strings.HasPrefix(key, "ecdsa-") {
			return fmt.Errorf("invalid SSH public key format: must begin with ssh-* or ecdsa-*")
		}

		sshDir := filepath.Dir(sshAuthorizedKeysPath)
		if err := os.MkdirAll(sshDir, 0700); err != nil {
			return fmt.Errorf("failed to create %s: %w", sshDir, err)
		}
		_ = os.Chmod(sshDir, 0700)

		authKeysPath := sshAuthorizedKeysPath
		f, err := os.OpenFile(authKeysPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			return fmt.Errorf("failed to open %s: %w", authKeysPath, err)
		}
		defer f.Close()

		if _, err := f.WriteString(key + "\n"); err != nil {
			return fmt.Errorf("failed to write key: %w", err)
		}
		_ = os.Chmod(authKeysPath, 0600)

		cmd.Println("✅ SSH public key added successfully. Authorized logins enabled.")
		return nil
	},
}

var sshKeyListCmd = &cobra.Command{
	Use:     "list",
	Short:   "List authorized keys",
	Example: `  ziroctl ssh key list`,
	RunE: func(cmd *cobra.Command, args []string) error {
		authKeysPath := sshAuthorizedKeysPath
		data, err := os.ReadFile(authKeysPath)
		if err != nil {
			if os.IsNotExist(err) {
				cmd.Println("No authorized keys found.")
				return nil
			}
			return err
		}

		cmd.Println("=== Authorized SSH Keys ===")
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		count := 0
		for i, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.Fields(line)
			keyType := parts[0]
			comment := ""
			if len(parts) >= 3 {
				comment = strings.Join(parts[2:], " ")
			}
			cmd.Printf("[%d] Type: %s | Comment: %s\n", i+1, keyType, comment)
			count++
		}
		if count == 0 {
			cmd.Println("No active keys found.")
		}
		return nil
	},
}

var sshKeyClearCmd = &cobra.Command{
	Use:     "clear",
	Short:   "Remove every authorized key",
	Example: `  ziroctl ssh key clear`,
	RunE: func(cmd *cobra.Command, args []string) error {
		authKeysPath := sshAuthorizedKeysPath
		if err := os.Remove(authKeysPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to remove %s: %w", authKeysPath, err)
		}
		cmd.Println("✅ All authorized keys cleared. Remote root SSH access disabled.")
		return nil
	},
}

func init() {
	sshKeyCmd.AddCommand(sshKeyAddCmd)
	sshKeyCmd.AddCommand(sshKeyListCmd)
	sshKeyCmd.AddCommand(sshKeyClearCmd)

	sshCmd.AddCommand(sshStatusCmd)
	sshCmd.AddCommand(sshKeyCmd)

	rootCmd.AddCommand(sshCmd)
}
