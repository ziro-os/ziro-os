package cmd

import (
	"crypto/rsa"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

// ssh key import: fetch a user's published public keys (like Ubuntu's ssh-import-id).
// Keys are validated, deduplicated by fingerprint and tagged with their source, so they can be
// synced or removed later without touching other keys.

type keySource struct {
	prefix, url string
	user        *regexp.Regexp
}

var keySources = map[string]keySource{
	"gh": {"gh", "https://github.com/%s.keys", regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$`)},
	"gl": {"gl", "https://gitlab.com/%s.keys", regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,254}$`)},
	"lp": {"lp", "https://launchpad.net/~%s/+sshkeys", regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]{0,63}$`)},
}

const keyImportTag = "ziro-import:"

// parseKeySource validates "gh:user" and returns the fixed provider URL for it.
func parseKeySource(s string) (src, user, url string, err error) {
	p, u, ok := strings.Cut(strings.TrimSpace(s), ":")
	ks, known := keySources[p]
	if !ok || !known {
		return "", "", "", fmt.Errorf("invalid source %q: use gh:<user>, gl:<user> or lp:<user>", s)
	}
	if !ks.user.MatchString(u) {
		return "", "", "", fmt.Errorf("invalid %s username %q", p, u)
	}
	return p, u, fmt.Sprintf(ks.url, u), nil
}

var keyFetchClient = &http.Client{
	Timeout:   10 * time.Second,
	Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, Proxy: http.ProxyFromEnvironment},
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 || req.URL.Host != via[0].URL.Host || req.URL.Scheme != "https" {
			return errors.New("refusing redirect off the key provider")
		}
		return nil
	},
}

func fetchPublicKeys(url string) ([]byte, error) {
	resp, err := keyFetchClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, fmt.Errorf("no such user (%s)", url)
	default:
		return nil, fmt.Errorf("%s answered %s", url, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64<<10))
}

type importedKey struct {
	line, fp string
}

// acceptKeys parses provider output, keeping only strong key types, each re-serialised as
// "<type> <base64> ziro-import:<src>:<user>" (no options, no provider comment).
func acceptKeys(data []byte, tag string) (keys []importedKey, rejected []string) {
	seen := map[string]bool{}
	for _, raw := range strings.Split(string(data), "\n") {
		raw = strings.TrimSpace(raw)
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		pk, _, opts, _, err := ssh.ParseAuthorizedKey([]byte(raw))
		if err != nil || len(opts) > 0 {
			rejected = append(rejected, "unparsable line")
			continue
		}
		if why := weakKey(pk); why != "" {
			rejected = append(rejected, why)
			continue
		}
		fp := ssh.FingerprintSHA256(pk)
		if seen[fp] {
			continue
		}
		seen[fp] = true
		keys = append(keys, importedKey{line: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk))) + " " + tag, fp: fp})
	}
	return keys, rejected
}

func weakKey(pk ssh.PublicKey) string {
	switch pk.Type() {
	case "ssh-dss": // DSA (the x/crypto constant is deprecated: DSA is insecure at any size it allows)
		return "ssh-dss (DSA) keys are not accepted"
	case ssh.KeyAlgoRSA:
		if ck, ok := pk.(ssh.CryptoPublicKey); ok {
			if rk, ok := ck.CryptoPublicKey().(*rsa.PublicKey); ok && rk.N.BitLen() < 2048 {
				return fmt.Sprintf("RSA key of %d bits (minimum 2048)", rk.N.BitLen())
			}
		}
	}
	return ""
}

// mergeAuthorizedKeys adds new keys (by fingerprint) and, with sync, drops keys carrying tag that
// the provider no longer lists. Other lines are kept byte for byte.
func mergeAuthorizedKeys(existing []byte, keys []importedKey, tag string, sync bool) (out []byte, added, removed int) {
	want := map[string]bool{}
	for _, k := range keys {
		want[k.fp] = true
	}
	have := map[string]bool{}
	var lines []string
	for _, l := range strings.Split(strings.TrimRight(string(existing), "\n"), "\n") {
		if l == "" {
			continue
		}
		pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(l))
		if err == nil {
			fp := ssh.FingerprintSHA256(pk)
			if sync && strings.HasSuffix(l, " "+tag) && !want[fp] {
				removed++
				continue
			}
			have[fp] = true
		}
		lines = append(lines, l)
	}
	for _, k := range keys {
		if !have[k.fp] {
			lines = append(lines, k.line)
			have[k.fp] = true
			added++
		}
	}
	return []byte(strings.Join(lines, "\n") + "\n"), added, removed
}

func writeAuthorizedKeys(data []byte) error {
	if err := os.MkdirAll(filepath.Dir(sshAuthorizedKeysPath), 0700); err != nil {
		return err
	}
	return writeFileAtomic(sshAuthorizedKeysPath, data, 0600)
}

// importKeys fetches and merges one source. It never syncs to an empty set: a provider hiccup or
// a typo must not remove every imported key and lock the admin out.
func importKeys(source string, sync bool) (added, removed int, rejected []string, err error) {
	src, user, url, err := parseKeySource(source)
	if err != nil {
		return 0, 0, nil, err
	}
	data, err := fetchPublicKeys(url)
	if err != nil {
		return 0, 0, nil, err
	}
	tag := keyImportTag + src + ":" + user
	keys, rejected := acceptKeys(data, tag)
	if len(keys) == 0 {
		return 0, 0, rejected, fmt.Errorf("no usable keys published for %s:%s", src, user)
	}
	cur, _ := os.ReadFile(sshAuthorizedKeysPath)
	out, added, removed := mergeAuthorizedKeys(cur, keys, tag, sync)
	if added == 0 && removed == 0 {
		return 0, 0, rejected, nil
	}
	return added, removed, rejected, writeAuthorizedKeys(out)
}

// removeImportedKeys drops every key imported from source.
func removeImportedKeys(source string) (int, error) {
	src, user, _, err := parseKeySource(source)
	if err != nil {
		return 0, err
	}
	cur, err := os.ReadFile(sshAuthorizedKeysPath)
	if err != nil {
		return 0, err
	}
	out, _, removed := mergeAuthorizedKeys(cur, nil, keyImportTag+src+":"+user, true)
	if removed == 0 {
		return 0, fmt.Errorf("no keys imported from %s", source)
	}
	return removed, writeAuthorizedKeys(out)
}

var sshImportSync bool

var sshKeyImportCmd = &cobra.Command{
	Use:   "import <gh:user|gl:user|lp:user>...",
	Short: "Import a user's public SSH keys from GitHub, GitLab or Launchpad",
	Example: `  ziroctl ssh key import gh:octocat
  ziroctl ssh key import gh:alice gl:bob
  ziroctl ssh key import --sync gh:alice      # also drop keys alice removed upstream`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		var failed []string
		for _, s := range args {
			added, removed, rejected, err := importKeys(s, sshImportSync)
			for _, r := range rejected {
				fmt.Printf("  ! %s: skipped %s\n", s, r)
			}
			if err != nil {
				fmt.Printf("✗ %s: %v\n", s, err)
				failed = append(failed, s)
				continue
			}
			fmt.Printf("✓ %s: %d key(s) added, %d removed\n", s, added, removed)
		}
		if len(failed) > 0 {
			return fmt.Errorf("import failed for %s", strings.Join(failed, ", "))
		}
		return nil
	},
}

var sshKeyRemoveSource string

var sshKeyRemoveCmd = &cobra.Command{
	Use:   "remove --source <gh:user>",
	Short: "Remove every key imported from a source",
	RunE: func(cmd *cobra.Command, args []string) error {
		if sshKeyRemoveSource == "" {
			return errors.New("--source is required (e.g. --source gh:alice)")
		}
		n, err := removeImportedKeys(sshKeyRemoveSource)
		if err != nil {
			return err
		}
		fmt.Printf("✓ Removed %d key(s) imported from %s\n", n, sshKeyRemoveSource)
		return nil
	},
}

func init() {
	sshKeyImportCmd.Flags().BoolVar(&sshImportSync, "sync", false, "Also remove previously imported keys the user no longer publishes")
	sshKeyRemoveCmd.Flags().StringVar(&sshKeyRemoveSource, "source", "", "Source to remove: gh:<user>, gl:<user> or lp:<user>")
	sshKeyCmd.AddCommand(sshKeyImportCmd, sshKeyRemoveCmd)
}
