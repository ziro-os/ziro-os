package cmd

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	sdkapi "github.com/ziro-os/ziro-os/sdk/api"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// Scoped API tokens. Each token has a role and an optional expiry; only its SHA-256 is stored.
//
//	viewer    read-only: GET/HEAD on every endpoint
//	deployer  viewer + deploy: push source, redeploy and roll back deployments (for CI and agents)
//	operator  deployer + actions (POST/PUT/DELETE, e.g. service start/stop)
//	admin     everything (the pre-RBAC token in /etc/ziro/api.token counts as admin)
//
// A token may also be limited to scopes (path prefixes of the API), whatever its role: an AI
// agent's token gets --scope sandboxes and can do nothing but manage its own sandboxes.
//
// Token format: ziro_<id>_<secret>; the id locates the entry, the secret is compared in constant
// time against the stored hash.

var apiTokensFile = "/etc/ziro/api-tokens.json"

var apiRoleRank = map[string]int{"viewer": 1, "deployer": 2, "operator": 3, "admin": 4}

// apiScopes maps a scope to the API paths it opens.
var apiScopes = map[string]string{"sandboxes": "/api/v1/sandboxes"}

// scopeAllows reports whether a token with these scopes (none = unrestricted) may use path.
func scopeAllows(scopes []string, path string) bool {
	if len(scopes) == 0 {
		return true
	}
	for _, s := range scopes {
		if p := apiScopes[s]; p != "" && (path == p || strings.HasPrefix(path, p+"/")) {
			return true
		}
	}
	return false
}

type apiToken struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Role    string   `json:"role"`
	Hash    string   `json:"hash"`
	Created string   `json:"created"`
	Expires string   `json:"expires,omitempty"` // RFC3339; empty = never
	Scopes  []string `json:"scopes,omitempty"`  // empty = every route its role allows
}

var apiTokenRe = regexp.MustCompile(`^ziro_([0-9a-f]{8})_([0-9a-f]{48})$`)

func loadAPITokens() ([]apiToken, error) {
	b, err := os.ReadFile(apiTokensFile)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var ts []apiToken
	return ts, json.Unmarshal(b, &ts)
}

func saveAPITokens(ts []apiToken) error {
	sort.Slice(ts, func(i, j int) bool { return ts[i].Name < ts[j].Name })
	b, err := json.MarshalIndent(ts, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(apiTokensFile, b, 0600)
}

// apiIdentity resolves a bearer token to (name, role, scopes); ok is false for unknown, expired
// or malformed tokens. legacy is the pre-RBAC admin token ("" when none).
func apiIdentity(bearer, legacy string, now time.Time) (name, role string, scopes []string, ok bool) {
	if legacy != "" && subtle.ConstantTimeCompare([]byte(bearer), []byte(legacy)) == 1 {
		return "legacy-token", "admin", nil, true
	}
	m := apiTokenRe.FindStringSubmatch(bearer)
	if m == nil {
		return "", "", nil, false
	}
	ts, err := loadAPITokens()
	if err != nil {
		return "", "", nil, false
	}
	sum := sha256.Sum256([]byte(bearer))
	for _, t := range ts {
		if t.ID != m[1] {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sum[:])), []byte(t.Hash)) != 1 {
			return "", "", nil, false
		}
		if t.Expires != "" {
			if exp, err := time.Parse(time.RFC3339, t.Expires); err != nil || now.After(exp) {
				return "", "", nil, false
			}
		}
		return t.Name, t.Role, t.Scopes, apiRoleRank[t.Role] > 0
	}
	return "", "", nil, false
}

// createAPIToken issues a token (returned once; only its hash is stored).
func createAPIToken(name, role string, ttl time.Duration, scopes ...string) (string, apiToken, error) {
	if err := validName(name); err != nil {
		return "", apiToken{}, err
	}
	if apiRoleRank[role] == 0 {
		return "", apiToken{}, fmt.Errorf("role must be viewer, deployer, operator or admin")
	}
	if ttl < 0 || ttl > 5*365*24*time.Hour {
		return "", apiToken{}, fmt.Errorf("ttl must be between 0 (no expiry) and 5 years")
	}
	for _, s := range scopes {
		if apiScopes[s] == "" {
			return "", apiToken{}, fmt.Errorf("unknown scope %q (known: sandboxes)", s)
		}
	}
	ts, err := loadAPITokens()
	if err != nil {
		return "", apiToken{}, err
	}
	for _, t := range ts {
		if t.Name == name {
			return "", apiToken{}, fmt.Errorf("a token named %q exists; revoke it first", name)
		}
	}
	tok := "ziro_" + randomHex(4) + "_" + randomHex(24)
	sum := sha256.Sum256([]byte(tok))
	t := apiToken{ID: tok[5:13], Name: name, Role: role, Hash: hex.EncodeToString(sum[:]), Created: time.Now().UTC().Format(time.RFC3339), Scopes: scopes}
	if ttl > 0 {
		t.Expires = time.Now().Add(ttl).UTC().Format(time.RFC3339)
	}
	return tok, t, saveAPITokens(append(ts, t))
}

// revokeAPIToken removes a token by name or id; "legacy" removes the pre-RBAC admin token.
func revokeAPIToken(name string) error {
	if name == "legacy" {
		if err := os.Remove(apiTokenFile); err != nil {
			return errNotFound("no legacy token")
		}
		return writeFileAtomic(apiLegacyRevoked, []byte("revoked\n"), 0600)
	}
	ts, err := loadAPITokens()
	if err != nil {
		return err
	}
	kept := ts[:0]
	for _, t := range ts {
		if t.Name != name && t.ID != name {
			kept = append(kept, t)
		}
	}
	if len(kept) == len(ts) {
		return errNotFound(fmt.Sprintf("no token named %q", name))
	}
	return saveAPITokens(kept)
}

// apiTokenViews lists tokens without their hashes.
func apiTokenViews() []sdkapi.Token {
	ts, _ := loadAPITokens()
	view := []sdkapi.Token{}
	for _, t := range ts {
		view = append(view, sdkapi.Token{Name: t.Name, Role: t.Role, ID: t.ID, Created: t.Created, Expires: t.Expires, Scopes: t.Scopes})
	}
	return view
}

// ---- CLI ----

var (
	apiTokenRole   string
	apiTokenTTL    time.Duration
	apiTokenScopes []string
)

var apiTokenCreateCmd = &cobra.Command{
	Use:   "create <name>",
	Short: "Create a scoped API token, printed once",
	Example: `  ziroctl api token create ci --role operator
  ziroctl api token create grafana --role viewer --ttl 720h
  ziroctl api token create agent --role deployer --scope sandboxes`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		tok, t, err := createAPIToken(args[0], apiTokenRole, apiTokenTTL, apiTokenScopes...)
		if err != nil {
			return err
		}
		return printResult(map[string]any{"name": t.Name, "role": t.Role, "token": tok, "expires": t.Expires, "scopes": t.Scopes}, func() {
			fmt.Println(tok)
			fmt.Fprintf(os.Stderr, "✓ %s token %q created%s. Store it now: it is not shown again.\n", t.Role, t.Name,
				map[bool]string{true: ", expires " + t.Expires, false: ""}[t.Expires != ""])
		})
	},
}

var apiTokenLsCmd = &cobra.Command{
	Use: "ls", Short: "List API tokens without their secrets", Example: "  ziroctl api token ls",
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := loadAPITokens(); err != nil {
			return err
		}
		view := apiTokenViews()
		return printResult(view, func() {
			fmt.Printf("%-20s %-9s %-10s %-22s %s\n", "NAME", "ROLE", "ID", "CREATED", "EXPIRES")
			for _, v := range view {
				exp := v.Expires
				if exp == "" {
					exp = "never"
				}
				fmt.Printf("%-20s %-9s %-10s %-22s %s\n", v.Name, v.Role, v.ID, v.Created, exp)
			}
			if fileExists(apiTokenFile) {
				fmt.Printf("\nThe pre-RBAC token in %s is also accepted, as admin (ziroctl api token revoke legacy).\n", apiTokenFile)
			}
		})
	},
}

var apiTokenRevokeCmd = &cobra.Command{
	Use: "revoke <name>", Short: "Revoke an API token now", Example: "  ziroctl api token revoke ci", Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := revokeAPIToken(args[0]); err != nil {
			return err
		}
		fmt.Printf("✓ token %q revoked\n", args[0])
		return nil
	},
}

func init() {
	apiTokenCreateCmd.Flags().StringVar(&apiTokenRole, "role", "viewer", "viewer (read-only), deployer (+ deploy), operator (+ actions) or admin")
	apiTokenCreateCmd.Flags().DurationVar(&apiTokenTTL, "ttl", 90*24*time.Hour, "Lifetime (0 = never expires)")
	apiTokenCreateCmd.Flags().StringSliceVar(&apiTokenScopes, "scope", nil, "Limit the token to these API areas (sandboxes); default: everything its role allows")
	apiTokenCmd.AddCommand(apiTokenCreateCmd, apiTokenLsCmd, apiTokenRevokeCmd)
}

func trimBearer(h string) string { return strings.TrimPrefix(h, "Bearer ") }
