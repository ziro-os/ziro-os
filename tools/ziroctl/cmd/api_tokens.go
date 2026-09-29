package cmd

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
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
//	operator  viewer + actions (POST/PUT/DELETE, e.g. service start/stop)
//	admin     everything (the pre-RBAC token in /etc/ziro/api.token counts as admin)
//
// Token format: ziro_<id>_<secret>; the id locates the entry, the secret is compared in constant
// time against the stored hash.

var apiTokensFile = "/etc/ziro/api-tokens.json"

var apiRoleRank = map[string]int{"viewer": 1, "operator": 2, "admin": 3}

type apiToken struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Role    string `json:"role"`
	Hash    string `json:"hash"`
	Created string `json:"created"`
	Expires string `json:"expires,omitempty"` // RFC3339; empty = never
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

// apiIdentity resolves a bearer token to (name, role); ok is false for unknown, expired or
// malformed tokens. legacy is the pre-RBAC admin token ("" when none).
func apiIdentity(bearer, legacy string, now time.Time) (name, role string, ok bool) {
	if legacy != "" && subtle.ConstantTimeCompare([]byte(bearer), []byte(legacy)) == 1 {
		return "legacy-token", "admin", true
	}
	m := apiTokenRe.FindStringSubmatch(bearer)
	if m == nil {
		return "", "", false
	}
	ts, err := loadAPITokens()
	if err != nil {
		return "", "", false
	}
	sum := sha256.Sum256([]byte(bearer))
	for _, t := range ts {
		if t.ID != m[1] {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sum[:])), []byte(t.Hash)) != 1 {
			return "", "", false
		}
		if t.Expires != "" {
			if exp, err := time.Parse(time.RFC3339, t.Expires); err != nil || now.After(exp) {
				return "", "", false
			}
		}
		return t.Name, t.Role, apiRoleRank[t.Role] > 0
	}
	return "", "", false
}

// apiAllowed: reads need viewer, anything that changes state needs operator.
func apiAllowed(role, method string) bool {
	need := "operator"
	if method == http.MethodGet || method == http.MethodHead {
		need = "viewer"
	}
	return apiRoleRank[role] >= apiRoleRank[need]
}

// ---- CLI ----

var (
	apiTokenRole string
	apiTokenTTL  time.Duration
)

var apiTokenCreateCmd = &cobra.Command{
	Use:   "create <name>",
	Short: "Create a scoped API token (printed once; only its hash is stored)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := validName(args[0]); err != nil {
			return err
		}
		if apiRoleRank[apiTokenRole] == 0 {
			return fmt.Errorf("--role must be viewer, operator or admin")
		}
		ts, err := loadAPITokens()
		if err != nil {
			return err
		}
		for _, t := range ts {
			if t.Name == args[0] {
				return fmt.Errorf("a token named %q exists; revoke it first", args[0])
			}
		}
		tok := "ziro_" + randomHex(4) + "_" + randomHex(24)
		sum := sha256.Sum256([]byte(tok))
		t := apiToken{ID: tok[5:13], Name: args[0], Role: apiTokenRole, Hash: hex.EncodeToString(sum[:]),
			Created: time.Now().UTC().Format(time.RFC3339)}
		if apiTokenTTL > 0 {
			t.Expires = time.Now().Add(apiTokenTTL).UTC().Format(time.RFC3339)
		}
		if err := saveAPITokens(append(ts, t)); err != nil {
			return err
		}
		return printResult(map[string]string{"name": t.Name, "role": t.Role, "token": tok, "expires": t.Expires}, func() {
			fmt.Println(tok)
			fmt.Fprintf(os.Stderr, "✓ %s token %q created%s. Store it now: it is not shown again.\n", t.Role, t.Name,
				map[bool]string{true: ", expires " + t.Expires, false: ""}[t.Expires != ""])
		})
	},
}

var apiTokenLsCmd = &cobra.Command{
	Use: "ls", Short: "List API tokens (never the tokens themselves)",
	RunE: func(cmd *cobra.Command, args []string) error {
		ts, err := loadAPITokens()
		if err != nil {
			return err
		}
		view := []map[string]string{}
		for _, t := range ts {
			view = append(view, map[string]string{"name": t.Name, "role": t.Role, "id": t.ID, "created": t.Created, "expires": t.Expires})
		}
		return printResult(view, func() {
			fmt.Printf("%-20s %-9s %-10s %-22s %s\n", "NAME", "ROLE", "ID", "CREATED", "EXPIRES")
			for _, v := range view {
				exp := v["expires"]
				if exp == "" {
					exp = "never"
				}
				fmt.Printf("%-20s %-9s %-10s %-22s %s\n", v["name"], v["role"], v["id"], v["created"], exp)
			}
			if fileExists(apiTokenFile) {
				fmt.Printf("\nThe pre-RBAC token in %s is also accepted, as admin (remove the file to disable it).\n", apiTokenFile)
			}
		})
	},
}

var apiTokenRevokeCmd = &cobra.Command{
	Use: "revoke <name>", Short: "Revoke an API token immediately", Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ts, err := loadAPITokens()
		if err != nil {
			return err
		}
		kept := ts[:0]
		for _, t := range ts {
			if t.Name != args[0] && t.ID != args[0] {
				kept = append(kept, t)
			}
		}
		if len(kept) == len(ts) {
			return fmt.Errorf("no token named %q", args[0])
		}
		if err := saveAPITokens(kept); err != nil {
			return err
		}
		fmt.Printf("✓ token %q revoked\n", args[0])
		return nil
	},
}

func init() {
	apiTokenCreateCmd.Flags().StringVar(&apiTokenRole, "role", "viewer", "viewer (read-only), operator (+ actions) or admin")
	apiTokenCreateCmd.Flags().DurationVar(&apiTokenTTL, "ttl", 90*24*time.Hour, "Lifetime (0 = never expires)")
	apiTokenCmd.AddCommand(apiTokenCreateCmd, apiTokenLsCmd, apiTokenRevokeCmd)
}

func trimBearer(h string) string { return strings.TrimPrefix(h, "Bearer ") }
