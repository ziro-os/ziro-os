package cmd

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Password rotation (ziroctl pg rotate-password). The master makes the new password and sends the
// primary only its SCRAM-SHA-256 verifier (ALTER ROLE ... PASSWORD 'SCRAM-SHA-256$...'), so the
// plaintext never appears in an order, a process list or a log. Once the primary has it, the cluster
// secret is updated and every member restarts on it, one at a time with the primary last (pgMayRoll),
// so replication and the entry script (which sets the passwords on every start) use the new one.
// Sessions already open stay open.

const opPassword = "password" // ALTER ROLE <role> PASSWORD <SCRAM verifier>; argument "role:verifier"

var pgVerifierRe = regexp.MustCompile(`^SCRAM-SHA-256\$4096:[A-Za-z0-9+/]+={0,2}\$[A-Za-z0-9+/]+={0,2}:[A-Za-z0-9+/]+={0,2}$`)

// PGRotation is a password change in progress.
type PGRotation struct {
	Role string    `json:"role"` // the database role: the application user, replicator or postgres
	Key  string    `json:"key"`  // its key in the cluster secret
	At   time.Time `json:"at"`
}

// pgPasswordKeys maps the roles that can be rotated to their secret keys.
func pgPasswordKeys(c *PGCluster) map[string]string {
	return map[string]string{c.User: "POSTGRES_PASSWORD", "replicator": "PG_REPL_PASSWORD", "postgres": "PG_SUPERUSER_PASSWORD"}
}

// scramVerifier is the SCRAM-SHA-256 verifier Postgres stores for a password (RFC 5802, 4096 rounds).
func scramVerifier(password string, salt []byte) (string, error) {
	salted, err := pbkdf2.Key(sha256.New, password, salt, 4096, 32)
	if err != nil {
		return "", err
	}
	mac := func(key []byte, msg string) []byte {
		h := hmac.New(sha256.New, key)
		h.Write([]byte(msg))
		return h.Sum(nil)
	}
	stored := sha256.Sum256(mac(salted, "Client Key"))
	b := base64.StdEncoding.EncodeToString
	return fmt.Sprintf("SCRAM-SHA-256$4096:%s$%s:%s", b(salt), b(stored[:]), b(mac(salted, "Server Key"))), nil
}

func validPasswordArg(arg string) error {
	role, verifier, ok := strings.Cut(arg, ":")
	if !ok || !pgIdentRe.MatchString(role) || !pgVerifierRe.MatchString(verifier) {
		return fmt.Errorf("invalid password change")
	}
	return nil
}

// pgRequestRotation starts a password change for role ("" = the application user).
func pgRequestRotation(st *ClusterState, name, role string, now time.Time) error {
	c, err := pgCluster(st, name)
	if err != nil {
		return err
	}
	if role == "" {
		role = c.User
	}
	key, ok := pgPasswordKeys(c)[role]
	if !ok {
		return fmt.Errorf("role %q: rotate %s, replicator or postgres", role, c.User)
	}
	if c.Rotation != nil {
		return fmt.Errorf("a password change for %s is still in progress", c.Rotation.Role)
	}
	next, err := genSecret("alnum:32")
	if err != nil {
		return err
	}
	if st.Secrets[c.caSecretName()] == nil {
		st.Secrets[c.caSecretName()] = map[string]string{}
	}
	st.Secrets[c.caSecretName()]["NEXT_"+key] = next // not delivered to any container
	c.Rotation = &PGRotation{Role: role, Key: key, At: now}
	return nil
}

// pgRotationPass sends the primary its order, and once it has the password, switches the secret and
// lets the members restart on it.
func pgRotationPass(st *ClusterState, c *PGCluster, now time.Time) {
	r := c.Rotation
	if r == nil {
		return
	}
	g := c.group(c.entryGroup())
	next := st.Secrets[c.caSecretName()]["NEXT_"+r.Key]
	if next == "" || now.Sub(r.At) > 10*time.Minute {
		c.Rotation = nil
		if g != nil {
			g.alert(now, "medium", "the password change for %s did not complete; the old password stays", r.Role)
		}
		return
	}
	// Every group's primary gets the new password (Citus workers have the same roles).
	for gi := range c.Groups {
		g := &c.Groups[gi]
		p := g.primary()
		if p == nil || !p.fresh(now) {
			return
		}
		if g.Notes != nil && !g.Notes["rotated-"+r.Key].Before(r.At) {
			continue // done in this group
		}
		if p.Cmd == nil {
			salt := make([]byte, 16)
			if _, err := rand.Read(salt); err != nil {
				return
			}
			if v, err := scramVerifier(next, salt); err == nil {
				p.issue(opPassword, r.Role+":"+v, g.Epoch, now)
			}
		}
		return // one group at a time; pgSettle marks it done
	}
	st.Secrets[c.secretName()][r.Key] = next
	delete(st.Secrets[c.caSecretName()], "NEXT_"+r.Key)
	c.SecretEpoch++
	c.Rotation = nil
	if g != nil {
		g.note(now, "the password of %s changed; the members restart on it one at a time", r.Role)
	}
}
