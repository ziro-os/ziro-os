package cmd

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// Image policy: which registries apps may come from, and whether images must carry a cosign
// signature by one of the cluster's keys. Verification happens once, at deploy time: the tag is
// resolved to a digest, the signature for that digest is checked, and the app is pinned to
// image@sha256:<digest>, so every node pulls exactly the verified content (no tag drift, no gap
// between verifying and pulling). The leader re-checks the network-free part (registry
// allowlist, digest pin) on every change.
//
// Signatures: cosign key-based signatures in the classic layout (tag sha256-<digest>.sig,
// simple-signing payload, signature annotation), with ECDSA, Ed25519 or RSA public keys.
// ponytail: keyless (Fulcio/Rekor) and the OCI-referrers bundle format are not verified; add
// sigstore-go if those are needed.

type ImagePolicy struct {
	AllowRegistries []string `json:"allow_registries,omitempty"` // repository prefixes, e.g. ghcr.io/acme
	RequireSigned   bool     `json:"require_signed,omitempty"`
	CosignKeys      []string `json:"cosign_keys,omitempty"` // PEM public keys; any one may sign
}

func (p ImagePolicy) empty() bool { return len(p.AllowRegistries) == 0 && !p.RequireSigned }

type imageRef struct {
	Registry, Repo, Tag, Digest string
}

func (r imageRef) name() string { return r.Registry + "/" + r.Repo }

// apiHost is the registry API endpoint (Docker Hub's API lives on another host).
func (r imageRef) apiHost() string {
	if r.Registry == "docker.io" {
		return "registry-1.docker.io"
	}
	return r.Registry
}

var (
	digestRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	repoRe   = regexp.MustCompile(`^[a-z0-9]+([._-][a-z0-9]+)*(/[a-z0-9]+([._-][a-z0-9]+)*)*$`)
)

// parseImageRef normalizes nginx, nginx:1.27, ghcr.io/acme/api@sha256:..., localhost:5000/x.
func parseImageRef(s string) (imageRef, error) {
	var r imageRef
	if i := strings.Index(s, "@"); i >= 0 {
		r.Digest, s = s[i+1:], s[:i]
		if !digestRe.MatchString(r.Digest) {
			return r, fmt.Errorf("invalid digest %q", r.Digest)
		}
	}
	if i := strings.LastIndex(s, ":"); i > strings.LastIndex(s, "/") {
		r.Tag, s = s[i+1:], s[:i]
	}
	parts := strings.SplitN(s, "/", 2)
	if len(parts) == 2 && (strings.ContainsAny(parts[0], ".:") || parts[0] == "localhost") {
		r.Registry, r.Repo = parts[0], parts[1]
	} else {
		r.Registry, r.Repo = "docker.io", s
		if !strings.Contains(s, "/") {
			r.Repo = "library/" + s
		}
	}
	if !repoRe.MatchString(r.Repo) {
		return r, fmt.Errorf("invalid repository %q", r.Repo)
	}
	if r.Tag == "" && r.Digest == "" {
		r.Tag = "latest"
	}
	return r, nil
}

// registryAllowed matches the repository against prefixes on path boundaries.
func registryAllowed(p ImagePolicy, r imageRef) bool {
	if len(p.AllowRegistries) == 0 {
		return true
	}
	n := r.name()
	for _, a := range p.AllowRegistries {
		a = strings.TrimSuffix(a, "/")
		if n == a || strings.HasPrefix(n, a+"/") {
			return true
		}
	}
	return false
}

// checkImage is the network-free check the leader applies to every changed app.
func checkImage(p ImagePolicy, image string) error {
	if p.empty() {
		return nil
	}
	r, err := parseImageRef(image)
	if err != nil {
		return err
	}
	if !registryAllowed(p, r) {
		return fmt.Errorf("image %s: registry not allowed by the cluster image policy (%s)", r.name(), strings.Join(p.AllowRegistries, ", "))
	}
	if p.RequireSigned && r.Digest == "" {
		return fmt.Errorf("image %s: the cluster requires signed images pinned by digest (deploy with ziroctl, which verifies and pins)", image)
	}
	return nil
}

// enforceImagePolicy checks the registry and, when signatures are required, verifies the
// signature and returns the image pinned to the verified digest.
func enforceImagePolicy(p ImagePolicy, image string) (string, error) {
	if p.empty() {
		return image, nil
	}
	r, err := parseImageRef(image)
	if err != nil {
		return "", err
	}
	if !registryAllowed(p, r) {
		return "", checkImage(p, image)
	}
	if !p.RequireSigned {
		return image, nil
	}
	reg := newRegistryClient(r)
	digest := r.Digest
	if digest == "" {
		if digest, err = reg.resolve(r.Tag); err != nil {
			return "", fmt.Errorf("resolve %s:%s: %w", r.name(), r.Tag, err)
		}
	}
	if err := reg.verifyCosign(digest, p.CosignKeys); err != nil {
		return "", fmt.Errorf("image %s@%s: %w", r.name(), digest, err)
	}
	return r.name() + "@" + digest, nil
}

// ---- minimal OCI registry client (anonymous pull, bearer token challenge) ----

type registryClient struct {
	ref    imageRef
	base   string // https://host/v2/<repo>
	client *http.Client
	token  string
}

var registryScheme = "https" // tests use a plain-HTTP registry

func newRegistryClient(r imageRef) *registryClient {
	return &registryClient{ref: r, base: registryScheme + "://" + r.apiHost() + "/v2/" + r.Repo,
		client: &http.Client{Timeout: 30 * time.Second}}
}

const manifestAccept = "application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, " +
	"application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json"

var bearerParamRe = regexp.MustCompile(`(\w+)="([^"]*)"`)

func (c *registryClient) get(path, accept string, limit int64) ([]byte, http.Header, error) {
	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequest(http.MethodGet, c.base+path, nil)
		if err != nil {
			return nil, nil, err
		}
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		if c.token != "" {
			req.Header.Set("Authorization", "Bearer "+c.token)
		}
		resp, err := c.client.Do(req)
		if err != nil {
			return nil, nil, err
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
		resp.Body.Close()
		if err != nil {
			return nil, nil, err
		}
		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 && c.token == "" {
			if err := c.fetchToken(resp.Header.Get("WWW-Authenticate")); err != nil {
				return nil, nil, err
			}
			continue
		}
		if resp.StatusCode != http.StatusOK {
			return nil, nil, fmt.Errorf("%s: HTTP %d", path, resp.StatusCode)
		}
		if int64(len(body)) > limit {
			return nil, nil, fmt.Errorf("%s: response too large", path)
		}
		return body, resp.Header, nil
	}
	return nil, nil, errors.New("registry authorization failed")
}

// fetchToken follows the Bearer challenge for anonymous pull access.
func (c *registryClient) fetchToken(challenge string) error {
	if !strings.HasPrefix(challenge, "Bearer ") {
		return errors.New("registry requires credentials (only anonymous pulls are supported)")
	}
	params := map[string]string{}
	for _, m := range bearerParamRe.FindAllStringSubmatch(challenge, -1) {
		params[m[1]] = m[2]
	}
	realm, err := url.Parse(params["realm"])
	if err != nil || (realm.Scheme != "https" && registryScheme == "https") {
		return errors.New("registry token realm must be https")
	}
	q := realm.Query()
	for _, k := range []string{"service", "scope"} {
		if params[k] != "" {
			q.Set(k, params[k])
		}
	}
	realm.RawQuery = q.Encode()
	resp, err := c.client.Get(realm.String())
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var t struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&t); err != nil || resp.StatusCode != http.StatusOK {
		return fmt.Errorf("registry token: HTTP %d", resp.StatusCode)
	}
	c.token = t.Token
	if c.token == "" {
		c.token = t.AccessToken
	}
	return nil
}

// resolve returns the digest a tag points to, computed from the manifest bytes themselves.
func (c *registryClient) resolve(tag string) (string, error) {
	body, _, err := c.get("/manifests/"+url.PathEscape(tag), manifestAccept, 4<<20)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

type cosignPayload struct {
	Critical struct {
		Image struct {
			DockerManifestDigest string `json:"docker-manifest-digest"`
		} `json:"image"`
		Type string `json:"type"`
	} `json:"critical"`
}

// verifyCosign accepts the image when any signature in its .sig artifact is valid under one of
// keys and its payload names exactly this digest.
func (c *registryClient) verifyCosign(digest string, keys []string) error {
	sigTag := strings.Replace(digest, ":", "-", 1) + ".sig"
	body, _, err := c.get("/manifests/"+sigTag, "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json", 4<<20)
	if err != nil {
		return fmt.Errorf("no cosign signature found (%v)", err)
	}
	var m struct {
		Layers []struct {
			Digest      string            `json:"digest"`
			Annotations map[string]string `json:"annotations"`
		} `json:"layers"`
	}
	if err := json.Unmarshal(body, &m); err != nil {
		return fmt.Errorf("signature manifest: %w", err)
	}
	for _, l := range m.Layers {
		sig, err := base64.StdEncoding.DecodeString(l.Annotations["dev.cosignproject.cosign/signature"])
		if err != nil || len(sig) == 0 || !digestRe.MatchString(l.Digest) {
			continue
		}
		payload, _, err := c.get("/blobs/"+l.Digest, "", 64<<10)
		if err != nil {
			continue
		}
		if sum := sha256.Sum256(payload); "sha256:"+hex.EncodeToString(sum[:]) != l.Digest {
			continue // content does not match its address
		}
		var p cosignPayload
		if json.Unmarshal(payload, &p) != nil || p.Critical.Image.DockerManifestDigest != digest ||
			p.Critical.Type != "cosign container image signature" {
			continue
		}
		for _, k := range keys {
			if verifySignature(k, payload, sig) == nil {
				return nil
			}
		}
	}
	return errors.New("no valid cosign signature by a trusted key")
}

func parsePublicKey(pemKey string) (crypto.PublicKey, error) {
	b, _ := pem.Decode([]byte(pemKey))
	if b == nil {
		return nil, errors.New("no PEM public key")
	}
	return x509.ParsePKIXPublicKey(b.Bytes)
}

func verifySignature(pemKey string, payload, sig []byte) error {
	pub, err := parsePublicKey(pemKey)
	if err != nil {
		return err
	}
	h := sha256.Sum256(payload)
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if ecdsa.VerifyASN1(k, h[:], sig) {
			return nil
		}
	case ed25519.PublicKey:
		if ed25519.Verify(k, payload, sig) {
			return nil
		}
	case *rsa.PublicKey:
		if rsa.VerifyPKCS1v15(k, crypto.SHA256, h[:], sig) == nil {
			return nil
		}
	default:
		return errors.New("unsupported key type")
	}
	return errors.New("bad signature")
}

// ---- CLI ----

var (
	imgAllow  []string
	imgSigned bool
	imgKeys   []string
	imgClear  bool
)

var clusterPolicyImagesCmd = &cobra.Command{
	Use:   "images",
	Short: "Show or set which images apps may run",
	Example: `  ziroctl cluster policy images
  ziroctl cluster policy images --allow-registry ghcr.io/acme --require-signed --cosign-key cosign.pub
  ziroctl cluster policy images --clear`,
	Long: `  ziroctl cluster policy images --allow-registry ghcr.io/acme --allow-registry docker.io/library
  ziroctl cluster policy images --require-signed --cosign-key cosign.pub
  ziroctl cluster policy images --clear

With --require-signed, each deploy resolves the tag, verifies a cosign signature by one of the
keys, and pins the app to image@sha256:<digest>. Running apps are not touched; they are checked
on their next change.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := requireMaster(); err != nil {
			return err
		}
		f := cmd.Flags()
		if !f.Changed("allow-registry") && !f.Changed("require-signed") && !f.Changed("cosign-key") && !imgClear {
			st, err := readState()
			if err != nil {
				return err
			}
			return printResult(st.ImagePolicy, func() {
				p := st.ImagePolicy
				if p.empty() {
					fmt.Println("Image policy: none (any registry, unsigned images allowed)")
					return
				}
				fmt.Printf("Allowed registries: %s\n", map[bool]string{true: "any", false: strings.Join(p.AllowRegistries, ", ")}[len(p.AllowRegistries) == 0])
				fmt.Printf("Signatures:         %s\n", map[bool]string{true: fmt.Sprintf("required (cosign, %d key(s))", len(p.CosignKeys)), false: "not required"}[p.RequireSigned])
			})
		}
		var keys []string
		for _, path := range imgKeys {
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if _, err := parsePublicKey(string(b)); err != nil {
				return fmt.Errorf("%s: %w", path, err)
			}
			keys = append(keys, string(b))
		}
		for _, a := range imgAllow {
			if _, err := parseImageRef(strings.TrimSuffix(a, "/") + "/x"); err != nil || strings.ContainsAny(a, "@ ") {
				return fmt.Errorf("invalid --allow-registry %q (want e.g. ghcr.io/acme or docker.io/library)", a)
			}
		}
		return withState(func(st *ClusterState) error {
			p := st.ImagePolicy
			if imgClear {
				p = ImagePolicy{}
			}
			if f.Changed("allow-registry") {
				p.AllowRegistries = imgAllow
			}
			if f.Changed("cosign-key") {
				p.CosignKeys = keys
			}
			if f.Changed("require-signed") {
				p.RequireSigned = imgSigned
			}
			if p.RequireSigned && len(p.CosignKeys) == 0 {
				return fmt.Errorf("--require-signed needs at least one --cosign-key")
			}
			st.ImagePolicy = p
			var bad []string
			for _, a := range st.Apps {
				if checkImage(p, a.Image) != nil {
					bad = append(bad, a.Name)
				}
			}
			fmt.Println("✓ image policy saved")
			if len(bad) > 0 {
				fmt.Printf("  running apps not yet compliant (checked on their next deploy): %s\n", strings.Join(bad, ", "))
			}
			return nil
		})
	},
}

func init() {
	f := clusterPolicyImagesCmd.Flags()
	f.StringSliceVar(&imgAllow, "allow-registry", nil, "Allowed repository prefix (repeatable; e.g. ghcr.io/acme, docker.io/library)")
	f.BoolVar(&imgSigned, "require-signed", false, "Require a cosign signature by one of the keys, and pin to the digest")
	f.StringSliceVar(&imgKeys, "cosign-key", nil, "cosign public key file (PEM; repeatable)")
	f.BoolVar(&imgClear, "clear", false, "Remove the image policy")
	clusterPolicyCmd.AddCommand(clusterPolicyImagesCmd)
}
