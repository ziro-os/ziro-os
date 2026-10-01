package cmd

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestParseImageRef(t *testing.T) {
	for in, want := range map[string]string{
		"nginx":             "docker.io/library/nginx :latest",
		"nginx:1.27-alpine": "docker.io/library/nginx :1.27-alpine",
		"acme/api:2":        "docker.io/acme/api :2",
		"ghcr.io/acme/api@sha256:" + strings.Repeat("a", 64): "ghcr.io/acme/api @sha256:" + strings.Repeat("a", 64),
		"localhost:5000/x/y:t":                               "localhost:5000/x/y :t",
	} {
		r, err := parseImageRef(in)
		got := r.name() + " "
		if r.Digest != "" {
			got += "@" + r.Digest
		} else {
			got += ":" + r.Tag
		}
		if err != nil || got != want {
			t.Errorf("%s: got %q (%v), want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"UPPER/case", "x@sha256:short", "a//b", ""} {
		if _, err := parseImageRef(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	p := ImagePolicy{AllowRegistries: []string{"ghcr.io/acme", "docker.io/library/"}}
	for img, ok := range map[string]bool{"ghcr.io/acme/api": true, "ghcr.io/acmeevil/api": false, "nginx": true, "evil/nginx": false} {
		r, _ := parseImageRef(img)
		if registryAllowed(p, r) != ok {
			t.Errorf("%s: allowed=%v", img, !ok)
		}
	}
	if err := checkImage(ImagePolicy{RequireSigned: true}, "ghcr.io/acme/api:1"); err == nil {
		t.Error("an unpinned image passed a signed-only policy")
	}
}

// fakeRegistry serves one repository with anonymous bearer-token auth, like Docker Hub/GHCR.
type fakeRegistry struct {
	manifest []byte
	sigs     map[string][]byte // sig tag -> manifest
	blobs    map[string][]byte
}

func (f *fakeRegistry) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			_ = json.NewEncoder(w).Encode(map[string]string{"token": "t0k"})
			return
		}
		if r.Header.Get("Authorization") != "Bearer t0k" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="http://`+r.Host+`/token",service="fake",scope="repository:library/app:pull"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		const base = "/v2/library/app/"
		// Serve only the fixture's own bytes, as an opaque download.
		serve := func(b []byte) {
			w.Header().Set("Content-Type", "application/octet-stream")
			http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(b))
		}
		switch p := strings.TrimPrefix(r.URL.Path, base); {
		case p == "manifests/v1":
			serve(f.manifest)
		case strings.HasPrefix(p, "manifests/") && f.sigs[strings.TrimPrefix(p, "manifests/")] != nil:
			serve(f.sigs[strings.TrimPrefix(p, "manifests/")])
		case strings.HasPrefix(p, "blobs/") && f.blobs[strings.TrimPrefix(p, "blobs/")] != nil:
			serve(f.blobs[strings.TrimPrefix(p, "blobs/")])
		default:
			http.NotFound(w, r)
		}
	})
}

func digestOf(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

// sign adds a cosign signature (classic layout) for imageDigest, signed by signer.
func (f *fakeRegistry) sign(imageDigest, claimed string, signer func([]byte) []byte) {
	payload := []byte(fmt.Sprintf(`{"critical":{"identity":{"docker-reference":"x"},"image":{"docker-manifest-digest":%q},"type":"cosign container image signature"},"optional":null}`, claimed))
	f.blobs[digestOf(payload)] = payload
	sigManifest, _ := json.Marshal(map[string]any{"schemaVersion": 2, "layers": []map[string]any{{
		"mediaType": "application/vnd.dev.cosign.simplesigning.v1+json", "digest": digestOf(payload),
		"annotations": map[string]string{"dev.cosignproject.cosign/signature": base64.StdEncoding.EncodeToString(signer(payload))},
	}}})
	f.sigs[strings.Replace(imageDigest, ":", "-", 1)+".sig"] = sigManifest
}

func pemPub(t *testing.T, pub any) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func TestImagePolicySignatures(t *testing.T) {
	old := registryScheme
	registryScheme = "http"
	defer func() { registryScheme = old }()

	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	edPub, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecSign := func(p []byte) []byte {
		h := sha256.Sum256(p)
		s, _ := ecdsa.SignASN1(rand.Reader, ecKey, h[:])
		return s
	}

	f := &fakeRegistry{manifest: []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}`),
		sigs: map[string][]byte{}, blobs: map[string][]byte{}}
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	image := host + "/library/app:v1"
	digest := digestOf(f.manifest)
	policy := ImagePolicy{AllowRegistries: []string{host + "/library"}, RequireSigned: true, CosignKeys: []string{pemPub(t, &ecKey.PublicKey)}}

	if _, err := enforceImagePolicy(policy, image); err == nil {
		t.Fatal("unsigned image accepted")
	}
	f.sign(digest, digest, ecSign)
	pinned, err := enforceImagePolicy(policy, image)
	if err != nil || pinned != host+"/library/app@"+digest {
		t.Fatalf("signed image: %q %v", pinned, err)
	}
	if err := checkImage(policy, pinned); err != nil {
		t.Fatalf("the pinned image must pass the leader's check: %v", err)
	}
	// Ed25519 keys work; a key the cluster does not trust does not.
	f.sign(digest, digest, func(p []byte) []byte { return ed25519.Sign(edPriv, p) })
	if _, err := enforceImagePolicy(ImagePolicy{RequireSigned: true, CosignKeys: []string{pemPub(t, edPub)}}, image); err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	if _, err := enforceImagePolicy(ImagePolicy{RequireSigned: true, CosignKeys: []string{pemPub(t, &otherKey.PublicKey)}}, image); err == nil {
		t.Fatal("a signature by an untrusted key was accepted")
	}
	// A valid signature over a different image digest (replay) is refused.
	f.sign(digest, "sha256:"+strings.Repeat("b", 64), ecSign)
	if _, err := enforceImagePolicy(policy, image); err == nil {
		t.Fatal("a signature for another digest was accepted")
	}
	// A payload whose bytes no longer match its digest is refused.
	f.sign(digest, digest, ecSign)
	for d := range f.blobs {
		f.blobs[d] = append([]byte(nil), f.blobs[d]...)
		f.blobs[d][10] ^= 1
	}
	if _, err := enforceImagePolicy(policy, image); err == nil {
		t.Fatal("tampered payload accepted")
	}
	// Registry not allowed: refused before any network call.
	if _, err := enforceImagePolicy(ImagePolicy{AllowRegistries: []string{"ghcr.io/acme"}}, "docker.io/library/nginx"); err == nil {
		t.Fatal("registry allowlist ignored")
	}
}

func TestLeaderRejectsUnpinnedImage(t *testing.T) {
	st := &ClusterState{NodeTokens: map[string]string{}, History: map[string][]ClusteredApp{}}
	ms := newTestGroup(t, 1, st)
	lead := ms[0].rs
	waitFor(t, "leader", lead.isLeader)
	if err := lead.mutate(func(s *ClusterState) error {
		s.ImagePolicy = ImagePolicy{RequireSigned: true, CosignKeys: []string{"k"}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	cur, ver, _ := lead.snapshot()
	cur.Apps = append(cur.Apps, ClusteredApp{Name: "web", Image: "nginx:latest", Replicas: 1})
	if err := lead.propose(ver, cur); err == nil {
		t.Fatal("the leader accepted an unpinned image under a signed-only policy")
	}
	cur.Apps[0].Image = "nginx@sha256:" + strings.Repeat("c", 64)
	if err := lead.propose(ver, cur); err != nil && !errors.Is(err, errConflict) {
		t.Fatalf("pinned image: %v", err)
	}
}
