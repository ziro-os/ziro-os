package cmd

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	sdkapi "github.com/ziro-os/ziro-os/sdk/api"
	"github.com/ziro-os/ziro-os/sdk/schema"
)

// Port previews: a sandbox port published at https://<port>-<id>.<gateway domain>. The gateway
// terminates TLS (ACME, the domain's wildcard certificate or its own CA) and has one exact route
// per preview to ziro-sandboxd's preview proxy on loopback. The proxy checks the preview's token
// (private previews), strips it, and proxies to the sandbox's own address (WebSockets too).
//
// Tokens are HMACs, not stored: hmac(key, id|port|created|expiry). Deleting and re-publishing a
// preview (a new "created") revokes every token it had; deleting the sandbox revokes them all.
//
// Known limitation: single host; in a cluster the gateway runs elsewhere (phase 8 routes over the mesh).

const (
	previewCookie = "ziro_preview"
	previewHeader = "X-Ziro-Preview-Token"
	previewQuery  = "ziro_token"
)

var (
	previewHostRe  = regexp.MustCompile(`^([0-9]{1,5})-([a-z2-7]{12})\.`)
	previewKeyFile = func() string { return filepath.Join(sandboxRoot, "preview.key") }
	// The gateway, behind seams for tests.
	previewDomain   = func() schema.GatewayDomain { return gatewayDomain() }
	previewPutRoute = func(r GatewayRoute) error {
		s, err := gatewayStore()
		if err != nil {
			return err
		}
		if s.name() == "cluster" {
			return errors.New("previews on a cluster member are not supported yet")
		}
		_, err = putRoute(s, r)
		return err
	}
	previewDelRoute = func(name string) error {
		s, err := gatewayStore()
		if err != nil {
			return err
		}
		return deleteRoute(s, name)
	}
)

func loadPreviewKey() ([]byte, error) {
	if b, err := os.ReadFile(previewKeyFile()); err == nil && len(b) == 32 {
		return b, nil
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, writeFileAtomic(previewKeyFile(), b, 0600)
}

func previewRoute(id string, port int) string { return fmt.Sprintf("sbx-%s-%d", id, port) }

func previewMAC(key []byte, id string, port int, created time.Time, exp int64) []byte {
	h := hmac.New(sha256.New, key)
	fmt.Fprintf(h, "%s|%d|%d|%d", id, port, created.UnixNano(), exp)
	return h.Sum(nil)[:16]
}

// previewToken: base64url(expiry seconds (8 bytes) || mac (16 bytes)).
func previewToken(key []byte, id string, pv sdkapi.SandboxPreview, exp time.Time) string {
	b := make([]byte, 8, 24)
	binary.BigEndian.PutUint64(b, uint64(exp.Unix()))
	return base64.RawURLEncoding.EncodeToString(append(b, previewMAC(key, id, pv.Port, pv.Created, exp.Unix())...))
}

func previewTokenOK(key []byte, id string, pv sdkapi.SandboxPreview, tok string, now time.Time) (time.Time, bool) {
	b, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil || len(b) != 24 {
		return time.Time{}, false
	}
	exp := int64(binary.BigEndian.Uint64(b[:8]))
	if now.Unix() >= exp || !hmac.Equal(b[8:], previewMAC(key, id, pv.Port, pv.Created, exp)) {
		return time.Time{}, false
	}
	return time.Unix(exp, 0), true
}

// expose publishes a port of a sandbox (or, for a port already published the same way, mints
// another token for it).
func (m *sandboxManager) expose(id string, c sandboxCaller, req sdkapi.SandboxPreviewRequest) (sdkapi.SandboxPreview, error) {
	sb, err := m.st.get(id, c)
	if err != nil {
		return sdkapi.SandboxPreview{}, err
	}
	if req.Port < 1 || req.Port > 65535 {
		return sdkapi.SandboxPreview{}, errors.New("port must be 1-65535")
	}
	if sb.IP == "" {
		return sdkapi.SandboxPreview{}, errors.New("the sandbox has no network: create it with --net or --allow to publish ports")
	}
	if m.previewKey == nil {
		return sdkapi.SandboxPreview{}, errors.New("previews are off (preview_port in " + sandboxConfigFile + ")")
	}
	dom := previewDomain()
	if mc := m.meshCfg(); mc != nil { // a cluster node: the master's gateway domain and routes
		dom = schema.GatewayDomain{Name: mc.Domain}
	}
	if dom.Name == "" {
		return sdkapi.SandboxPreview{}, errors.New("previews need a gateway domain: ziroctl gateway domain set <domain>")
	}
	exp := sb.Expires
	if req.TTL != "" {
		d, err := time.ParseDuration(req.TTL)
		if err != nil || d < time.Minute {
			return sdkapi.SandboxPreview{}, errors.New("ttl must be at least 1m")
		}
		if t := m.now().Add(d); t.Before(exp) {
			exp = t
		}
	}
	var pv sdkapi.SandboxPreview
	found := false
	for _, p := range sb.Previews {
		if p.Port == req.Port && p.Public == req.Public {
			pv, found = p, true
		}
	}
	if !found {
		if len(sb.Previews) >= 16 {
			return pv, errors.New("a sandbox publishes at most 16 ports")
		}
		host := fmt.Sprintf("%d-%s.%s", req.Port, id, dom.Name)
		pv = sdkapi.SandboxPreview{Port: req.Port, Public: req.Public, URL: "https://" + host + "/", Created: m.now().UTC()}
		r := GatewayRoute{Name: previewRoute(id, req.Port), Hosts: []string{host}, TLS: dom.TLS(),
			To: []GatewayUpstream{{Address: net.JoinHostPort("127.0.0.1", strconv.Itoa(m.previewPort))}}, MaxBodyMB: 100, Timeout: "5m"}
		if !clusterPreviews.Load() { // on a cluster the master adds the route
			if err := previewPutRoute(r); err != nil {
				return pv, fmt.Errorf("gateway route: %w", err)
			}
		}
		err := m.st.update(id, func(x *sdkapi.Sandbox) {
			kept := x.Previews[:0:0]
			for _, p := range x.Previews {
				if p.Port != req.Port {
					kept = append(kept, p)
				}
			}
			x.Previews = append(kept, pv)
		})
		if err != nil {
			return pv, err
		}
	}
	if !pv.Public {
		pv.Token = previewToken(m.previewKey, id, pv, exp)
		pv.TokenURL = pv.URL + "?" + previewQuery + "=" + pv.Token
	}
	return pv, nil
}

func (m *sandboxManager) unexpose(id string, c sandboxCaller, port int) error {
	sb, err := m.st.get(id, c)
	if err != nil {
		return err
	}
	found := false
	for _, p := range sb.Previews {
		found = found || p.Port == port
	}
	if !found {
		return errNotFound(fmt.Sprintf("port %d isn't published", port))
	}
	if !clusterPreviews.Load() {
		if err := previewDelRoute(previewRoute(id, port)); err != nil {
			return err
		}
	}
	return m.st.update(id, func(x *sdkapi.Sandbox) {
		kept := x.Previews[:0:0]
		for _, p := range x.Previews {
			if p.Port != port {
				kept = append(kept, p)
			}
		}
		x.Previews = kept
	})
}

// dropPreviews removes the gateway routes of a deleted sandbox.
func dropPreviews(sb sdkapi.Sandbox) {
	if clusterPreviews.Load() { // the master drops them with the sandbox's directory entry
		return
	}
	for _, p := range sb.Previews {
		if err := previewDelRoute(previewRoute(sb.ID, p.Port)); err != nil {
			fmt.Printf("[sandboxd] %s: remove preview route %d: %v\n", sb.ID, p.Port, err)
		}
	}
}

// previewHandler is the proxy the gateway's preview routes point to.
func (m *sandboxManager) previewHandler() http.Handler {
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(&url.URL{Scheme: "http", Host: pr.In.Context().Value(previewTarget{}).(string)})
			pr.Out.Host = pr.In.Host
			pr.Out.Header["X-Forwarded-For"] = pr.In.Header["X-Forwarded-For"] // the gateway set them
			pr.Out.Header.Del(previewHeader)
			stripPreviewCookie(pr.Out)
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			http.Error(w, "nothing answers on this port of the sandbox (listen on 0.0.0.0)", http.StatusBadGateway)
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mm := previewHostRe.FindStringSubmatch(strings.ToLower(r.Host))
		if mm == nil {
			http.NotFound(w, r)
			return
		}
		port, _ := strconv.Atoi(mm[1])
		id := mm[2]
		sb, err := m.st.get(id, sandboxCaller{Role: "admin"})
		var pv *sdkapi.SandboxPreview
		for i := range sb.Previews {
			if sb.Previews[i].Port == port {
				pv = &sb.Previews[i]
			}
		}
		if err != nil || pv == nil {
			http.NotFound(w, r)
			return
		}
		if sb.State != "running" || sb.IP == "" {
			http.Error(w, "the sandbox is "+sb.State, http.StatusServiceUnavailable)
			return
		}
		if !pv.Public {
			now := m.now()
			if tok := r.URL.Query().Get(previewQuery); tok != "" {
				// A link with the token: trade it for a cookie and drop it from the address bar.
				exp, ok := previewTokenOK(m.previewKey, id, *pv, tok, now)
				if !ok {
					http.Error(w, "invalid or expired preview token", http.StatusUnauthorized)
					return
				}
				http.SetCookie(w, &http.Cookie{Name: previewCookie, Value: tok, Path: "/", Expires: exp,
					Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
				q := r.URL.Query()
				q.Del(previewQuery)
				u := *r.URL
				u.RawQuery = q.Encode()
				http.Redirect(w, r, u.RequestURI(), http.StatusSeeOther)
				return
			}
			tok := r.Header.Get(previewHeader)
			if tok == "" {
				if ck, err := r.Cookie(previewCookie); err == nil {
					tok = ck.Value
				}
			}
			if _, ok := previewTokenOK(m.previewKey, id, *pv, tok, now); !ok {
				http.Error(w, "this preview needs a token (open the link with ?ziro_token=, or send X-Ziro-Preview-Token)", http.StatusUnauthorized)
				return
			}
		}
		if now := m.now(); now.Sub(sb.LastActive) > 30*time.Second {
			m.touch(id)
		}
		target := net.JoinHostPort(sb.IP, strconv.Itoa(port))
		proxy.ServeHTTP(w, r.WithContext(contextWith(r, previewTarget{}, target)))
	})
}

type previewTarget struct{}

func contextWith(r *http.Request, k, v any) context.Context {
	return context.WithValue(r.Context(), k, v)
}

// stripPreviewCookie keeps the token away from the sandbox.
func stripPreviewCookie(r *http.Request) {
	cks := r.Cookies()
	r.Header.Del("Cookie")
	for _, c := range cks {
		if c.Name != previewCookie {
			r.AddCookie(c)
		}
	}
}

// ---- CLI ----

var sbxPreview sdkapi.SandboxPreviewRequest

var sandboxExposeCmd = &cobra.Command{
	Use:   "expose <id> <port>",
	Short: "Publish a sandbox port at an HTTPS preview URL",
	Example: `  ziroctl sandbox expose <id> 3000
  ziroctl sandbox expose <id> 8080 --public`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		req := sbxPreview
		var err error
		if req.Port, err = strconv.Atoi(args[1]); err != nil {
			return fmt.Errorf("bad port %q", args[1])
		}
		var pv sdkapi.SandboxPreview
		if err := sandboxCall("POST", "/v1/sandboxes/"+args[0]+"/previews", req, &pv); err != nil {
			return err
		}
		return printResult(pv, func() {
			if pv.Public {
				fmt.Println(pv.URL)
				return
			}
			fmt.Println(pv.TokenURL)
			fmt.Fprintf(os.Stderr, "✓ private preview: open the link once (it sets a cookie), or send %s: %s\n", previewHeader, pv.Token)
		})
	},
}

var sandboxUnexposeCmd = &cobra.Command{
	Use: "unexpose <id> <port>", Short: "Remove a preview URL and revoke its tokens", Example: "  ziroctl sandbox unexpose <id> 3000",
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := sandboxCall("DELETE", "/v1/sandboxes/"+args[0]+"/previews/"+args[1], nil, nil); err != nil {
			return err
		}
		fmt.Printf("✓ preview %s of %s removed\n", args[1], args[0])
		return nil
	},
}

func init() {
	sandboxExposeCmd.Flags().BoolVar(&sbxPreview.Public, "public", false, "Anyone with the URL can open it (default: a token is needed)")
	sandboxExposeCmd.Flags().StringVar(&sbxPreview.TTL, "ttl", "", "Lifetime of the token printed (default: the sandbox's)")
	sandboxCmd.AddCommand(sandboxExposeCmd, sandboxUnexposeCmd)
}
