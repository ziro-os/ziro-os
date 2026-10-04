package cmd

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/spf13/cobra"
	zr "github.com/ziro-os/ziro-os/sdk/router"
	"golang.org/x/oauth2"
)

// Router SSO: devices sign in with the OAuth 2.0 device-code flow (RFC 8628) against the
// router's OIDC provider. The router runs the flow (zirocd never talks to the provider and the
// client secret stays on the masters): zirocd registers with SSO set, shows the user the URL and
// code the router got, and repeats the same request until the leader has received and verified
// an ID token (issuer, audience, signature, expiry, verified email) and the network's policy
// (email domains, groups) admits the user. Signed-in devices expire and must sign in again.

const (
	ssoSecretName     = "router-sso"
	ssoSecretKey      = "client_secret"
	ssoDefaultExpiry  = 180 * 24 * time.Hour
	ssoMaxSessions    = 1000
	ssoMaxFlow        = 15 * time.Minute
	ssoProviderMaxAge = time.Hour
)

type ssoIdentity struct {
	email string
	tags  []string
	ttl   time.Duration
}

type ssoSession struct {
	network string
	da      *oauth2.DeviceAuthResponse
	started time.Time

	mu       sync.Mutex
	done     bool
	err      error
	email    string
	verified bool
	groups   []string
	cancel   context.CancelFunc
}

func (s *ssoSession) result() (done bool, email string, verified bool, groups []string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.done, s.email, s.verified, s.groups, s.err
}

type cachedProvider struct {
	p  *oidc.Provider
	at time.Time
}

// ssoManager holds the sign-ins under way on the leader (soft state: after a failover the
// device's next poll starts a new sign-in).
type ssoManager struct {
	hc        *http.Client
	mu        sync.Mutex
	sessions  map[string]*ssoSession // device TLS key hash -> sign-in
	providers map[string]cachedProvider
}

func newSSOManager() *ssoManager {
	return &ssoManager{hc: &http.Client{Timeout: 15 * time.Second}, sessions: map[string]*ssoSession{}, providers: map[string]cachedProvider{}}
}

func (m *ssoManager) provider(_ context.Context, issuer string) (*oidc.Provider, error) {
	m.mu.Lock()
	c, ok := m.providers[issuer]
	m.mu.Unlock()
	if ok && time.Since(c.at) < ssoProviderMaxAge {
		return c.p, nil
	}
	// go-oidc keeps this context for later JWKS fetches: never a request's (it would be cancelled);
	// the client's timeout bounds discovery.
	p, err := oidc.NewProvider(oidc.ClientContext(context.Background(), m.hc), issuer)
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery: %w", err)
	}
	if p.Endpoint().DeviceAuthURL == "" {
		return nil, errors.New("the OIDC provider does not offer the device authorization grant")
	}
	m.mu.Lock()
	m.providers[issuer] = cachedProvider{p: p, at: time.Now()}
	m.mu.Unlock()
	return p, nil
}

// session returns the sign-in for a device, starting one when there is none (or its code expired).
func (m *ssoManager) session(ctx context.Context, cfg zr.SSO, secret, network, keyHash string) (*ssoSession, error) {
	m.mu.Lock()
	s := m.sessions[keyHash]
	if s != nil && s.network == network {
		// A finished sign-in (approved or failed) is kept until its result has been delivered once
		// (registerSSO then forgets it); only a code that expired unused starts over.
		done, _, _, _, _ := s.result()
		if done || time.Now().Before(s.da.Expiry) {
			m.mu.Unlock()
			return s, nil
		}
	}
	if s != nil {
		s.cancel()
		delete(m.sessions, keyHash)
	}
	if len(m.sessions) >= ssoMaxSessions {
		m.mu.Unlock()
		return nil, httpError{http.StatusTooManyRequests, "too many sign-ins under way"}
	}
	m.mu.Unlock()

	p, err := m.provider(ctx, cfg.Issuer)
	if err != nil {
		return nil, httpError{http.StatusBadGateway, err.Error()}
	}
	oc := &oauth2.Config{ClientID: cfg.ClientID, ClientSecret: secret, Endpoint: p.Endpoint(),
		Scopes: []string{oidc.ScopeOpenID, "email", "profile"}}
	hctx := oidc.ClientContext(ctx, m.hc)
	da, err := oc.DeviceAuth(hctx)
	if err != nil {
		return nil, httpError{http.StatusBadGateway, "device authorization: " + err.Error()}
	}
	if da.Expiry.IsZero() || time.Until(da.Expiry) > ssoMaxFlow {
		da.Expiry = time.Now().Add(ssoMaxFlow)
	}
	fctx, cancel := context.WithDeadline(context.Background(), da.Expiry)
	s = &ssoSession{network: network, da: da, started: time.Now(), cancel: cancel}
	m.mu.Lock()
	m.sessions[keyHash] = s
	m.mu.Unlock()
	go s.finish(oidc.ClientContext(fctx, m.hc), cancel, oc, p, cfg)
	return s, nil
}

// finish polls the provider until the user approves (or the code expires) and verifies the ID token.
func (s *ssoSession) finish(ctx context.Context, cancel context.CancelFunc, oc *oauth2.Config, p *oidc.Provider, cfg zr.SSO) {
	defer cancel()
	var email string
	var verified bool
	var groups []string
	tok, err := oc.DeviceAccessToken(ctx, s.da)
	if err == nil {
		raw, _ := tok.Extra("id_token").(string)
		if raw == "" {
			err = errors.New("the provider returned no ID token")
		} else {
			var idt *oidc.IDToken
			if idt, err = p.Verifier(&oidc.Config{ClientID: cfg.ClientID}).Verify(ctx, raw); err == nil {
				var claims map[string]any
				if err = idt.Claims(&claims); err == nil {
					email, _ = claims["email"].(string)
					verified, _ = claims["email_verified"].(bool)
					claim := cfg.GroupsClaim
					if claim == "" {
						claim = "groups"
					}
					if gs, ok := claims[claim].([]any); ok {
						for _, g := range gs {
							if str, ok := g.(string); ok {
								groups = append(groups, str)
							}
						}
					}
				}
			}
		}
	}
	s.mu.Lock()
	s.done, s.err, s.email, s.verified, s.groups = true, err, strings.ToLower(email), verified, groups
	s.mu.Unlock()
}

func (m *ssoManager) forget(keyHash string) {
	m.mu.Lock()
	if s := m.sessions[keyHash]; s != nil {
		s.cancel()
		delete(m.sessions, keyHash)
	}
	m.mu.Unlock()
}

// ssoPolicy decides whether a signed-in user may join a network and which tags their device gets.
func ssoPolicy(cfg zr.SSO, n zr.NetworkSSO, email string, verified bool, groups []string) (ssoIdentity, error) {
	deny := func(msg string) (ssoIdentity, error) { return ssoIdentity{}, httpError{http.StatusForbidden, msg} }
	at := strings.LastIndex(email, "@")
	if at <= 0 || at == len(email)-1 {
		return deny("the provider sent no email address")
	}
	if !verified && !cfg.TrustUnverifiedEmail {
		return deny("the provider has not verified " + email)
	}
	if len(n.Domains) == 0 && len(n.Groups) == 0 {
		return deny("sign-in is not configured for this network") // never "any account of the provider"
	}
	if len(n.Domains) > 0 && !slices.Contains(n.Domains, email[at+1:]) {
		return deny(email + " is not in an allowed domain")
	}
	if len(n.Groups) > 0 && !slices.ContainsFunc(groups, func(g string) bool { return slices.Contains(n.Groups, g) }) {
		return deny(email + " is not in an allowed group")
	}
	tags := append([]string{}, n.Tags...)
	for _, g := range groups {
		tags = append(tags, n.GroupTags[g]...)
	}
	sort.Strings(tags)
	tags = slices.Compact(tags)
	ttl := ssoDefaultExpiry
	if n.KeyExpiry > 0 {
		ttl = time.Duration(n.KeyExpiry) * time.Hour
	}
	return ssoIdentity{email: email, tags: tags, ttl: ttl}, nil
}

// registerSSO handles a Register with SSO set: start or continue the sign-in, and admit the
// device once the provider and the network's policy agree.
func (rt *routerServer) registerSSO(r *http.Request, req zr.RegisterRequest, csr csrInfo, who routerIdent) (zr.RegisterResponse, error) {
	st, err := readState()
	if err != nil {
		return zr.RegisterResponse{}, err
	}
	R := routerOf(st)
	var n *zr.Network
	for i := range R.Networks {
		if R.Networks[i].ID == req.Network {
			n = &R.Networks[i]
		}
	}
	if n == nil || R.SSO == nil || n.SSO == nil {
		return zr.RegisterResponse{}, httpError{http.StatusNotFound, "sign-in is not enabled for this network"}
	}
	secret := st.Secrets[ssoSecretName][ssoSecretKey]
	s, err := rt.sso.session(r.Context(), *R.SSO, secret, n.ID, csr.keyHash)
	if err != nil {
		return zr.RegisterResponse{}, err
	}
	done, email, verified, groups, ferr := s.result()
	if !done {
		return zr.RegisterResponse{Status: "sso", URL: s.da.VerificationURI, URLComplete: s.da.VerificationURIComplete,
			Code: s.da.UserCode, SSOExpires: s.da.Expiry, Interval: int(max(s.da.Interval, 5))}, nil
	}
	rt.sso.forget(csr.keyHash) // a result is used once
	if ferr != nil {
		clusterAudit("ip:"+who.ip, "router sso failed", n.Name, ferr)
		return zr.RegisterResponse{}, httpError{http.StatusForbidden, "sign-in failed: " + ferr.Error()}
	}
	id, err := ssoPolicy(*R.SSO, *n.SSO, email, verified, groups)
	if err != nil {
		clusterAudit("user:"+email, "router sso denied", n.Name, err)
		return zr.RegisterResponse{}, err
	}
	var out zr.RegisterResponse
	err = withState(func(cur *ClusterState) error {
		var e error
		out, e = routerRegister(cur, req, csr.req, csr.keyHash, time.Now(), &id)
		return e
	})
	clusterAudit("user:"+email, "router sso register", out.Member, err)
	if err == nil {
		rt.sync()
	}
	return out, err
}

// ---- CLI ----

var (
	ssoIssuer, ssoClientID, ssoSecretFile, ssoGroupsClaim string
	ssoTrustUnverified                                    bool
	netSSODomains, netSSOGroups, netSSOTags               []string
	netSSOGroupTags                                       map[string]string
	netKeyExpiry                                          time.Duration
	netSSOOff                                             bool
	memberNever                                           bool
	memberExpiresIn                                       time.Duration
)

var routerSSOCmd = &cobra.Command{Use: "sso", Short: "Sign devices in with your identity provider",
	Example: "  ziroctl router sso set --issuer https://login.example.com --client-id ziro-router\n  ziroctl router network set office --sso-domains example.com"}

var routerSSOSetCmd = &cobra.Command{
	Use:   "set",
	Short: "Configure the OIDC provider for device sign-in",
	Example: `  ziroctl router sso set --issuer https://accounts.google.com --client-id 123.apps.googleusercontent.com --client-secret-file /root/oidc.secret
  ziroctl router sso set --issuer https://login.microsoftonline.com/<tenant>/v2.0 --client-id <app-id>`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := requireMaster(); err != nil {
			return err
		}
		u, err := url.Parse(ssoIssuer)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return fmt.Errorf("--issuer must be an https URL")
		}
		if ssoClientID == "" || len(ssoClientID) > 256 || strings.ContainsAny(ssoClientID, " \t\r\n") {
			return fmt.Errorf("--client-id is required")
		}
		secret := ""
		if ssoSecretFile != "" {
			b, err := os.ReadFile(ssoSecretFile)
			if err != nil {
				return err
			}
			secret = strings.TrimSpace(string(b))
		}
		ctx, cancel := context.WithTimeout(cmd.Context(), 15*time.Second)
		defer cancel()
		if _, err := newSSOManager().provider(ctx, ssoIssuer); err != nil { // fail now, not at the first sign-in
			return err
		}
		err = withState(func(st *ClusterState) error {
			routerOf(st).SSO = &zr.SSO{Issuer: ssoIssuer, ClientID: ssoClientID, GroupsClaim: ssoGroupsClaim, TrustUnverifiedEmail: ssoTrustUnverified}
			if secret != "" {
				st.Secrets[ssoSecretName] = map[string]string{ssoSecretKey: secret}
			} else {
				delete(st.Secrets, ssoSecretName)
			}
			return nil
		})
		if err == nil {
			fmt.Printf("✓ sign-in through %s configured; allow it per network: ziroctl router network set <net> --sso-domains <domain>\n", ssoIssuer)
		}
		return err
	},
}

var routerSSOShowCmd = &cobra.Command{
	Use: "show", Short: "Show the OIDC provider", Example: "  ziroctl router sso show",
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := requireMaster(); err != nil {
			return err
		}
		st, err := readState()
		if err != nil {
			return err
		}
		cfg := routerOf(st).SSO
		hasSecret := st.Secrets[ssoSecretName][ssoSecretKey] != ""
		return printResult(map[string]any{"sso": cfg, "client_secret_set": hasSecret}, func() {
			if cfg == nil {
				fmt.Println("sign-in not configured (ziroctl router sso set)")
				return
			}
			fmt.Printf("issuer:     %s\nclient id:  %s\nsecret:     %v\ngroups:     %s claim\n", cfg.Issuer, cfg.ClientID, hasSecret, orDefault(cfg.GroupsClaim, "groups"))
		})
	},
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

var routerSSOClearCmd = &cobra.Command{
	Use: "clear", Short: "Remove the OIDC provider", Example: "  ziroctl router sso clear",
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := requireMaster(); err != nil {
			return err
		}
		return withState(func(st *ClusterState) error {
			routerOf(st).SSO = nil
			delete(st.Secrets, ssoSecretName)
			return nil
		})
	},
}

// applyNetworkSSO applies `network set --sso-*` flags.
func applyNetworkSSO(cmd *cobra.Command, n *zr.Network) error {
	f := cmd.Flags()
	if netSSOOff {
		n.SSO = nil
		return nil
	}
	if !f.Changed("sso-domains") && !f.Changed("sso-groups") && !f.Changed("sso-tags") && !f.Changed("sso-group-tags") && !f.Changed("key-expiry") {
		return nil
	}
	s := zr.NetworkSSO{}
	if n.SSO != nil {
		s = *n.SSO
	}
	if f.Changed("sso-domains") {
		s.Domains = nil
		for _, d := range netSSODomains {
			d = strings.ToLower(strings.TrimPrefix(d, "@"))
			if !validHost(d) {
				return fmt.Errorf("invalid domain %q", d)
			}
			s.Domains = append(s.Domains, d)
		}
	}
	if f.Changed("sso-groups") {
		s.Groups = netSSOGroups
	}
	if f.Changed("sso-tags") {
		if err := validTags(netSSOTags); err != nil {
			return err
		}
		s.Tags = netSSOTags
	}
	if f.Changed("sso-group-tags") {
		s.GroupTags = map[string][]string{}
		for g, ts := range netSSOGroupTags {
			tags := strings.Split(ts, "+")
			if err := validTags(tags); err != nil {
				return err
			}
			s.GroupTags[g] = tags
		}
	}
	if f.Changed("key-expiry") {
		if netKeyExpiry < time.Hour || netKeyExpiry > 5*365*24*time.Hour {
			return fmt.Errorf("--key-expiry must be between 1h and 5 years")
		}
		s.KeyExpiry = int(netKeyExpiry / time.Hour)
	}
	if len(s.Domains) == 0 && len(s.Groups) == 0 {
		return fmt.Errorf("sign-in needs --sso-domains or --sso-groups: an open provider would admit anyone")
	}
	n.SSO = &s
	return nil
}

var routerMemberExpiryCmd = &cobra.Command{
	Use:   "expiry <network> <device>",
	Short: "Change when a device must sign in again",
	Example: `  ziroctl router member expiry office db-1 --never
  ziroctl router member expiry office alice-laptop --in 720h`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := requireMaster(); err != nil {
			return err
		}
		if memberNever == cmd.Flags().Changed("in") {
			return fmt.Errorf("give exactly one of --never or --in")
		}
		return memberOp(args[0], args[1], func(_ *zr.State, m *zr.Member) error {
			if memberNever {
				m.Expires = time.Time{}
			} else {
				if memberExpiresIn <= 0 {
					return fmt.Errorf("--in must be positive")
				}
				m.Expires = time.Now().Add(memberExpiresIn).UTC()
			}
			return nil
		})
	},
}

func init() {
	routerSSOSetCmd.Flags().StringVar(&ssoIssuer, "issuer", "", "OIDC issuer URL (https)")
	routerSSOSetCmd.Flags().StringVar(&ssoClientID, "client-id", "", "OAuth client ID (device-code grant enabled)")
	routerSSOSetCmd.Flags().StringVar(&ssoSecretFile, "client-secret-file", "", "file holding the client secret (confidential clients)")
	routerSSOSetCmd.Flags().StringVar(&ssoGroupsClaim, "groups-claim", "", "ID token claim listing groups (default groups)")
	routerSSOSetCmd.Flags().BoolVar(&ssoTrustUnverified, "trust-unverified-email", false, "accept emails the provider does not mark verified")
	routerSSOCmd.AddCommand(routerSSOSetCmd, routerSSOShowCmd, routerSSOClearCmd)
	routerCmd.AddCommand(routerSSOCmd)

	f := routerNetworkSetCmd.Flags()
	f.StringSliceVar(&netSSODomains, "sso-domains", nil, "email domains that may sign in")
	f.StringSliceVar(&netSSOGroups, "sso-groups", nil, "groups that may sign in (any of)")
	f.StringSliceVar(&netSSOTags, "sso-tags", nil, "tags for signed-in devices")
	f.StringToStringVar(&netSSOGroupTags, "sso-group-tags", nil, "group=tag1+tag2: extra tags per group")
	f.DurationVar(&netKeyExpiry, "key-expiry", ssoDefaultExpiry, "how long a signed-in device stays in")
	f.BoolVar(&netSSOOff, "sso-off", false, "turn sign-in off for the network")

	routerMemberExpiryCmd.Flags().BoolVar(&memberNever, "never", false, "never expire (servers)")
	routerMemberExpiryCmd.Flags().DurationVar(&memberExpiresIn, "in", 0, "expire after this long")
	routerMemberCmd.AddCommand(routerMemberExpiryCmd)
}
