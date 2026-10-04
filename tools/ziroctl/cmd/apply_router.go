package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	zr "github.com/ziro-os/ziro-os/sdk/router"
	"github.com/ziro-os/ziro-os/sdk/schema"
)

// The `router:` section of a host file, applied on a master: endpoints, the sign-in provider,
// networks (ACL, client version, sign-in policy) and moons. Every value is checked while
// planning, so a bad file changes nothing; each item is applied with the same state change as
// its CLI command. Networks and moons missing from the file are left alone.

func jsonEqual(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

func planRouter(p *hostPlanner, r *schema.HostRouter) error {
	cfg, err := requireMaster()
	if err != nil {
		return fmt.Errorf("router: %w", err)
	}
	st, err := readState()
	if err != nil {
		return err
	}
	R := routerOf(st)

	if len(r.Endpoints) > 0 {
		for _, a := range r.Endpoints {
			if err := validHostPort(a); err != nil {
				return fmt.Errorf("router endpoints: %w", err)
			}
		}
		eps := r.Endpoints
		p.add("router", "endpoints "+strings.Join(eps, ","), !slices.Equal(R.Endpoints, eps), func() error {
			return withState(func(st *ClusterState) error { routerOf(st).Endpoints = eps; return nil })
		})
	}

	if s := r.SSO; s != nil {
		if u, err := url.Parse(s.Issuer); err != nil || u.Scheme != "https" || u.Host == "" {
			return errors.New("router sso: issuer must be an https URL")
		}
		if s.ClientID == "" || strings.ContainsAny(s.ClientID, " \t\r\n") {
			return errors.New("router sso: client_id is required")
		}
		secret := ""
		if s.ClientSecretFile != "" {
			f := s.ClientSecretFile
			if !filepath.IsAbs(f) {
				f = filepath.Join(p.dir, f)
			}
			b, err := os.ReadFile(f)
			if err != nil {
				return fmt.Errorf("router sso: %w", err)
			}
			secret = strings.TrimSpace(string(b))
		}
		want := zr.SSO{Issuer: s.Issuer, ClientID: s.ClientID, GroupsClaim: s.GroupsClaim, TrustUnverifiedEmail: s.TrustUnverifiedEmail}
		changed := R.SSO == nil || *R.SSO != want || st.Secrets[ssoSecretName][ssoSecretKey] != secret
		p.add("router", "sso "+s.Issuer, changed, func() error {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			if _, err := newSSOManager().provider(ctx, want.Issuer); err != nil {
				return err
			}
			return withState(func(st *ClusterState) error {
				routerOf(st).SSO = &want
				if secret != "" {
					st.Secrets[ssoSecretName] = map[string]string{ssoSecretKey: secret}
				} else {
					delete(st.Secrets, ssoSecretName)
				}
				return nil
			})
		})
	}

	for _, n := range r.Networks {
		if err := planRouterNetwork(p, R, n); err != nil {
			return fmt.Errorf("router network %s: %w", n.Name, err)
		}
	}
	for _, m := range r.Moons {
		if err := planRouterMoon(p, R, cfg, m); err != nil {
			return fmt.Errorf("router moon %s: %w", m.Name, err)
		}
	}
	return nil
}

func planRouterNetwork(p *hostPlanner, R *zr.State, n schema.HostRouterNetwork) error {
	if err := validLabel(n.Name); err != nil {
		return err
	}
	if n.ACL != nil {
		if err := validateACL(*n.ACL); err != nil {
			return err
		}
	}
	var sso *zr.NetworkSSO
	if n.SSO != nil {
		s := *n.SSO
		s.Domains = append([]string(nil), s.Domains...)
		if err := validNetworkSSO(&s); err != nil {
			return err
		}
		sso = &s
	}
	cv, cvSet := strings.TrimPrefix(n.ClientVersion, "v"), n.ClientVersion != ""
	if cv == "latest" {
		cv = ""
	} else if _, ok := parseSemver(cv); cvSet && !ok {
		return fmt.Errorf("invalid client_version %q (X.Y.Z or latest)", n.ClientVersion)
	}
	set := func(net *zr.Network) {
		if n.ACL != nil {
			net.ACL = *n.ACL
		}
		if cvSet {
			net.ClientVersion = cv
		}
		if sso != nil {
			net.SSO = sso
		}
	}
	cur := findNetwork(R, n.Name)
	if cur == nil {
		p.add("router", "network "+n.Name+" (new)", true, func() error {
			return withState(func(st *ClusterState) error {
				R := routerOf(st)
				if findNetwork(R, n.Name) != nil {
					return fmt.Errorf("network %q exists", n.Name)
				}
				v4, v6, err := allocNetwork(R, n.CIDR)
				if err != nil {
					return err
				}
				net := zr.Network{ID: randomHex(8), Name: n.Name, IPv4: v4, IPv6: v6, CreatedAt: time.Now().UTC()}
				set(&net)
				R.Networks = append(R.Networks, net)
				return nil
			})
		})
		return nil
	}
	if n.CIDR != "" && n.CIDR != cur.IPv4 {
		return fmt.Errorf("cidr %s differs from the network's %s (an existing network keeps its addresses)", n.CIDR, cur.IPv4)
	}
	next := *cur
	set(&next)
	p.add("router", "network "+n.Name, !jsonEqual(*cur, next), func() error {
		return withState(func(st *ClusterState) error {
			net := findNetwork(routerOf(st), n.Name)
			if net == nil {
				return fmt.Errorf("network %q is gone", n.Name)
			}
			set(net)
			return nil
		})
	})
	return nil
}

func planRouterMoon(p *hostPlanner, R *zr.State, cfg *ClusterConfig, m schema.HostRouterMoon) error {
	if err := validLabel(m.Name); err != nil {
		return err
	}
	if err := validHostPort(m.Public); err != nil {
		return fmt.Errorf("public: %w", err)
	}
	port := m.STUNPort
	if port == 0 {
		port = 3478
	}
	if port < 1 || port > 65535 {
		return errors.New("invalid stun_port")
	}
	h, _, _ := net.SplitHostPort(m.Public)
	want := zr.Relay{Name: m.Name, Addr: m.Public, STUN: net.JoinHostPort(h, strconv.Itoa(port)), ServerName: zr.MoonServerName(m.Name)}
	var cur *zr.Relay
	for i := range R.Relays {
		if R.Relays[i].Name == m.Name {
			cur = &R.Relays[i]
		}
	}
	if cur != nil && cur.ServerName == "" {
		return errors.New("a planet relay has this name")
	}
	if cur == nil {
		p.add("router", "moon "+m.Name+" (new)", true, func() error {
			var tok string
			err := withState(func(st *ClusterState) error {
				R := routerOf(st)
				R.Relays = append(R.Relays, want)
				R.Moons = append(R.Moons, zr.Moon{Name: m.Name, CreatedAt: time.Now().UTC()})
				var e error
				tok, e = moonToken(st, cfg, m.Name, moonTokenTTL)
				return e
			})
			if err == nil { // stderr: --json output on stdout stays parseable
				fmt.Fprintf(os.Stderr, "moon %s registration token (shown once, valid %s):\n%s\n", m.Name, moonTokenTTL, tok)
			}
			return err
		})
		return nil
	}
	p.add("router", "moon "+m.Name, *cur != want, func() error {
		return withState(func(st *ClusterState) error {
			R := routerOf(st)
			for i := range R.Relays {
				if R.Relays[i].Name == m.Name {
					R.Relays[i] = want
				}
			}
			return nil
		})
	})
	return nil
}
