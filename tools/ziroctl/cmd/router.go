package cmd

import (
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	zr "github.com/ziro-os/ziro-os/sdk/router"
	"go.yaml.in/yaml/v3"
)

// `ziroctl router`: global networks for devices anywhere (laptops, CI, other clouds and
// clusters), joined with zirocd. The control plane runs inside cluster-master on every master.

var routerCmd = &cobra.Command{
	Use:   "router",
	Short: "Global mesh networks for devices joined with zirocd",
	Long: `The router is a global network switch: devices running zirocd join a network with a key
(or an admin's approval), get a stable address and a name (<device>.<network>.ziro), and reach
the peers its ACL allows, directly or through relays. It runs on the cluster masters.`,
	Example: `  ziroctl router network create office
  ziroctl router key create office --reusable --tags laptop --expiry 720h
  ziroctl router member ls office
  ziroctl router acl set office -f acl.yaml`,
}

var (
	rtCIDR          string
	rtPolicy        string
	rtClientVersion string
	rtReusable      bool
	rtEphemeral     bool
	rtExpiry        time.Duration
	rtTags          []string
	rtACLFile       string
)

// routerEndpoints are the addresses clients dial: the configured public ones, else the masters.
func routerEndpoints(st *ClusterState, cfg *ClusterConfig) []string {
	if st.Router != nil && len(st.Router.Endpoints) > 0 {
		return st.Router.Endpoints
	}
	return masterAddrs(st, cfg)
}

// routerInvite builds the string a device joins with.
func routerInvite(st *ClusterState, cfg *ClusterConfig, netID, key string) (string, error) {
	pin, err := pemHash(st.CACert)
	if err != nil {
		return "", fmt.Errorf("cluster CA: %w", err)
	}
	eps := routerEndpoints(st, cfg)
	if len(eps) == 0 {
		return "", fmt.Errorf("no router endpoints: ziroctl router endpoints set <host:port>")
	}
	return zr.Invite{Endpoints: eps, Pin: pin, Network: netID, Key: key}.String(), nil
}

func mustNetwork(st *ClusterState, ref string) (*zr.Network, error) {
	if n := findNetwork(routerOf(st), ref); n != nil {
		return n, nil
	}
	return nil, fmt.Errorf("no network %q (ziroctl router network ls)", ref)
}

// ---- endpoints ----

var routerEndpointsCmd = &cobra.Command{
	Use:   "endpoints",
	Short: "Show or set the public addresses devices dial",
	Example: `  ziroctl router endpoints
  ziroctl router endpoints set router.example.com:7443 203.0.113.7:7443
  ziroctl router endpoints set   # back to the master addresses`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := requireMaster()
		if err != nil {
			return err
		}
		st, err := readState()
		if err != nil {
			return err
		}
		eps := routerEndpoints(st, cfg)
		return printResult(eps, func() {
			for _, e := range eps {
				fmt.Println(e)
			}
		})
	},
}

var routerEndpointsSetCmd = &cobra.Command{
	Use:     "set [host:port...]",
	Short:   "Set the public addresses devices dial",
	Example: "  ziroctl router endpoints set router.example.com:7443",
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := requireMaster(); err != nil {
			return err
		}
		for _, a := range args {
			h, p, err := net.SplitHostPort(a)
			if err != nil || h == "" || !validPortNum(p) || !(validHost(h) || net.ParseIP(h) != nil) {
				return fmt.Errorf("invalid endpoint %q (want host:port)", a)
			}
		}
		if err := withState(func(st *ClusterState) error { routerOf(st).Endpoints = args; return nil }); err != nil {
			return err
		}
		fmt.Println("✓ router endpoints updated; new keys and invites carry them (existing devices learn them on reconnect)")
		return nil
	},
}

// ---- networks ----

var routerNetworkCmd = &cobra.Command{Use: "network", Aliases: []string{"net"}, Short: "Create and manage networks",
	Example: "  ziroctl router network create office\n  ziroctl router network ls"}

var routerNetworkCreateCmd = &cobra.Command{
	Use:   "create <name>",
	Short: "Create a network; default deny until ACL rules allow traffic",
	Example: `  ziroctl router network create office
  ziroctl router network create lab --cidr 100.70.0.0/16 --policy allow`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := requireMaster(); err != nil {
			return err
		}
		if err := validLabel(args[0]); err != nil {
			return err
		}
		var acl zr.ACL
		switch rtPolicy {
		case "deny":
		case "allow":
			acl.Rules = []zr.Rule{{Src: []string{"*"}, Dst: []string{"*:*"}}}
		default:
			return fmt.Errorf("--policy must be deny or allow")
		}
		var n zr.Network
		err := withState(func(st *ClusterState) error {
			R := routerOf(st)
			if findNetwork(R, args[0]) != nil {
				return fmt.Errorf("network %q exists", args[0])
			}
			v4, v6, err := allocNetwork(R, rtCIDR)
			if err != nil {
				return err
			}
			n = zr.Network{ID: randomHex(8), Name: args[0], IPv4: v4, IPv6: v6, ACL: acl, CreatedAt: time.Now().UTC()}
			R.Networks = append(R.Networks, n)
			return nil
		})
		if err != nil {
			return err
		}
		return printResult(n, func() {
			fmt.Printf("✓ network %s (%s): %s, %s, policy %s\n", n.Name, n.ID, n.IPv4, n.IPv6, rtPolicy)
			fmt.Printf("  Admit devices: ziroctl router key create %s\n", n.Name)
		})
	},
}

var routerNetworkLsCmd = &cobra.Command{
	Use: "ls", Short: "List networks", Example: "  ziroctl router network ls",
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := requireMaster(); err != nil {
			return err
		}
		st, err := readState()
		if err != nil {
			return err
		}
		R := routerOf(st)
		count := map[string]int{}
		for _, m := range R.Members {
			if m.Authorized {
				count[m.Network]++
			}
		}
		nets := append([]zr.Network{}, R.Networks...)
		return printResult(nets, func() {
			tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "NAME\tID\tIPV4\tIPV6\tMEMBERS\tRULES\tCLIENT")
			for _, n := range nets {
				cv := n.ClientVersion
				if cv == "" {
					cv = "latest"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%d\t%s\n", n.Name, n.ID, n.IPv4, n.IPv6, count[n.ID], len(n.ACL.Rules), cv)
			}
			tw.Flush()
		})
	},
}

var routerNetworkRmCmd = &cobra.Command{
	Use: "rm <network>", Short: "Delete a network, its members and keys", Args: cobra.ExactArgs(1),
	Example: "  ziroctl router network rm lab",
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := requireMaster(); err != nil {
			return err
		}
		err := withState(func(st *ClusterState) error {
			n, err := mustNetwork(st, args[0])
			if err != nil {
				return err
			}
			R, id := routerOf(st), n.ID
			var nets []zr.Network
			for _, x := range R.Networks {
				if x.ID != id {
					nets = append(nets, x)
				}
			}
			var ms []zr.Member
			for _, m := range R.Members {
				if m.Network != id {
					ms = append(ms, m)
				}
			}
			var ks []zr.JoinKey
			for _, k := range R.Keys {
				if k.Network != id {
					ks = append(ks, k)
				}
			}
			R.Networks, R.Members, R.Keys = nets, ms, ks
			return nil
		})
		if err == nil {
			fmt.Printf("✓ network %s deleted; its devices were disconnected\n", args[0])
		}
		return err
	},
}

var routerNetworkSetCmd = &cobra.Command{
	Use:     "set <network>",
	Short:   "Change network settings",
	Example: "  ziroctl router network set office --client-version 1.0.21\n  ziroctl router network set office --client-version latest",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := requireMaster(); err != nil {
			return err
		}
		if !cmd.Flags().Changed("client-version") {
			return fmt.Errorf("nothing to set (--client-version)")
		}
		cv := strings.TrimPrefix(rtClientVersion, "v")
		if cv == "latest" {
			cv = ""
		} else if _, ok := parseSemver(cv); !ok {
			return fmt.Errorf("invalid --client-version %q (X.Y.Z or latest)", rtClientVersion)
		}
		return withState(func(st *ClusterState) error {
			n, err := mustNetwork(st, args[0])
			if err == nil {
				n.ClientVersion = cv
			}
			return err
		})
	},
}

var routerNetworkInviteCmd = &cobra.Command{
	Use:   "invite <network>",
	Short: "Print a key whose devices wait for an admin's approval",
	Example: `  ziroctl router network invite office
  # on the device: zirocd up --key zr1_...   then here: ziroctl router member approve office <name>`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := requireMaster()
		if err != nil {
			return err
		}
		st, err := readState()
		if err != nil {
			return err
		}
		n, err := mustNetwork(st, args[0])
		if err != nil {
			return err
		}
		inv, err := routerInvite(st, cfg, n.ID, "")
		if err != nil {
			return err
		}
		return printResult(map[string]string{"invite": inv}, func() { fmt.Println(inv) })
	},
}

// ---- join keys ----

var routerKeyCmd = &cobra.Command{Use: "key", Aliases: []string{"keys"}, Short: "Join keys that admit devices without approval",
	Example: "  ziroctl router key create office --reusable --tags laptop\n  ziroctl router key ls"}

var routerKeyCreateCmd = &cobra.Command{
	Use:   "create <network>",
	Short: "Create a join key, shown once",
	Example: `  ziroctl router key create office                       # one device, 24h
  ziroctl router key create office --reusable --expiry 720h --tags laptop
  ziroctl router key create ci --reusable --ephemeral --tags ci`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := requireMaster()
		if err != nil {
			return err
		}
		if err := validTags(rtTags); err != nil {
			return err
		}
		if rtExpiry <= 0 || rtExpiry > 365*24*time.Hour {
			return fmt.Errorf("--expiry must be between 1s and 8760h")
		}
		id, full, hash := routerKeySecret()
		var k zr.JoinKey
		var inv string
		err = withState(func(st *ClusterState) error {
			n, err := mustNetwork(st, args[0])
			if err != nil {
				return err
			}
			now := time.Now().UTC()
			k = zr.JoinKey{ID: id, Network: n.ID, Hash: hash, Reusable: rtReusable, Ephemeral: rtEphemeral, Tags: rtTags,
				Expires: now.Add(rtExpiry), CreatedAt: now}
			R := routerOf(st)
			R.Keys = append(R.Keys, k)
			inv, err = routerInvite(st, cfg, n.ID, full)
			return err
		})
		if err != nil {
			return err
		}
		return printResult(map[string]any{"id": k.ID, "key": inv, "expires": k.Expires}, func() {
			fmt.Println(inv)
			fmt.Fprintf(os.Stderr, "✓ key %s (expires %s). Shown once: on the device run  zirocd up --key <key>\n", k.ID, k.Expires.Format(time.RFC3339))
		})
	},
}

var routerKeyLsCmd = &cobra.Command{
	Use: "ls [network]", Short: "List join keys without their secrets", Args: cobra.MaximumNArgs(1),
	Example: "  ziroctl router key ls\n  ziroctl router key ls office --json",
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := requireMaster(); err != nil {
			return err
		}
		st, err := readState()
		if err != nil {
			return err
		}
		R := routerOf(st)
		type keyView struct {
			ID        string    `json:"id"`
			Network   string    `json:"network"`
			Reusable  bool      `json:"reusable"`
			Ephemeral bool      `json:"ephemeral"`
			Tags      []string  `json:"tags"`
			Uses      int       `json:"uses"`
			Expires   time.Time `json:"expires"`
		}
		out := []keyView{}
		for _, k := range R.Keys {
			n := findNetwork(R, k.Network)
			if n == nil || (len(args) == 1 && n.Name != args[0] && n.ID != args[0]) {
				continue
			}
			out = append(out, keyView{k.ID, n.Name, k.Reusable, k.Ephemeral, k.Tags, k.Uses, k.Expires})
		}
		return printResult(out, func() {
			tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tNETWORK\tREUSABLE\tEPHEMERAL\tTAGS\tUSES\tEXPIRES")
			for _, k := range out {
				exp := k.Expires.Format(time.RFC3339)
				if time.Now().After(k.Expires) {
					exp += " (expired)"
				}
				fmt.Fprintf(tw, "%s\t%s\t%v\t%v\t%s\t%d\t%s\n", k.ID, k.Network, k.Reusable, k.Ephemeral, strings.Join(k.Tags, ","), k.Uses, exp)
			}
			tw.Flush()
		})
	},
}

var routerKeyRmCmd = &cobra.Command{
	Use: "rm <id>", Short: "Revoke a join key; devices it admitted stay", Args: cobra.ExactArgs(1),
	Example: "  ziroctl router key rm 3f9a1c2e",
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := requireMaster(); err != nil {
			return err
		}
		return withState(func(st *ClusterState) error {
			R := routerOf(st)
			for i, k := range R.Keys {
				if k.ID == args[0] {
					R.Keys = append(R.Keys[:i], R.Keys[i+1:]...)
					return nil
				}
			}
			return fmt.Errorf("no key %q", args[0])
		})
	},
}

// ---- members ----

var routerMemberCmd = &cobra.Command{Use: "member", Aliases: []string{"members", "device"}, Short: "Devices in a network",
	Example: "  ziroctl router member ls office\n  ziroctl router member approve office alice-laptop"}

// routerOnline asks the leader's hub for liveness (best effort: nil when unavailable).
func routerOnline() map[string]routerSoft {
	var out map[string]routerSoft
	if !raftMode() {
		return nil
	}
	if code, err := socketCall("GET", "/router/online", nil, &out); err != nil || code != 200 {
		return nil
	}
	return out
}

var routerMemberLsCmd = &cobra.Command{
	Use: "ls <network>", Short: "List devices; pending ones need approval", Args: cobra.ExactArgs(1),
	Example: "  ziroctl router member ls office\n  ziroctl router member ls office --json",
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := requireMaster(); err != nil {
			return err
		}
		st, err := readState()
		if err != nil {
			return err
		}
		n, err := mustNetwork(st, args[0])
		if err != nil {
			return err
		}
		live := routerOnline()
		type memberView struct {
			zr.Member
			Status    string    `json:"status"`
			Endpoints []string  `json:"endpoints,omitempty"`
			Version   string    `json:"version,omitempty"`
			LastSeen  time.Time `json:"last_seen,omitempty"`
		}
		out := []memberView{}
		for _, m := range routerOf(st).Members {
			if m.Network != n.ID {
				continue
			}
			v := memberView{Member: m, Status: "offline"}
			if !m.Authorized {
				v.Status = "pending"
			}
			if s, ok := live[m.ID]; ok {
				v.Endpoints, v.Version, v.LastSeen = s.Endpoints, s.Version, s.Seen
				if s.Online && m.Authorized {
					v.Status = "online"
				}
			}
			out = append(out, v)
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
		return printResult(out, func() {
			tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "NAME\tID\tIPV4\tSTATUS\tOS\tVERSION\tTAGS\tROUTES")
			for _, m := range out {
				routes := strings.Join(m.Approved, ",")
				if len(m.Routes) > len(m.Approved) {
					routes += fmt.Sprintf(" (+%d unapproved)", len(m.Routes)-len(m.Approved))
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", m.Name, m.ID, m.IPv4, m.Status, m.OS, m.Version,
					strings.Join(m.Tags, ","), routes)
			}
			tw.Flush()
		})
	},
}

// memberOp changes one member of a network under the state lock.
func memberOp(netRef, ref string, fn func(R *zr.State, m *zr.Member) error) error {
	return withState(func(st *ClusterState) error {
		n, err := mustNetwork(st, netRef)
		if err != nil {
			return err
		}
		m := findMember(routerOf(st), n.ID, ref)
		if m == nil {
			return fmt.Errorf("no device %q in %s", ref, n.Name)
		}
		return fn(routerOf(st), m)
	})
}

var routerMemberApproveCmd = &cobra.Command{
	Use: "approve <network> <device>", Short: "Admit a device that asked to join", Args: cobra.ExactArgs(2),
	Example: "  ziroctl router member approve office alice-laptop --tags admin",
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := requireMaster(); err != nil {
			return err
		}
		if err := validTags(rtTags); err != nil {
			return err
		}
		err := memberOp(args[0], args[1], func(_ *zr.State, m *zr.Member) error {
			m.Authorized = true
			if cmd.Flags().Changed("tags") {
				m.Tags = rtTags
			}
			return nil
		})
		if err == nil {
			fmt.Printf("✓ %s admitted to %s\n", args[1], args[0])
		}
		return err
	},
}

var routerMemberRmCmd = &cobra.Command{
	Use: "rm <network> <device>", Short: "Remove a device and disconnect it at once", Args: cobra.ExactArgs(2),
	Example: "  ziroctl router member rm office old-laptop",
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := requireMaster(); err != nil {
			return err
		}
		err := memberOp(args[0], args[1], func(R *zr.State, m *zr.Member) error {
			id := m.ID
			for i := range R.Members {
				if R.Members[i].ID == id {
					R.Members = append(R.Members[:i], R.Members[i+1:]...)
					return nil
				}
			}
			return nil
		})
		if err == nil {
			fmt.Printf("✓ %s removed from %s\n", args[1], args[0])
		}
		return err
	},
}

var routerMemberTagCmd = &cobra.Command{
	Use: "tag <network> <device>", Short: "Replace a device's tags", Args: cobra.ExactArgs(2),
	Example: "  ziroctl router member tag office build-01 --tags ci,linux",
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := requireMaster(); err != nil {
			return err
		}
		if err := validTags(rtTags); err != nil {
			return err
		}
		return memberOp(args[0], args[1], func(_ *zr.State, m *zr.Member) error { m.Tags = rtTags; return nil })
	},
}

// ---- ACL ----

var routerACLCmd = &cobra.Command{
	Use:     "acl",
	Short:   "Who may reach whom; default deny",
	Example: "  ziroctl router acl get office > acl.yaml\n  ziroctl router acl set office -f acl.yaml\n  ziroctl router acl test office web-1 db-1 5432/tcp",
	Long: `Rules allow traffic; everything else is dropped by the receiving device.
Selectors: *, tag:<t>, group:<g>, member:<name> or a CIDR (subnet routes).
Destinations add ports: tag:db:5432, *:*, member:nas:80,443, 10.0.0.0/16:22.

  groups:
    admins: [alice-laptop, bob-laptop]
  rules:
    - src: [group:admins]
      dst: ["*:*"]
    - src: [tag:web]
      dst: [tag:db:5432]
      proto: tcp`,
}

var routerACLGetCmd = &cobra.Command{
	Use: "get <network>", Short: "Print the ACL as YAML", Args: cobra.ExactArgs(1),
	Example: "  ziroctl router acl get office",
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := requireMaster(); err != nil {
			return err
		}
		st, err := readState()
		if err != nil {
			return err
		}
		n, err := mustNetwork(st, args[0])
		if err != nil {
			return err
		}
		return printResult(n.ACL, func() {
			b, _ := yaml.Marshal(n.ACL)
			os.Stdout.Write(b)
		})
	},
}

var routerACLSetCmd = &cobra.Command{
	Use: "set <network> -f <file>", Short: "Replace the ACL from a YAML or JSON file", Args: cobra.ExactArgs(1),
	Example: "  ziroctl router acl set office -f acl.yaml",
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := requireMaster(); err != nil {
			return err
		}
		if rtACLFile == "" {
			return fmt.Errorf("-f <file> is required")
		}
		b, err := os.ReadFile(rtACLFile)
		if err != nil {
			return err
		}
		var acl zr.ACL
		dec := yaml.NewDecoder(strings.NewReader(string(b)))
		dec.KnownFields(true) // a typo must not silently drop a rule
		if err := dec.Decode(&acl); err != nil {
			return fmt.Errorf("%s: %w", rtACLFile, err)
		}
		if err := validateACL(acl); err != nil {
			return err
		}
		err = withState(func(st *ClusterState) error {
			n, err := mustNetwork(st, args[0])
			if err == nil {
				n.ACL = acl
			}
			return err
		})
		if err == nil {
			fmt.Printf("✓ ACL of %s updated (%d rules); devices apply it within a second\n", args[0], len(acl.Rules))
		}
		return err
	},
}

var routerACLTestCmd = &cobra.Command{
	Use:     "test <network> <src-device> <dst-device> <port>[/tcp|udp]",
	Short:   "Check whether the ACL allows a connection",
	Example: "  ziroctl router acl test office alice-laptop db-1 5432/tcp",
	Args:    cobra.ExactArgs(4),
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := requireMaster(); err != nil {
			return err
		}
		st, err := readState()
		if err != nil {
			return err
		}
		n, err := mustNetwork(st, args[0])
		if err != nil {
			return err
		}
		R := routerOf(st)
		src, dst := findMember(R, n.ID, args[1]), findMember(R, n.ID, args[2])
		if src == nil || dst == nil {
			return fmt.Errorf("unknown device")
		}
		ps, proto, _ := strings.Cut(args[3], "/")
		if proto == "" {
			proto = "tcp"
		}
		port, err := strconv.ParseUint(ps, 10, 16)
		if err != nil {
			return fmt.Errorf("invalid port %q", ps)
		}
		var members []*zr.Member
		for i := range R.Members {
			if R.Members[i].Network == n.ID && R.Members[i].Authorized {
				members = append(members, &R.Members[i])
			}
		}
		ok := compileACL(n.ACL, members).allowed(src, dst, proto, uint16(port))
		verdict := "deny"
		if ok {
			verdict = "allow"
		}
		return printResult(map[string]any{"allowed": ok}, func() {
			fmt.Printf("%s: %s → %s %d/%s\n", verdict, src.Name, dst.Name, port, proto)
		})
	},
}

// ---- subnet routes ----

var routerRouteCmd = &cobra.Command{Use: "route", Aliases: []string{"routes"}, Short: "Subnets devices advertise into a network",
	Example: "  ziroctl router route ls office\n  ziroctl router route approve office gw-1 10.200.0.0/16"}

var routerRouteLsCmd = &cobra.Command{
	Use: "ls <network>", Short: "List advertised and approved routes", Args: cobra.ExactArgs(1),
	Example: "  ziroctl router route ls office",
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := requireMaster(); err != nil {
			return err
		}
		st, err := readState()
		if err != nil {
			return err
		}
		n, err := mustNetwork(st, args[0])
		if err != nil {
			return err
		}
		type routeView struct {
			Device   string `json:"device"`
			Route    string `json:"route"`
			Approved bool   `json:"approved"`
		}
		out := []routeView{}
		for _, m := range routerOf(st).Members {
			if m.Network == n.ID {
				for _, r := range m.Routes {
					out = append(out, routeView{m.Name, r, hasString(m.Approved, r)})
				}
			}
		}
		return printResult(out, func() {
			tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "DEVICE\tROUTE\tAPPROVED")
			for _, r := range out {
				fmt.Fprintf(tw, "%s\t%s\t%v\n", r.Device, r.Route, r.Approved)
			}
			tw.Flush()
		})
	},
}

func routeOp(approve bool) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		if _, err := requireMaster(); err != nil {
			return err
		}
		rs, err := validRoutes(args[2:3])
		if err != nil {
			return err
		}
		r := rs[0]
		return memberOp(args[0], args[1], func(_ *zr.State, m *zr.Member) error {
			if !hasString(m.Routes, r) {
				return fmt.Errorf("%s does not advertise %s (zirocd up --advertise-routes %s)", m.Name, r, r)
			}
			var out []string
			for _, a := range m.Approved {
				if a != r {
					out = append(out, a)
				}
			}
			if approve {
				out = append(out, r)
				sort.Strings(out)
			}
			m.Approved = out
			return nil
		})
	}
}

var routerRouteApproveCmd = &cobra.Command{
	Use: "approve <network> <device> <cidr>", Short: "Route a subnet through a device", Args: cobra.ExactArgs(3),
	Example: "  ziroctl router route approve office gw-1 10.200.0.0/16", RunE: routeOp(true),
}

var routerRouteRevokeCmd = &cobra.Command{
	Use: "revoke <network> <device> <cidr>", Short: "Stop routing a subnet through a device", Args: cobra.ExactArgs(3),
	Example: "  ziroctl router route revoke office gw-1 10.200.0.0/16", RunE: routeOp(false),
}

func init() {
	rootCmd.AddCommand(routerCmd)
	routerCmd.AddCommand(routerEndpointsCmd, routerNetworkCmd, routerKeyCmd, routerMemberCmd, routerACLCmd, routerRouteCmd)
	routerEndpointsCmd.AddCommand(routerEndpointsSetCmd)

	routerNetworkCreateCmd.Flags().StringVar(&rtCIDR, "cidr", "", "IPv4 network (default: a free /16 of 100.64.0.0/10)")
	routerNetworkCreateCmd.Flags().StringVar(&rtPolicy, "policy", "deny", "deny (rules allow traffic) or allow (every device reaches every device)")
	routerNetworkSetCmd.Flags().StringVar(&rtClientVersion, "client-version", "", "zirocd version the fleet runs (X.Y.Z, or latest)")
	routerNetworkCmd.AddCommand(routerNetworkCreateCmd, routerNetworkLsCmd, routerNetworkRmCmd, routerNetworkSetCmd, routerNetworkInviteCmd)

	routerKeyCreateCmd.Flags().BoolVar(&rtReusable, "reusable", false, "admit any number of devices until it expires")
	routerKeyCreateCmd.Flags().BoolVar(&rtEphemeral, "ephemeral", false, "devices are removed 10 minutes after going offline (CI, autoscaling)")
	routerKeyCreateCmd.Flags().DurationVar(&rtExpiry, "expiry", 24*time.Hour, "how long the key admits devices")
	routerKeyCreateCmd.Flags().StringSliceVar(&rtTags, "tags", nil, "tags given to devices it admits")
	routerKeyCmd.AddCommand(routerKeyCreateCmd, routerKeyLsCmd, routerKeyRmCmd)

	routerMemberApproveCmd.Flags().StringSliceVar(&rtTags, "tags", nil, "tags to give the device")
	routerMemberTagCmd.Flags().StringSliceVar(&rtTags, "tags", nil, "the device's tags")
	routerMemberCmd.AddCommand(routerMemberLsCmd, routerMemberApproveCmd, routerMemberRmCmd, routerMemberTagCmd)

	routerACLSetCmd.Flags().StringVarP(&rtACLFile, "file", "f", "", "ACL file (YAML or JSON)")
	routerACLCmd.AddCommand(routerACLGetCmd, routerACLSetCmd, routerACLTestCmd)

	routerRouteCmd.AddCommand(routerRouteLsCmd, routerRouteApproveCmd, routerRouteRevokeCmd)
}
