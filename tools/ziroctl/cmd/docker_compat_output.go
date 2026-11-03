package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strconv"
	"strings"
	"text/template"
	"time"
)

// Docker-shaped output for `docker ps`, `docker inspect` and `docker network inspect`.
//
// nerdctl 2.2.1 prints most of what Docker prints, with gaps that break tools reading it (Coolify,
// scripts written for Docker):
//   - a container's networks are named "unknown-eth0", "unknown-eth1" instead of their names;
//   - `ps` has no State, Networks, RunningFor or Mounts, so '{{.State}}' is a template error;
//   - `inspect` has no Config.OpenStdin; `network inspect` has no EnableIPv6, Driver or Scope, and
//     its Containers carry no addresses.
//
// The wrapper asks nerdctl for JSON, fills these in, and renders the caller's --format with Docker's
// template functions. Without --format (or with a "table" format) nerdctl's own output is kept.

// nerdctlRunner runs nerdctl with args and returns its stdout.
type nerdctlRunner func(args ...string) ([]byte, error)

// dockerTemplateFuncs are the functions Docker's --format templates have (docker/cli templates.basicFunctions).
var dockerTemplateFuncs = template.FuncMap{
	"json": func(v any) (string, error) {
		var b bytes.Buffer
		enc := json.NewEncoder(&b)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(v); err != nil {
			return "", err
		}
		return strings.TrimSpace(b.String()), nil
	},
	"split": strings.Split,
	"join":  strings.Join,
	"title": func(s string) string {
		if s == "" {
			return s
		}
		return strings.ToUpper(s[:1]) + s[1:]
	},
	"lower": strings.ToLower,
	"upper": strings.ToUpper,
	"pad": func(s string, before, after int) string {
		return strings.Repeat(" ", before) + s + strings.Repeat(" ", after)
	},
	"truncate": func(s string, n int) string {
		if n >= 0 && len(s) > n {
			return s[:n]
		}
		return s
	},
}

// renderDockerTemplate executes a Docker --format template once per item, one item per line, as
// Docker does. "json" alone means '{{json .}}'.
func renderDockerTemplate(format string, items []any) ([]byte, error) {
	if format == "json" {
		format = "{{json .}}"
	}
	t, err := template.New("").Funcs(dockerTemplateFuncs).Parse(format)
	if err != nil {
		return nil, fmt.Errorf("template parsing error: %v", err)
	}
	var out bytes.Buffer
	for _, it := range items {
		if err := t.Execute(&out, it); err != nil {
			return nil, fmt.Errorf("template: %v", err)
		}
		out.WriteByte('\n')
	}
	return out.Bytes(), nil
}

// takeFormat removes --format/-f (as `flag`) from args and returns it. short says whether "-f" means
// --format for this command (it does for inspect, not for ps where -f is --filter).
func takeFormat(args []string, short bool) (rest []string, format string, found bool) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			return append(rest, args[i:]...), format, found
		case a == "--format" || (short && a == "-f"):
			if i+1 < len(args) {
				format, found = args[i+1], true
				i++
				continue
			}
		case strings.HasPrefix(a, "--format="):
			format, found = strings.TrimPrefix(a, "--format="), true
			continue
		}
		rest = append(rest, a)
	}
	return rest, format, found
}

// containerNetworks is the `nerdctl/networks` label: the container's networks in attach order, so
// interface eth<i> belongs to networks[i] (go-cni names interfaces that way).
func containerNetworks(labels map[string]string) []string {
	var n []string
	_ = json.Unmarshal([]byte(labels["nerdctl/networks"]), &n)
	return n
}

// dockerNetworkName maps nerdctl's "unknown-eth<i>" key to the network's name, as nerdctl main's
// cniNetworkName does (not in a release up to 2.3.5). Anything else is kept.
func dockerNetworkName(key string, networks []string) string {
	if idx, ok := strings.CutPrefix(key, "unknown-eth"); ok {
		if i, err := strconv.Atoi(idx); err == nil && i >= 0 && i < len(networks) {
			return networks[i]
		}
	}
	return key
}

func asMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func stringMap(v any) map[string]string {
	out := map[string]string{}
	for k, x := range asMap(v) {
		if s, ok := x.(string); ok {
			out[k] = s
		}
	}
	return out
}

// cniConfigs are the CNI network configurations the inspect fixes match addresses against; tests
// replace it.
var cniConfigs = func() []cniNetwork { return cniNetworks(defaultCNIConfDir) }

// networkForAddress is the network among the container's whose subnet holds ip, if exactly one does.
// It names an interface correctly even after a disconnect changed the order of the networks list.
func networkForAddress(ip string, networks []string, confs []cniNetwork) string {
	addr := net.ParseIP(ip)
	if addr == nil {
		return ""
	}
	found := ""
	for _, c := range confs {
		if !slices.Contains(networks, c.Name) {
			continue
		}
		for _, sn := range c.Subnets {
			if sn.Contains(addr) {
				if found != "" && found != c.Name {
					return ""
				}
				found = c.Name
			}
		}
	}
	return found
}

// fixContainerInspect fills in what nerdctl's container inspect lacks. obj is one element of
// `nerdctl inspect` output, decoded with UseNumber; confs are the CNI configurations.
func fixContainerInspect(obj map[string]any, confs []cniNetwork) {
	cfg := asMap(obj["Config"])
	if cfg == nil {
		cfg = map[string]any{}
		obj["Config"] = cfg
	}
	if _, ok := cfg["OpenStdin"]; !ok {
		cfg["OpenStdin"] = cfg["AttachStdin"] == true
	}
	for _, k := range []string{"Tty", "StdinOnce", "AttachStdout", "AttachStderr"} {
		if _, ok := cfg[k]; !ok {
			cfg[k] = false
		}
	}
	networks := containerNetworks(stringMap(cfg["Labels"]))
	ns := asMap(obj["NetworkSettings"])
	if ns == nil {
		return
	}
	nets := asMap(ns["Networks"])
	if nets == nil {
		return
	}
	fixed := make(map[string]any, len(nets))
	for k, v := range nets {
		name := dockerNetworkName(k, networks)
		ip, _ := asMap(v)["IPAddress"].(string)
		if n := networkForAddress(ip, networks, confs); n != "" && strings.HasPrefix(k, "unknown-") {
			name = n
		}
		if ep := asMap(v); ep != nil {
			if _, ok := ep["NetworkID"]; !ok {
				ep["NetworkID"] = name
			}
			if _, ok := ep["Aliases"]; !ok {
				ep["Aliases"] = nil
			}
		}
		fixed[name] = v
	}
	ns["Networks"] = fixed
	if hc := asMap(obj["HostConfig"]); hc != nil {
		if mode, _ := hc["NetworkMode"].(string); (mode == "" || mode == "default" || strings.HasPrefix(mode, "unknown-")) && len(networks) > 0 {
			hc["NetworkMode"] = networks[0]
		}
	}
}

// isContainerInspect tells a container from an image, network or volume in `nerdctl inspect` output.
func isContainerInspect(obj map[string]any) bool {
	_, st := obj["State"]
	_, ns := obj["NetworkSettings"]
	return st && ns
}

// decodeJSONList decodes nerdctl's inspect output: a JSON array (or one object per line).
func decodeJSONList(b []byte) ([]map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var out []map[string]any
	for {
		var v any
		if err := dec.Decode(&v); err != nil {
			if errors.Is(err, io.EOF) {
				return out, nil
			}
			return nil, err
		}
		switch x := v.(type) {
		case []any:
			for _, e := range x {
				if m := asMap(e); m != nil {
					out = append(out, m)
				}
			}
		case map[string]any:
			out = append(out, x)
		}
	}
}

// formatInspect turns `nerdctl inspect` JSON into Docker's: with format, the template per object;
// without, an indented JSON array.
func formatInspect(raw []byte, format string) ([]byte, error) {
	objs, err := decodeJSONList(raw)
	if err != nil {
		return nil, err
	}
	items := make([]any, len(objs))
	var confs []cniNetwork
	for i, o := range objs {
		if isContainerInspect(o) {
			if confs == nil {
				confs = cniConfigs()
			}
			fixContainerInspect(o, confs)
		}
		items[i] = o
	}
	if format != "" {
		return renderDockerTemplate(format, items)
	}
	b, err := json.MarshalIndent(items, "", "    ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// fixNetworkInspect adds the fields Docker has and nerdctl does not, and the containers' addresses.
// inspectContainers returns `inspect` output for the given container IDs.
func fixNetworkInspect(obj map[string]any, inspectContainers func(ids []string) ([]map[string]any, error)) {
	name, _ := obj["Name"].(string)
	ipv6 := false
	if ipam := asMap(obj["IPAM"]); ipam != nil {
		if cfgs, ok := ipam["Config"].([]any); ok {
			for _, c := range cfgs {
				if s, _ := asMap(c)["Subnet"].(string); strings.Contains(s, ":") {
					ipv6 = true
				}
			}
		}
	}
	defaults := map[string]any{"EnableIPv6": ipv6, "Driver": "bridge", "Scope": "local", "Attachable": true,
		"Internal": false, "Ingress": false, "Options": map[string]any{}}
	if name == "host" || name == "none" {
		defaults["Driver"] = name
	}
	for k, v := range defaults {
		if _, ok := obj[k]; !ok {
			obj[k] = v
		}
	}
	if _, ok := obj["Id"]; !ok {
		obj["Id"] = name
	}
	ctrs := asMap(obj["Containers"])
	if len(ctrs) == 0 || inspectContainers == nil {
		return
	}
	ids := make([]string, 0, len(ctrs))
	for id := range ctrs {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	infos, err := inspectContainers(ids)
	if err != nil {
		return
	}
	for _, info := range infos {
		id, _ := info["Id"].(string)
		ep := asMap(ctrs[id])
		if ep == nil {
			continue
		}
		fixContainerInspect(info, cniConfigs())
		net := asMap(asMap(asMap(info["NetworkSettings"])["Networks"])[name])
		if net == nil {
			continue
		}
		if ip, _ := net["IPAddress"].(string); ip != "" {
			ep["IPv4Address"] = ip + "/" + fmt.Sprint(net["IPPrefixLen"])
		}
		if ip, _ := net["GlobalIPv6Address"].(string); ip != "" {
			ep["IPv6Address"] = ip + "/" + fmt.Sprint(net["GlobalIPv6PrefixLen"])
		}
		if mac, _ := net["MacAddress"].(string); mac != "" {
			ep["MacAddress"] = mac
		}
	}
	for _, v := range ctrs {
		if ep := asMap(v); ep != nil {
			for _, k := range []string{"IPv4Address", "IPv6Address", "MacAddress", "EndpointID"} {
				if _, ok := ep[k]; !ok {
					ep[k] = ""
				}
			}
		}
	}
}

func formatNetworkInspect(raw []byte, format string, run nerdctlRunner) ([]byte, error) {
	objs, err := decodeJSONList(raw)
	if err != nil {
		return nil, err
	}
	inspect := func(ids []string) ([]map[string]any, error) {
		out, err := run(append([]string{"container", "inspect"}, ids...)...)
		if err != nil && len(out) == 0 {
			return nil, err
		}
		return decodeJSONList(out)
	}
	items := make([]any, len(objs))
	for i, o := range objs {
		fixNetworkInspect(o, inspect)
		items[i] = o
	}
	if format != "" {
		return renderDockerTemplate(format, items)
	}
	b, err := json.MarshalIndent(items, "", "    ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// dockerPsItem is one row of `docker ps` with Docker's fields. Label is a method, as in Docker
// ('{{.Label "com.docker.compose.service"}}').
type dockerPsItem struct {
	Command      string
	CreatedAt    string
	ID           string
	Image        string
	Labels       string
	LocalVolumes string
	Mounts       string
	Names        string
	Networks     string
	Platform     string `json:",omitempty"`
	Ports        string
	RunningFor   string
	Runtime      string `json:",omitempty"`
	Size         string
	State        string
	Status       string

	labels map[string]string
}

func (p dockerPsItem) Label(name string) string { return p.labels[name] }

// psFormat is what the wrapper asks nerdctl for: the row as JSON, then its labels as a map (nerdctl's
// Labels column is "k=v,…", which cannot be split back when a value holds a comma).
const psFormat = "{{json .}}\t{{json .LabelsMap}}"

// dockerState derives Docker's State from nerdctl's Status column.
func dockerState(status string) string {
	s := strings.ToLower(status)
	switch {
	case strings.HasPrefix(s, "up") && strings.Contains(s, "paused"):
		return "paused"
	case strings.HasPrefix(s, "up"):
		return "running"
	case strings.HasPrefix(s, "created"):
		return "created"
	case strings.HasPrefix(s, "exited"):
		return "exited"
	case strings.HasPrefix(s, "paused"):
		return "paused"
	case strings.HasPrefix(s, "restarting"):
		return "restarting"
	case strings.HasPrefix(s, "removing"):
		return "removing"
	case strings.HasPrefix(s, "dead"):
		return "dead"
	}
	return s
}

// dockerHumanDuration is Docker's units.HumanDuration, used for RunningFor ("5 minutes ago").
func dockerHumanDuration(d time.Duration) string {
	switch s := int(d.Seconds()); {
	case s < 1:
		return "Less than a second"
	case s == 1:
		return "1 second"
	case s < 60:
		return fmt.Sprintf("%d seconds", s)
	}
	switch m := int(d.Minutes()); {
	case m == 1:
		return "About a minute"
	case m < 60:
		return fmt.Sprintf("%d minutes", m)
	}
	switch h := int(d.Hours() + 0.5); {
	case h == 1:
		return "About an hour"
	case h < 48:
		return fmt.Sprintf("%d hours", h)
	case h < 24*7*2:
		return fmt.Sprintf("%d days", h/24)
	case h < 24*30*2:
		return fmt.Sprintf("%d weeks", h/24/7)
	case h < 24*365*2:
		return fmt.Sprintf("%d months", h/24/30)
	default:
		return fmt.Sprintf("%d years", int(d.Hours())/24/365)
	}
}

// formatPs renders `nerdctl ps --format psFormat` output as Docker's ps with format.
func formatPs(raw []byte, format string, now time.Time) ([]byte, error) {
	var items []any
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		row, labelsJSON, _ := strings.Cut(line, "\t")
		var n struct {
			Command, ID, Image, Names, Ports, Status, Runtime, Size, Platform string
			CreatedAt                                                         time.Time
		}
		if err := json.Unmarshal([]byte(row), &n); err != nil {
			return nil, fmt.Errorf("reading nerdctl ps: %v", err)
		}
		var labels map[string]string
		_ = json.Unmarshal([]byte(labelsJSON), &labels)
		keys := make([]string, 0, len(labels))
		for k := range labels {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		pairs := make([]string, len(keys))
		for i, k := range keys {
			pairs[i] = k + "=" + labels[k]
		}
		it := dockerPsItem{Command: n.Command, ID: n.ID, Image: n.Image, Names: n.Names, Ports: n.Ports, Status: n.Status,
			Runtime: n.Runtime, Size: n.Size, Platform: n.Platform, Labels: strings.Join(pairs, ","), State: dockerState(n.Status),
			Networks: strings.Join(containerNetworks(labels), ","), labels: labels}
		if !n.CreatedAt.IsZero() {
			it.CreatedAt = n.CreatedAt.Format("2006-01-02 15:04:05 -0700 MST")
			it.RunningFor = dockerHumanDuration(now.Sub(n.CreatedAt)) + " ago"
		}
		items = append(items, it)
	}
	return renderDockerTemplate(format, items)
}
