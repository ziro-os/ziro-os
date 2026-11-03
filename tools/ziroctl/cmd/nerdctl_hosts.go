package cmd

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	types100 "github.com/containernetworking/cni/pkg/types/100"
)

// nerdctl's hosts store, which makes containers on a network resolve each other by name: per
// container, <data store>/etchosts/<namespace>/<id>/meta.json (its networks and names) and hosts
// (bind-mounted as its /etc/hosts). Each change rewrites the <nerdctl> region of every hosts file from
// all the meta files. This is the same store and format as nerdctl 2.2.1 (pkg/dnsutil/hostsstore),
// kept here so that `docker network connect` of a running container updates name resolution without
// linking nerdctl's packages (and rootlesskit, which they pull in).

const (
	nerdctlHostsMarkerBegin = "<nerdctl>"
	nerdctlHostsMarkerEnd   = "</nerdctl>"
	nerdctlDefaultNetwork   = "bridge"
)

// nerdctlHostsMeta is hostsstore.Meta.
type nerdctlHostsMeta struct {
	ID         string
	Networks   map[string]*types100.Result
	Hostname   string
	ExtraHosts map[string]string // host:ip
	Name       string
	Domainname string
}

type nerdctlHostsStore struct{ dir string } // <data store>/etchosts/<namespace>

func newNerdctlHostsStore(dataStore, namespace string) (*nerdctlHostsStore, error) {
	if dataStore == "" || namespace == "" {
		return nil, fmt.Errorf("hosts store: no data store or namespace")
	}
	dir := filepath.Join(dataStore, "etchosts", namespace)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &nerdctlHostsStore{dir: dir}, nil
}

// withLock holds the exclusive flock on the store directory, the lock nerdctl's store takes.
func (s *nerdctlHostsStore) withLock(fn func() error) error {
	f, err := os.Open(s.dir)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	return fn()
}

func (s *nerdctlHostsStore) meta(id string) (nerdctlHostsMeta, bool) {
	var m nerdctlHostsMeta
	b, err := os.ReadFile(filepath.Join(s.dir, id, "meta.json"))
	if err != nil || json.Unmarshal(b, &m) != nil {
		return nerdctlHostsMeta{}, false
	}
	return m, true
}

// update changes the meta of a container (fn gets the current one, or a zero one) and rewrites all
// hosts files.
func (s *nerdctlHostsStore) update(id string, fn func(m *nerdctlHostsMeta)) error {
	return s.withLock(func() error {
		m, ok := s.meta(id)
		if !ok {
			m = nerdctlHostsMeta{ID: id}
		}
		fn(&m)
		b, err := json.Marshal(m)
		if err != nil {
			return err
		}
		dir := filepath.Join(s.dir, id)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		hosts := filepath.Join(dir, "hosts")
		if _, err := os.Stat(hosts); os.IsNotExist(err) {
			if err := os.WriteFile(hosts, nil, 0o644); err != nil {
				return err
			}
			_ = os.Chmod(hosts, 0o644)
		}
		tmp := filepath.Join(dir, ".meta.json.tmp")
		if err := os.WriteFile(tmp, b, 0o600); err != nil {
			return err
		}
		if err := os.Rename(tmp, filepath.Join(dir, "meta.json")); err != nil {
			return err
		}
		return s.writeAll()
	})
}

// hostsLine is nerdctl's createLine: "<hostname>.<domain> <hostname> <hostname>.<net> <name> <name>.<net>"
// for a container on a network the reader is on too.
func hostsLine(network string, m *nerdctlHostsMeta, mine map[string]bool) []string {
	if !mine[network] {
		return nil
	}
	var line []string
	if m.Domainname != "" {
		line = append(line, m.Hostname+"."+m.Domainname)
	}
	bases := []string{m.Hostname}
	if m.Name != "" {
		bases = append(bases, m.Name)
	}
	for _, b := range bases {
		line = append(line, b)
		if network != nerdctlDefaultNetwork {
			line = append(line, b+"."+network)
		}
	}
	return line
}

// keepUnmarked is parseHostsButSkipMarkedRegion: the lines of a hosts file outside the <nerdctl>
// region, without comments and loopback entries.
func keepUnmarked(w io.Writer, r io.Reader) error {
	sc := bufio.NewScanner(r)
	skip := false
LINE:
	for sc.Scan() {
		line := strings.ReplaceAll(strings.Trim(sc.Text(), " \t"), "\t", " ")
		sawEnd := false
		if strings.HasPrefix(line, "#") {
			switch strings.TrimSpace(line[1:]) {
			case nerdctlHostsMarkerBegin:
				skip = true
			case nerdctlHostsMarkerEnd:
				sawEnd = true
			}
		}
		if !skip {
			if len(line) == 0 || line[0] == ';' || line[0] == '#' {
				continue
			}
			pieces := strings.SplitN(line, " ", 2)
			if len(pieces) > 1 && len(pieces[0]) > 0 {
				if pieces[0] == "127.0.0.1" || pieces[0] == "::1" {
					continue LINE
				}
				if names := strings.Fields(pieces[1]); len(names) > 0 {
					for _, n := range names {
						if strings.HasPrefix(n, "#") {
							continue LINE
						}
					}
					fmt.Fprintln(w, line)
				}
			}
		}
		if sawEnd {
			skip = false
		}
	}
	return sc.Err()
}

// renderHosts is the hosts file of one container, from its current content and every meta.
func renderHosts(current []byte, me *nerdctlHostsMeta, metas []*nerdctlHostsMeta) []byte {
	type addr struct {
		ip, network string
		meta        *nerdctlHostsMeta
	}
	var addrs []addr
	for _, m := range metas {
		for net, res := range m.Networks {
			if res == nil {
				continue
			}
			for _, ipc := range res.IPs {
				if ip := ipc.Address.IP; ip != nil && !ip.IsLoopback() && !ip.IsUnspecified() {
					addrs = append(addrs, addr{ip.String(), net, m})
				}
			}
		}
	}
	slices.SortFunc(addrs, func(a, b addr) int { return strings.Compare(a.ip, b.ip) })
	mine := map[string]bool{}
	for n := range me.Networks {
		mine[n] = true
	}
	var buf bytes.Buffer
	_ = keepUnmarked(&buf, bytes.NewReader(current))
	fmt.Fprintf(&buf, "# %s\n", nerdctlHostsMarkerBegin)
	buf.WriteString("127.0.0.1	localhost localhost.localdomain\n")
	buf.WriteString("::1		localhost localhost.localdomain\n")
	hosts := make([]string, 0, len(me.ExtraHosts))
	for h := range me.ExtraHosts {
		hosts = append(hosts, h)
	}
	slices.Sort(hosts)
	for _, h := range hosts {
		fmt.Fprintf(&buf, "%-15s %s\n", me.ExtraHosts[h], h)
	}
	seen := map[string]bool{}
	for _, a := range addrs {
		if seen[a.ip] {
			continue // one line per address, as nerdctl's map by IP
		}
		seen[a.ip] = true
		if line := hostsLine(a.network, a.meta, mine); len(line) > 0 {
			fmt.Fprintf(&buf, "%-15s %s\n", a.ip, strings.Join(line, " "))
		}
	}
	fmt.Fprintf(&buf, "# %s\n", nerdctlHostsMarkerEnd)
	return buf.Bytes()
}

// writeAll is updateAllHosts. Hosts files are rewritten in place: each is bind-mounted into its
// container, and a rename would leave the container with the old file.
func (s *nerdctlHostsStore) writeAll() error {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return err
	}
	var metas []*nerdctlHostsMeta
	byID := map[string]*nerdctlHostsMeta{}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if m, ok := s.meta(e.Name()); ok {
			mm := m
			metas = append(metas, &mm)
			byID[e.Name()] = &mm
		}
	}
	for id, me := range byID {
		path := filepath.Join(s.dir, id, "hosts")
		current, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		_ = os.WriteFile(path, renderHosts(current, me, metas), 0o644)
		_ = os.Chmod(path, 0o644)
	}
	return nil
}
