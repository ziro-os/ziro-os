package cmd

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// The Docker API calls Coolify's Sentinel uses for metrics, and rename (Compose renames a container
// it recreates): GET /containers/{id}/stats, GET /system/df and POST /containers/{id}/rename. Stats
// are read from the container's cgroup v2 files and its network namespace, as Docker does.

var dockerNameR = regexp.MustCompile(`^/?[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)

func (d *dockerAPI) registerStats(mux *http.ServeMux) {
	mux.HandleFunc("GET /containers/{id}/stats", d.containerStats)
	mux.HandleFunc("POST /containers/{id}/rename", d.containerRename)
	mux.HandleFunc("GET /system/df", d.systemDF)
}

// cgroupSample is one reading of a container's cgroup and network counters.
type cgroupSample struct {
	read       time.Time
	cpuUsec    uint64 // cpu.stat usage_usec
	userUsec   uint64
	systemUsec uint64
	systemNs   uint64 // the host's total CPU time (/proc/stat), as Docker's system_cpu_usage
	memCurrent uint64
	memMax     uint64
	memStat    map[string]uint64
	pids       uint64
	ioRead     uint64
	ioWrite    uint64
	nets       map[string][2]uint64 // interface -> rx, tx bytes
	cpus       int
}

func readKV(path string) map[string]uint64 {
	out := map[string]uint64{}
	b, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), " "); ok {
			if n, err := strconv.ParseUint(strings.TrimSpace(v), 10, 64); err == nil {
				out[k] = n
			}
		}
	}
	return out
}

// hostCPUNs is the total of /proc/stat's first line in nanoseconds (USER_HZ is 100 on Linux).
func hostCPUNs() uint64 {
	b, err := os.ReadFile(filepath.Join(procRoot, "stat"))
	if err != nil {
		return 0
	}
	line, _, _ := strings.Cut(string(b), "\n")
	var total uint64
	for _, f := range strings.Fields(line)[1:] {
		n, _ := strconv.ParseUint(f, 10, 64)
		total += n
	}
	return total * 1e7
}

// netDev reads /proc/<pid>/net/dev: rx and tx bytes per interface, without lo.
func netDev(pid uint32) map[string][2]uint64 {
	out := map[string][2]uint64{}
	b, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(int(pid)), "net", "dev"))
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(b), "\n") {
		name, rest, ok := strings.Cut(line, ":")
		name = strings.TrimSpace(name)
		if !ok || name == "lo" || strings.Contains(name, "|") {
			continue
		}
		f := strings.Fields(rest)
		if len(f) >= 9 {
			rx, _ := strconv.ParseUint(f[0], 10, 64)
			tx, _ := strconv.ParseUint(f[8], 10, 64)
			out[name] = [2]uint64{rx, tx}
		}
	}
	return out
}

// sampleCgroup reads the counters of the cgroup at dir (under cgroupRoot) and the task's network.
func sampleCgroup(dir string, pid uint32) cgroupSample {
	p := filepath.Join(cgroupRoot, dir)
	s := cgroupSample{read: time.Now().UTC(), systemNs: hostCPUNs(), cpus: runtime.NumCPU()}
	cpu := readKV(filepath.Join(p, "cpu.stat"))
	s.cpuUsec, s.userUsec, s.systemUsec = cpu["usage_usec"], cpu["user_usec"], cpu["system_usec"]
	s.memCurrent = readUint(filepath.Join(p, "memory.current"))
	s.memMax = readUint(filepath.Join(p, "memory.max")) // "max" reads as 0: no limit
	s.memStat = readKV(filepath.Join(p, "memory.stat"))
	s.pids = readUint(filepath.Join(p, "pids.current"))
	if b, err := os.ReadFile(filepath.Join(p, "io.stat")); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			for _, f := range strings.Fields(line) {
				k, v, _ := strings.Cut(f, "=")
				n, _ := strconv.ParseUint(v, 10, 64)
				switch k {
				case "rbytes":
					s.ioRead += n
				case "wbytes":
					s.ioWrite += n
				}
			}
		}
	}
	if pid != 0 {
		s.nets = netDev(pid)
	}
	return s
}

// dockerStats is the /containers/{id}/stats document for a sample and the one before it (zero for one-shot).
func dockerStats(id, name string, cur, pre cgroupSample) map[string]any {
	cpuDoc := func(s cgroupSample) map[string]any {
		if s.read.IsZero() {
			return map[string]any{"cpu_usage": map[string]any{"total_usage": 0, "usage_in_kernelmode": 0, "usage_in_usermode": 0},
				"system_cpu_usage": 0, "online_cpus": 0, "throttling_data": map[string]any{}}
		}
		return map[string]any{
			"cpu_usage":        map[string]any{"total_usage": s.cpuUsec * 1000, "usage_in_kernelmode": s.systemUsec * 1000, "usage_in_usermode": s.userUsec * 1000},
			"system_cpu_usage": s.systemNs, "online_cpus": s.cpus, "throttling_data": map[string]any{},
		}
	}
	limit := cur.memMax
	if limit == 0 {
		limit = uint64(inspectSystem().TotalMemMB) << 20
	}
	nets := map[string]any{}
	for ifn, v := range cur.nets {
		nets[ifn] = map[string]any{"rx_bytes": v[0], "tx_bytes": v[1], "rx_packets": 0, "tx_packets": 0, "rx_errors": 0, "tx_errors": 0, "rx_dropped": 0, "tx_dropped": 0}
	}
	preread := "0001-01-01T00:00:00Z"
	if !pre.read.IsZero() {
		preread = pre.read.Format(time.RFC3339Nano)
	}
	return map[string]any{
		"id": id, "name": "/" + strings.TrimPrefix(name, "/"),
		"read": cur.read.Format(time.RFC3339Nano), "preread": preread,
		"pids_stats":   map[string]any{"current": cur.pids},
		"cpu_stats":    cpuDoc(cur),
		"precpu_stats": cpuDoc(pre),
		"memory_stats": map[string]any{"usage": cur.memCurrent, "limit": limit, "stats": cur.memStat},
		"blkio_stats": map[string]any{"io_service_bytes_recursive": []map[string]any{
			{"major": 0, "minor": 0, "op": "read", "value": cur.ioRead}, {"major": 0, "minor": 0, "op": "write", "value": cur.ioWrite}}},
		"networks": nets,
	}
}

// containerCgroup finds a running container's cgroup (its spec's cgroupsPath) and task pid.
func (d *dockerAPI) containerCgroup(r *http.Request, id string) (cgroup, name, fullID string, pid uint32, err error) {
	c := d.ctrd
	if c == nil {
		c = newCtrdClient(containerdSocket, containerdNamespace())
	}
	ct, err := findNerdctlContainer(r.Context(), c, id)
	if err != nil {
		return "", "", "", 0, err
	}
	var spec struct {
		Linux struct {
			CgroupsPath string `json:"cgroupsPath"`
		} `json:"linux"`
	}
	_ = json.Unmarshal(ct.Spec, &spec)
	cg := spec.Linux.CgroupsPath
	if strings.Contains(cg, ":") { // systemd form "slice:prefix:name"
		parts := strings.Split(cg, ":")
		cg = filepath.Join(parts[0], parts[1]+"-"+parts[2]+".scope")
	}
	if t, terr := c.Task(r.Context(), ct.ID); terr == nil && t.Status == ctrdTaskRunning {
		pid = t.Pid
	}
	return cg, ct.Labels["nerdctl/name"], ct.ID, pid, nil
}

func (d *dockerAPI) containerStats(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !dockerIDRe.MatchString(id) {
		dockerError(w, http.StatusNotFound, "no such container")
		return
	}
	cg, name, full, pid, err := d.containerCgroup(r, id)
	if err != nil {
		d.fail(w, err)
		return
	}
	q := r.URL.Query()
	stream := q.Get("stream") != "0" && q.Get("stream") != "false"
	oneShot := q.Get("one-shot") == "1" || q.Get("one-shot") == "true"
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	if !stream {
		pre := cgroupSample{}
		if !oneShot { // Docker takes two samples a second apart so a client can compute CPU %
			pre = sampleCgroup(cg, pid)
			select {
			case <-r.Context().Done():
				return
			case <-time.After(time.Second):
			}
		}
		_ = enc.Encode(dockerStats(full, name, sampleCgroup(cg, pid), pre))
		return
	}
	pre := cgroupSample{}
	for {
		cur := sampleCgroup(cg, pid)
		if err := enc.Encode(dockerStats(full, name, cur, pre)); err != nil {
			return
		}
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		pre = cur
		select {
		case <-r.Context().Done():
			return
		case <-time.After(time.Second):
		}
	}
}

func (d *dockerAPI) containerRename(w http.ResponseWriter, r *http.Request) {
	id, name := r.PathValue("id"), r.URL.Query().Get("name")
	if !dockerIDRe.MatchString(id) {
		dockerError(w, http.StatusNotFound, "no such container")
		return
	}
	if !dockerNameR.MatchString(name) {
		dockerError(w, http.StatusBadRequest, "invalid container name")
		return
	}
	if _, err := d.run(r.Context(), "rename", id, strings.TrimPrefix(name, "/")); err != nil {
		d.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// systemDF is GET /system/df: images, containers and volumes with their sizes, from nerdctl's lists.
func (d *dockerAPI) systemDF(w http.ResponseWriter, r *http.Request) {
	rows := func(args ...string) []map[string]any {
		out, err := d.run(r.Context(), args...)
		if err != nil {
			return nil
		}
		var list []map[string]any
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			var m map[string]any
			if json.Unmarshal([]byte(line), &m) == nil {
				list = append(list, m)
			}
		}
		return list
	}
	str := func(m map[string]any, k string) string { s, _ := m[k].(string); return s }
	images, layers := []map[string]any{}, int64(0)
	for _, im := range rows("images", "--format", "{{json .}}") {
		size := parseHumanSize(str(im, "Size"))
		layers += size
		tag := str(im, "Repository") + ":" + str(im, "Tag")
		images = append(images, map[string]any{"Id": str(im, "ID"), "RepoTags": []string{tag}, "Size": size, "SharedSize": -1, "Containers": -1, "Created": 0})
	}
	containers := []map[string]any{}
	for _, c := range rows("ps", "-a", "--size", "--format", "{{json .}}") {
		rw, root := sizeOf(str(c, "Size"))
		containers = append(containers, map[string]any{"Id": str(c, "ID"), "Names": []string{"/" + str(c, "Names")}, "Image": str(c, "Image"),
			"State": dockerState(str(c, "Status")), "Status": str(c, "Status"), "SizeRw": rw, "SizeRootFs": root})
	}
	volumes := []map[string]any{}
	for _, v := range rows("volume", "ls", "--size", "--format", "{{json .}}") {
		volumes = append(volumes, map[string]any{"Name": str(v, "Name"), "Driver": "local", "Mountpoint": str(v, "Mountpoint"),
			"UsageData": map[string]any{"Size": parseHumanSize(str(v, "Size")), "RefCount": -1}})
	}
	dockerJSON(w, map[string]any{"LayersSize": layers, "Images": images, "Containers": containers, "Volumes": volumes, "BuildCache": []any{}})
}

// sizeOf parses `ps --size` output ("1.2kB (virtual 7.8MB)") into Docker's SizeRw and SizeRootFs.
func sizeOf(s string) (rw, root int64) {
	a, b, _ := strings.Cut(s, "(virtual")
	return parseHumanSize(a), parseHumanSize(strings.TrimSuffix(strings.TrimSpace(b), ")"))
}
