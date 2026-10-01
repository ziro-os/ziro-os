package schema

import (
	"fmt"
	"regexp"
	"strconv"
)

// Resources bounds what a plugin service or an app component may use. Every field is optional;
// an unset field means no limit. A service is placed in its own cgroup with these limits; a
// container gets the equivalent runtime flags.
type Resources struct {
	Memory string  `json:"memory,omitempty"` // hard limit: 512Mi, 1Gi, 1.5G (binary units)
	CPUs   float64 `json:"cpus,omitempty"`   // CPU time, e.g. 0.5 or 2
	PIDs   int     `json:"pids,omitempty"`   // max processes/threads
}

var sizeRe = regexp.MustCompile(`^([0-9]+(?:\.[0-9]+)?)(Ki|Mi|Gi|Ti|K|M|G|T)?$`)

// ParseSize parses a memory size ("512Mi", "1Gi", "1.5G", "1048576") into bytes. K/M/G/T are
// treated as binary units, like container runtimes do.
func ParseSize(s string) (int64, error) {
	m := sizeRe.FindStringSubmatch(s)
	if m == nil {
		return 0, fmt.Errorf("bad size %q (want e.g. 512Mi, 1Gi)", s)
	}
	n, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0, err
	}
	shift := map[string]uint{"": 0, "K": 10, "Ki": 10, "M": 20, "Mi": 20, "G": 30, "Gi": 30, "T": 40, "Ti": 40}[m[2]]
	b := n * float64(int64(1)<<shift)
	if b < 1 || b > 1<<50 {
		return 0, fmt.Errorf("size %q out of range", s)
	}
	return int64(b), nil
}

// MemoryBytes is the memory limit in bytes, 0 when unset.
func (r *Resources) MemoryBytes() int64 {
	if r == nil || r.Memory == "" {
		return 0
	}
	n, _ := ParseSize(r.Memory)
	return n
}

func (r *Resources) Validate() error {
	if r == nil {
		return nil
	}
	if r.Memory != "" {
		n, err := ParseSize(r.Memory)
		if err != nil {
			return err
		}
		if n < 16<<20 {
			return fmt.Errorf("memory %s is below the 16Mi minimum", r.Memory)
		}
	}
	if r.CPUs < 0 || r.CPUs > 1024 {
		return fmt.Errorf("bad cpus %v", r.CPUs)
	}
	if r.PIDs < 0 || (r.PIDs > 0 && r.PIDs < 8) || r.PIDs > 4194304 {
		return fmt.Errorf("bad pids %d (8 or more)", r.PIDs)
	}
	return nil
}
