package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"sync"
)

// Heartbeat deltas: the big parts of a heartbeat answer (a node's assignments, the mesh peers, the
// app endpoints, ...) are the same from one heartbeat to the next until something changes, but
// were sent in full every 10 s to every node (about 47 KB per answer at 100 nodes, growing with
// nodes²). The master now sends a hash with each of them; the agent echoes the hashes it holds
// (Have), and the master leaves out a part whose hash the agent already has (Same).
//
// Compatible both ways: an older agent sends no Have and gets everything; an older master
// ignores Have and sends everything (and no Same).

// deltaFields are the parts that can be left out, by name, as pointers into r.
func (r *heartbeatResponse) deltaFields() map[string]any {
	return map[string]any{
		"assignments": &r.Assignments,
		"peers":       &r.Peers,
		"endpoints":   &r.Endpoints,
		"pod_dns":     &r.PodDNS,
		"dns_records": &r.DNSRecords,
		"policy":      &r.Policy,
		"egress":      &r.Egress,
		"nfs_exports": &r.NFSExports,
		"nfs_mounts":  &r.NFSMounts,
	}
}

func deltaHash(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:12])
}

// omitUnchanged (master) hashes each part and leaves out those the agent already holds.
func (r *heartbeatResponse) omitUnchanged(have map[string]string) {
	r.Hashes = map[string]string{}
	for name, p := range r.deltaFields() {
		v := reflect.ValueOf(p).Elem()
		b, err := json.Marshal(v.Interface())
		if err != nil {
			continue // sent in full, without a hash
		}
		h := deltaHash(b)
		if have[name] == h {
			v.SetZero()
			r.Same = append(r.Same, name)
			continue
		}
		r.Hashes[name] = h
	}
}

// heartbeatDelta (agent) keeps the parts it received, to fill in what the master leaves out.
type heartbeatDelta struct {
	mu     sync.Mutex
	parts  map[string][]byte // name -> the part as received (JSON)
	hashes map[string]string
}

var errDeltaMissing = errors.New("the master left out a part this node doesn't hold")

// have is what the agent tells the master it holds.
func (d *heartbeatDelta) have() map[string]string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.hashes) == 0 {
		return nil
	}
	out := make(map[string]string, len(d.hashes))
	for k, v := range d.hashes {
		out[k] = v
	}
	return out
}

// fill completes an answer: parts the master left out come from what was kept, parts it sent
// (with their hash) are kept for next time. A left-out part this node doesn't hold is an error:
// the answer must not be used (an empty assignment list would remove every container).
func (d *heartbeatDelta) fill(r *heartbeatResponse) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.parts == nil {
		d.parts, d.hashes = map[string][]byte{}, map[string]string{}
	}
	fields := r.deltaFields()
	for _, name := range r.Same {
		p, ok := fields[name]
		b, held := d.parts[name]
		if !ok || !held {
			return errDeltaMissing
		}
		if err := json.Unmarshal(b, p); err != nil {
			return err
		}
	}
	for name, h := range r.Hashes {
		p, ok := fields[name]
		if !ok {
			continue
		}
		b, err := json.Marshal(reflect.ValueOf(p).Elem().Interface())
		if err != nil {
			continue
		}
		d.parts[name], d.hashes[name] = b, h
	}
	return nil
}

// reset forgets everything (the next answer is complete).
func (d *heartbeatDelta) reset() {
	d.mu.Lock()
	d.parts, d.hashes = nil, nil
	d.mu.Unlock()
}
