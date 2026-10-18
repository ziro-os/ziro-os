package cmd

import (
	"bytes"
	"io"
	"regexp"
	"strconv"
	"sync"
)

// nerdctl exec exits 1 when the command fails and logs the real status on its stderr:
// time="..." level=fatal msg="exec failed with exit code N". exitFilter passes everything else
// through unchanged and keeps N, so callers report the command's own exit code.
type exitFilter struct {
	mu   sync.Mutex
	w    io.Writer
	buf  []byte
	code int // -1 until seen
}

var (
	nerdctlExitRe  = regexp.MustCompile(`level=fatal msg="exec failed with exit code ([0-9]+)"`)
	nerdctlLogHead = []byte(`time="`)
)

func newExitFilter(w io.Writer) *exitFilter { return &exitFilter{w: w, code: -1} }

func (f *exitFilter) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.buf = append(f.buf, p...)
	for {
		i := bytes.IndexByte(f.buf, '\n')
		if i < 0 {
			break
		}
		line := f.buf[:i+1]
		if m := nerdctlExitRe.FindSubmatch(line); m != nil && bytes.HasPrefix(line, nerdctlLogHead) {
			f.code, _ = strconv.Atoi(string(m[1]))
		} else if _, err := f.w.Write(line); err != nil {
			return len(p), err
		}
		f.buf = f.buf[i+1:]
	}
	// Hold back only what may be the start of nerdctl's own log line; send the rest now
	// (prompts without a newline must not wait).
	if len(f.buf) > 0 && !bytes.HasPrefix(f.buf, nerdctlLogHead) && !bytes.HasPrefix(nerdctlLogHead, f.buf) || len(f.buf) > 4096 {
		_, err := f.w.Write(f.buf)
		f.buf = f.buf[:0]
		return len(p), err
	}
	return len(p), nil
}

// finish flushes what is held back and returns the command's exit code, given nerdctl's.
func (f *exitFilter) finish(nerdctlCode int) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.buf) > 0 {
		_, _ = f.w.Write(f.buf)
		f.buf = nil
	}
	if nerdctlCode == 1 && f.code >= 0 {
		return f.code
	}
	return nerdctlCode
}
