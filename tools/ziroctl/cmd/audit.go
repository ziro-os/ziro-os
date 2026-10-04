package cmd

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	sdkapi "github.com/ziro-os/ziro-os/sdk/api"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

// Tamper-evident audit log: append-only JSONL where every record carries the SHA-256 of the
// previous line, so editing or deleting a record breaks the chain at that point
// (`ziroctl audit verify`). It lives in /var/log/ziro/, outside the /var/log/*.log copy+truncate
// rotator, and rotates itself by rename so the chain continues across files.
// ponytail: root can still rewrite the whole chain; ship the log off-host (syslog/SIEM) or
// record `audit verify`'s head hash externally when that threat matters.
var auditPath = "/var/log/ziro/audit.log"

const (
	auditMaxSize = 10 << 20
	auditKeep    = 10
	auditGenesis = "0000000000000000000000000000000000000000000000000000000000000000"
)

type auditRecord = sdkapi.AuditRecord

func lineHash(line []byte) string {
	sum := sha256.Sum256(line)
	return hex.EncodeToString(sum[:])
}

// lastLine returns the final non-empty line of path (records are small; the tail is enough).
func lastLine(path string) []byte {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil
	}
	off := fi.Size() - 64<<10
	if off < 0 {
		off = 0
	}
	buf := make([]byte, fi.Size()-off)
	if _, err := f.ReadAt(buf, off); err != nil && err != io.EOF {
		return nil
	}
	lines := strings.Split(strings.TrimRight(string(buf), "\n"), "\n")
	return []byte(lines[len(lines)-1])
}

// auditLog appends one record. Records are bounded and control characters stripped; callers
// never pass secret values (see redactArgs).
func auditLog(actor, source, action, target string, err error) error {
	if e := os.MkdirAll(filepath.Dir(auditPath), 0700); e != nil {
		return e
	}
	f, e := os.OpenFile(auditPath, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	// flock serialises the CLI, cluster-master and ziro-api writing concurrently.
	if e := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); e != nil {
		return e
	}
	if fi, e := f.Stat(); e == nil && fi.Size() >= auditMaxSize {
		for i := auditKeep - 1; i >= 1; i-- {
			_ = os.Rename(auditPath+"."+strconv.Itoa(i), auditPath+"."+strconv.Itoa(i+1))
		}
		if e := os.Rename(auditPath, auditPath+".1"); e != nil {
			return e
		}
		f.Close()
		return auditLog(actor, source, action, target, err)
	}
	prev := auditGenesis
	if l := lastLine(auditPath); len(l) > 0 {
		prev = lineHash(l)
	} else if l := lastLine(auditPath + ".1"); len(l) > 0 {
		prev = lineHash(l)
	}
	res := "ok"
	if err != nil {
		res = "error: " + sanitizeLabel(err.Error(), 300)
	}
	line, e := json.Marshal(auditRecord{
		TS: time.Now().UTC().Format(time.RFC3339Nano), Actor: sanitizeLabel(actor, 128), Source: sanitizeLabel(source, 128),
		Action: sanitizeLabel(action, 128), Target: sanitizeLabel(target, 1024), Result: res, Prev: prev,
	})
	if e != nil {
		return e
	}
	_, e = f.Write(append(line, '\n'))
	return e
}

// auditFiles lists the log generations oldest first.
func auditFiles() []string {
	var files []string
	for i := auditKeep; i >= 1; i-- {
		if p := auditPath + "." + strconv.Itoa(i); fileExists(p) {
			files = append(files, p)
		}
	}
	if fileExists(auditPath) {
		files = append(files, auditPath)
	}
	return files
}

// verifyAudit walks the chain across all generations. The oldest retained record may point
// at a rotated-away file, so only links inside the retained window are checked.
func verifyAudit(files []string) (records int, head string, err error) {
	var prevLine []byte
	for _, p := range files {
		f, e := os.Open(p)
		if e != nil {
			return records, "", e
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		n := 0
		for sc.Scan() {
			n++
			line := sc.Bytes()
			var r auditRecord
			if e := json.Unmarshal(line, &r); e != nil {
				f.Close()
				return records, "", fmt.Errorf("%s:%d: not a valid record", p, n)
			}
			if prevLine != nil && r.Prev != lineHash(prevLine) {
				f.Close()
				return records, "", fmt.Errorf("%s:%d: chain broken (a record before it was changed or removed)", p, n)
			}
			prevLine = append(prevLine[:0], line...)
			records++
		}
		f.Close()
		if e := sc.Err(); e != nil {
			return records, "", fmt.Errorf("%s: %w", p, e)
		}
	}
	if prevLine != nil {
		head = lineHash(prevLine)
	}
	return records, head, nil
}

// ---- CLI integration ----

// Leaf commands that only read; everything else run as root is audited.
var auditReadOnly = map[string]bool{
	"status": true, "list": true, "ls": true, "nodes": true, "services": true, "endpoints": true, "logs": true,
	"ps": true, "images": true, "inspect": true, "search": true, "usage": true, "version": true, "scan": true,
	"monitor": true, "motd": true, "doctor": true, "audit": true, "log": true, "verify": true, "help": true,
	"completion": true, "token": true,
}

// sensitiveFlags hold credentials; their values are never recorded.
var sensitiveFlags = map[string]bool{"token": true, "t": true, "password": true, "passphrase": true, "private-key": true, "key": true}

// redactArgs keeps what an auditor needs (command, names, images, counts) and drops values
// that may be secret: KEY=VALUE pairs keep only KEY, credential flags lose their value.
func redactArgs(args []string) []string {
	out := make([]string, 0, len(args))
	redactNext := false
	for _, a := range args {
		switch {
		case redactNext:
			a, redactNext = "<redacted>", false
		case strings.Contains(a, "zr1_"): // a router key, wherever it appears
			a = "<redacted>"
		case strings.HasPrefix(a, "-"):
			name, val, hasVal := strings.Cut(strings.TrimLeft(a, "-"), "=")
			if sensitiveFlags[name] {
				if hasVal {
					a = a[:strings.Index(a, "=")+1] + "<redacted>"
				} else {
					redactNext = true
				}
			} else if hasVal && strings.Contains(val, "=") {
				k, _, _ := strings.Cut(val, "=")
				a = a[:strings.Index(a, "=")+1] + k + "=<redacted>"
			}
		case strings.Contains(a, "="):
			k, _, _ := strings.Cut(a, "=")
			a = k + "=<redacted>"
		}
		out = append(out, a)
	}
	return out
}

func cliActor() (actor, source string) {
	actor = "uid:" + strconv.Itoa(os.Getuid())
	if u, err := user.Current(); err == nil {
		actor += "(" + u.Username + ")"
	}
	if s := os.Getenv("SUDO_USER"); s != "" {
		actor += " sudo:" + s
	}
	if c := strings.Fields(os.Getenv("SSH_CONNECTION")); len(c) > 0 {
		source = "ssh:" + c[0]
	}
	return actor, source
}

// auditCommand records a mutating CLI invocation after it ran. Hidden daemon/cron commands
// and read-only leaves are skipped so polling tools cannot flood the log.
func auditCommand(c *cobra.Command, err error) {
	if c == nil || c.Hidden || auditReadOnly[c.Name()] || os.Geteuid() != 0 || !c.Runnable() {
		return
	}
	if h, _ := c.Flags().GetBool("help"); h {
		return
	}
	path := strings.TrimPrefix(c.CommandPath(), rootCmd.Name()+" ")
	actor, source := cliActor()
	if e := auditLog(actor, source, path, strings.Join(redactArgs(os.Args[1:]), " "), err); e != nil {
		fmt.Fprintf(os.Stderr, "⚠ audit log: %v\n", e)
	}
}

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Read and verify the tamper-evident audit log",
	Example: `  ziroctl audit log --since 24h
  ziroctl audit verify`,
}

var auditSince time.Duration

var auditLogCmd = &cobra.Command{
	Use:   "log",
	Short: "Show audit records, newest last",
	Example: `  ziroctl audit log
  ziroctl audit log --since 2h`,
	RunE: func(cmd *cobra.Command, args []string) error {
		var recs []auditRecord
		cutoff := time.Time{}
		if auditSince > 0 {
			cutoff = time.Now().Add(-auditSince)
		}
		for _, p := range auditFiles() {
			f, err := os.Open(p)
			if err != nil {
				return err
			}
			sc := bufio.NewScanner(f)
			sc.Buffer(make([]byte, 64<<10), 1<<20)
			for sc.Scan() {
				var r auditRecord
				if json.Unmarshal(sc.Bytes(), &r) != nil {
					continue
				}
				if t, err := time.Parse(time.RFC3339Nano, r.TS); err == nil && t.Before(cutoff) {
					continue
				}
				recs = append(recs, r)
			}
			f.Close()
		}
		if recs == nil {
			recs = []auditRecord{}
		}
		return printResult(recs, func() {
			for _, r := range recs {
				src := ""
				if r.Source != "" {
					src = " [" + r.Source + "]"
				}
				fmt.Printf("%s %s%s %s %s -> %s\n", r.TS, r.Actor, src, r.Action, r.Target, r.Result)
			}
		})
	},
}

var auditVerifyCmd = &cobra.Command{
	Use:     "verify",
	Short:   "Check the audit hash chain for changed records",
	Example: `  ziroctl audit verify`,
	RunE: func(cmd *cobra.Command, args []string) error {
		n, head, err := verifyAudit(auditFiles())
		if err != nil {
			return err
		}
		return printResult(map[string]interface{}{"status": "ok", "records": n, "head": head}, func() {
			fmt.Printf("✓ audit chain intact: %d records, head sha256:%s\n", n, head)
		})
	},
}

func init() {
	auditLogCmd.Flags().DurationVar(&auditSince, "since", 0, "Only records newer than this (e.g. 24h)")
	auditCmd.AddCommand(auditLogCmd, auditVerifyCmd)
	rootCmd.AddCommand(auditCmd)
}
