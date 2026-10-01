package cmd

import (
	"strings"
	"testing"
)

func TestIntegrityCheck(t *testing.T) {
	h := func(c byte) string { return strings.Repeat(string(c), 64) }
	ms := parseIMAMeasurements(strings.NewReader(
		"10 aa ima-ng sha256:" + h('0') + " boot_aggregate\n" +
			"10 aa ima-ng sha256:" + h('1') + " /usr/bin/ziroctl\n" +
			"10 aa ima-ng sha256:" + h('1') + " /usr/bin/ziroctl\n" + // duplicates count once
			"10 aa ima-ng sha256:" + h('2') + " /bin/busybox\n" + // tampered
			"10 aa ima-ng sha256:" + h('3') + " /usr/sbin/clamd\n" + // from a package, intact
			"10 aa ima-ng sha256:" + h('4') + " /usr/bin/garage\n" + // package file changed on disk
			"10 aa ima-ng sha256:" + h('5') + " /usr/local/bin/dropper\n" + // unknown
			"10 aa ima-ng sha256:" + h('6') + " /srv/data/tool\n" + // outside system paths
			"10 aa ima-sig sha256:" + h('7') + " /ignored\n"))
	baseline := readBaseline(strings.NewReader(h('1') + "  /usr/bin/ziroctl\n" + h('9') + "  /bin/busybox\n"))
	owned := apkOwnedFiles(strings.NewReader("P:clamav-daemon\nF:usr/sbin\nR:clamd\nZ:Q1x\n\nP:garage\nF:usr/bin\nR:garage\nZ:Q1y\n"))
	if !owned["/usr/sbin/clamd"] || !owned["/usr/bin/garage"] || len(owned) != 2 {
		t.Fatalf("apk db %v", owned)
	}
	// apk audit's verdict: garage was changed after installation.
	modified := parseAPKAudit("U usr/bin/garage\nA usr/bin/other\n")
	if !modified["/usr/bin/garage"] || modified["/usr/bin/other"] {
		t.Fatalf("audit parse %v", modified)
	}
	orig := fileSHA256
	defer func() { fileSHA256 = orig }()
	fileSHA256 = func(p string) (string, error) {
		switch p {
		case "/usr/sbin/clamd":
			return h('3'), nil
		case "/usr/bin/garage":
			return h('4'), nil
		}
		return "", nil
	}
	rep := checkIntegrity(ms, baseline, owned, modified)
	if rep.Measured != 6 || rep.Image != 1 || rep.Package != 1 || rep.Other != 1 || len(rep.Findings) != 3 {
		t.Fatalf("%+v", rep)
	}
	got := map[string]string{}
	for _, f := range rep.Findings {
		got[f.Path] = f.Reason
	}
	if got["/bin/busybox"] != "differs from the OS image" || got["/usr/bin/garage"] != "differs from its package" ||
		!strings.Contains(got["/usr/local/bin/dropper"], "not part of") {
		t.Fatalf("findings %v", got)
	}
}
