package schema

import "testing"

func TestResources(t *testing.T) {
	for in, want := range map[string]int64{"512Mi": 512 << 20, "1Gi": 1 << 30, "1.5G": 3 << 29, "1048576": 1 << 20, "64M": 64 << 20} {
		if got, err := ParseSize(in); err != nil || got != want {
			t.Errorf("ParseSize(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "1GB", "-1Mi", "1 Gi", "0", "abc"} {
		if _, err := ParseSize(bad); err == nil {
			t.Errorf("ParseSize(%q) accepted", bad)
		}
	}
	if err := (&Resources{Memory: "8Mi"}).Validate(); err == nil {
		t.Error("tiny memory accepted")
	}
	if err := (&Resources{Memory: "1Gi", CPUs: 1.5, PIDs: 512}).Validate(); err != nil {
		t.Error(err)
	}
	var nilRes *Resources
	if nilRes.Validate() != nil || nilRes.MemoryBytes() != 0 {
		t.Error("nil resources")
	}
}
