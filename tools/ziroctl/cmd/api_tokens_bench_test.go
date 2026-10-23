package cmd

import (
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// Authenticating a request: a file stat instead of reading and parsing the token file.
func BenchmarkAPIIdentity(b *testing.B) {
	old := apiTokensFile
	apiTokensFile = filepath.Join(b.TempDir(), "tokens.json")
	defer func() { apiTokensFile = old }()
	var tok string
	for i := 0; i < 50; i++ {
		tok, _, _ = createAPIToken("t"+strconv.Itoa(i), "viewer", 0)
	}
	now := time.Now()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, _, ok := apiIdentity(tok, "", now); !ok {
			b.Fatal("rejected")
		}
	}
}
