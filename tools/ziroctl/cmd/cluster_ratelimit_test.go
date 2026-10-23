package cmd

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

// Many nodes behind one NAT address each get their own budget; one credential is still limited.
func TestClusterRateLimitPerCredential(t *testing.T) {
	s := newClusterServer()
	h := s.wrap(func(r *http.Request) (interface{}, error) { return map[string]string{"ok": "1"}, nil })
	call := func(tok string) int {
		r := httptest.NewRequest("POST", "/cluster/v1/heartbeat", nil)
		r.RemoteAddr = "203.0.113.7:4000" // the same NAT address for everyone
		r.Header.Set("Authorization", "Bearer "+tok)
		w := httptest.NewRecorder()
		h(w, r)
		return w.Code
	}
	for n := 0; n < 50; n++ { // 50 nodes, 6 heartbeats a minute each
		for i := 0; i < 6; i++ {
			if code := call("node-" + strconv.Itoa(n)); code != 200 {
				t.Fatalf("node %d heartbeat %d: %d", n, i, code)
			}
		}
	}
	limited := false
	for i := 0; i < 200; i++ {
		if call("chatty") == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Error("one credential isn't rate limited")
	}
}
