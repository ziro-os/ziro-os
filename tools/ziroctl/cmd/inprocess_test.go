package cmd

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// An in-process answer streams: the response is back before the handler is done, the body
// arrives as it is written, and identity reaches the handler through the context.
func TestInProcessStreams(t *testing.T) {
	release := make(chan struct{})
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Who", apiTokenName(r)+"/"+apiRole(r)+"/"+r.RemoteAddr)
		w.WriteHeader(http.StatusAccepted)
		io.WriteString(w, "first\n")
		<-release
		io.WriteString(w, "second\n")
	})
	c := &http.Client{Transport: inProcess{h: h, ctx: asHostRoot}}
	resp, err := c.Get("http://x/y")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 202 || resp.Header.Get("X-Who") != "root/admin/127.0.0.1:0" {
		t.Fatalf("%d %v", resp.StatusCode, resp.Header)
	}
	br := bufio.NewReader(resp.Body)
	if l, _ := br.ReadString('\n'); l != "first\n" {
		t.Fatalf("first line %q", l)
	}
	close(release)
	if rest, _ := io.ReadAll(br); string(rest) != "second\n" {
		t.Fatalf("rest %q", rest)
	}

	// A handler that never writes still answers 200; a panic becomes a 500, not a crash.
	resp, err = (&http.Client{Transport: inProcess{h: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})}}).Get("http://x/")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("empty handler: %v %v", resp, err)
	}
	resp, err = (&http.Client{Transport: inProcess{h: http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom") })}}).Get("http://x/")
	if err != nil || resp.StatusCode != 500 {
		t.Fatalf("panic: %v %v", resp, err)
	}

	// A caller that gives up before the headers gets its context error, and the handler is
	// released (its writes fail) instead of leaking.
	stuck := make(chan error, 1)
	slow := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
		_, err := w.Write([]byte(strings.Repeat("x", 10)))
		stuck <- err
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", "http://x/", nil)
	if _, err := (&http.Client{Transport: inProcess{h: slow}}).Do(req); err == nil {
		t.Fatal("no error after the deadline")
	}
	select {
	case err := <-stuck:
		if err == nil {
			t.Error("the handler's write after the caller left succeeded")
		}
	case <-time.After(2 * time.Second):
		t.Error("the handler is stuck")
	}
}

// A daemon that predates a request answers with its mux's bare 404: say what to do about it.
func TestDaemonDecodeOldDaemon(t *testing.T) {
	c := &http.Client{Transport: inProcess{h: http.NotFoundHandler()}}
	resp, err := c.Get("http://ziro-sandboxd/v1/sandboxes/abc/stats")
	if err != nil {
		t.Fatal(err)
	}
	err = daemonDecode("ziro-sandboxd", resp, nil)
	if err == nil || !strings.Contains(err.Error(), "older ziroctl") || !strings.Contains(err.Error(), "GET /v1/sandboxes/abc/stats") ||
		!strings.Contains(err.Error(), "ziroctl service restart ziro-sandboxd") {
		t.Errorf("%v", err)
	}
	// A JSON error is passed on as it is.
	resp, _ = (&http.Client{Transport: inProcess{h: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiReply(w, errNotFound("no sandbox abc"), nil)
	})}}).Get("http://ziro-sandboxd/v1/sandboxes/abc")
	if err := daemonDecode("ziro-sandboxd", resp, nil); err == nil || err.Error() != "no sandbox abc" {
		t.Errorf("%v", err)
	}
}
