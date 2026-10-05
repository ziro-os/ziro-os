package cmd

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A build log and a source upload outlast the server's default read and write timeouts. Cutting
// an answer off in the middle of a TLS record shows up on the client as "bad record MAC", so
// both must get through a TLS server whose defaults are far shorter than the transfer.
func TestLongTransfersOutlastServerTimeouts(t *testing.T) {
	dir, err := os.MkdirTemp("", "z")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	oldSock, oldHTTP := deploySocket, deployHTTP
	deploySocket = filepath.Join(dir, "d.sock")
	deployHTTP = &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", deploySocket)
	}}}
	defer func() { deploySocket, deployHTTP = oldSock, oldHTTP }()

	got := make(chan int, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/deployments/{app}/builds/{id}/log", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "extracting\n")
		w.(http.Flusher).Flush()
		time.Sleep(600 * time.Millisecond) // a quiet stretch of the build
		io.WriteString(w, "done\n")
	})
	mux.HandleFunc("POST /v1/deployments/{app}/source", func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		got <- int(n)
		io.WriteString(w, `{"id":"b1"}`)
	})
	l, err := net.Listen("unix", deploySocket)
	if err != nil {
		t.Fatal(err)
	}
	daemon := &http.Server{Handler: mux}
	go daemon.Serve(l)
	defer daemon.Close()

	api := newAPIHarness(t, registerDeployRoutes)
	tok, _, err := createAPIToken("t-deployer", "deployer", 0)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(api.h)
	srv.Config.ReadTimeout, srv.Config.WriteTimeout = 200*time.Millisecond, 200*time.Millisecond
	srv.StartTLS()
	defer srv.Close()
	do := func(method, path string, body io.Reader, token string) *http.Response {
		req, _ := http.NewRequest(method, srv.URL+path, body)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		return resp
	}

	resp := do("GET", "/api/v1/deployments/web/builds/b1/log?follow=true", nil, api.tok["viewer"])
	b, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || string(b) != "extracting\ndone\n" {
		t.Fatalf("log: %q, %v", b, err)
	}

	pr, pw := io.Pipe()
	go func() {
		io.WriteString(pw, strings.Repeat("a", 1000))
		time.Sleep(600 * time.Millisecond) // a slow link
		io.WriteString(pw, strings.Repeat("b", 1000))
		pw.Close()
	}()
	resp = do("POST", "/api/v1/deployments/web/source", pr, tok)
	b, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(b), "b1") || <-got != 2000 {
		t.Fatalf("upload: %d %s", resp.StatusCode, b)
	}
}
