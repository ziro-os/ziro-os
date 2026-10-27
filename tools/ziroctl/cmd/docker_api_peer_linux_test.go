//go:build linux

package cmd

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A real unix socket: the kernel's record of who connected ends up in the audit entry.
func TestDockerSocketAuditsTheKernelsPeerCredentials(t *testing.T) {
	f := &fakeDocker{}
	dir, err := os.MkdirTemp("", "dkp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "d.sock")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serveDockerAPI(ctx, sock, f.api()) }()
	t.Cleanup(func() { cancel(); <-done })
	c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		}}}
	var resp *http.Response
	for i := 0; i < 100; i++ { // the listener comes up asynchronously
		resp, err = c.Post("http://d/containers/web/start", "", nil)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	f.mu.Lock()
	defer f.mu.Unlock()
	want := fmt.Sprintf("uid:%d pid:%d", os.Getuid(), os.Getpid())
	if resp.StatusCode != 204 || len(f.actors) != 1 || f.actors[0] != want {
		t.Fatalf("status %d, actors %q, want %q", resp.StatusCode, f.actors, want)
	}
}
