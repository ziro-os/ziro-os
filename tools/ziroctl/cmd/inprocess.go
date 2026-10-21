package cmd

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
)

// inProcess is an http.RoundTripper that serves requests with a handler instead of a network.
// The answer streams through a pipe: the response returns as soon as the handler has written
// its headers, and the handler blocks while the reader is behind, so a long exec or a large
// download costs constant memory. Used by the API's MCP endpoint (its tools call the API as
// the client that called it) and by the host CLI on a cluster master.
type inProcess struct {
	h      http.Handler
	remote string                                // the RemoteAddr the handler sees ("" = loopback)
	ctx    func(context.Context) context.Context // what else the handler's context carries (identity)
}

func (t inProcess) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.RemoteAddr, req.RequestURI = t.remote, req.URL.RequestURI()
	if req.RemoteAddr == "" {
		req.RemoteAddr = "127.0.0.1:0"
	}
	if req.Body == nil || req.Body == http.NoBody {
		req.Body, req.ContentLength = http.NoBody, 0
	} else if req.ContentLength == 0 {
		// A client request's 0 with a body means "unknown length" (a file), where a server
		// request's means empty: say -1, as a server reading a chunked body would, or a
		// ReverseProxy behind the handler drops the body.
		req.ContentLength = -1
	}
	if t.ctx != nil {
		req = req.WithContext(t.ctx(req.Context()))
	}
	pr, pw := io.Pipe()
	w := &pipeResponse{header: http.Header{}, pw: pw, ready: make(chan struct{})}
	go func() {
		defer func() {
			if p := recover(); p != nil {
				w.WriteHeader(http.StatusInternalServerError)
				_ = pw.CloseWithError(fmt.Errorf("handler panic: %v", p))
				return
			}
			w.WriteHeader(http.StatusOK) // a handler that wrote nothing
			_ = pw.Close()
		}()
		t.h.ServeHTTP(w, req)
	}()
	select {
	case <-w.ready:
	case <-req.Context().Done():
		_ = pr.CloseWithError(req.Context().Err()) // the handler's writes fail and it stops
		return nil, req.Context().Err()
	}
	return &http.Response{StatusCode: w.status, Status: fmt.Sprintf("%d %s", w.status, http.StatusText(w.status)),
		Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1, Header: w.sent, Body: pr, ContentLength: -1, Request: req}, nil
}

// pipeResponse is the handler's side of inProcess.
type pipeResponse struct {
	header http.Header
	sent   http.Header // the headers as they were when the status was written
	status int
	pw     *io.PipeWriter
	once   sync.Once
	ready  chan struct{}
}

func (p *pipeResponse) Header() http.Header { return p.header }

func (p *pipeResponse) WriteHeader(code int) {
	p.once.Do(func() {
		p.status, p.sent = code, p.header.Clone()
		close(p.ready)
	})
}

func (p *pipeResponse) Write(b []byte) (int, error) {
	p.WriteHeader(http.StatusOK)
	return p.pw.Write(b)
}

func (p *pipeResponse) Flush() {}
