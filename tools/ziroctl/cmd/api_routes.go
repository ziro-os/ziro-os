package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"
)

// The REST API is one table of routes. Each route names its method, path (http.ServeMux
// pattern syntax: {name} is one path segment), the minimum role and the handler. The server,
// role checks, the audit trail and the OpenAPI drift test (sdk/openapi.yaml) are all built from
// this table, so a route can't be served without being authorized, audited and documented.
//
// Roles: "public" (no token), "viewer" (read), "deployer" (deploy apps), "operator" (day-to-day changes), "admin"
// (anything that grants or removes access, installs software, deletes data or changes where
// traffic goes).

type apiRoute struct {
	Method  string
	Path    string
	Role    string
	Handler http.HandlerFunc
}

type apiRouter struct{ routes []apiRoute }

func (a *apiRouter) handle(method, path, role string, h http.HandlerFunc) {
	if apiRoleRank[role] == 0 && role != "public" {
		panic("api route " + method + " " + path + ": unknown role " + role)
	}
	a.routes = append(a.routes, apiRoute{method, path, role, h})
}

func (a *apiRouter) get(path, role string, h http.HandlerFunc) {
	a.handle(http.MethodGet, path, role, h)
}
func (a *apiRouter) post(path, role string, h http.HandlerFunc) {
	a.handle(http.MethodPost, path, role, h)
}
func (a *apiRouter) put(path, role string, h http.HandlerFunc) {
	a.handle(http.MethodPut, path, role, h)
}
func (a *apiRouter) delete(path, role string, h http.HandlerFunc) {
	a.handle(http.MethodDelete, path, role, h)
}

// apiRoutes builds the route table.
func apiRoutes() *apiRouter {
	a := &apiRouter{}
	registerCoreRoutes(a)
	registerSecurityRoutes(a)
	registerSystemRoutes(a)
	registerHostRoutes(a)
	registerDNSRoutes(a)
	registerModuleRoutes(a)
	registerAppRoutes(a)
	registerNFSRoutes(a)
	registerGatewayRoutes(a)
	registerGatewayDomainRoutes(a)
	registerDNSCloudRoutes(a)
	registerContainerRoutes(a)
	registerFirewallRoutes(a)
	registerClusterRoutes(a)
	registerOpsRoutes(a)
	registerStackRoutes(a)
	registerDeployRoutes(a)
	return a
}

// ---- errors ----

// apiError writes the error envelope: {"status":"error","code":...,"message":...}.
func apiError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(APIMessage{Status: "error", Code: apiErrorCode(status), Message: msg})
}

func apiErrorCode(status int) string {
	switch status {
	case http.StatusBadRequest:
		return "invalid"
	case http.StatusUnauthorized:
		return "unauthorized"
	case http.StatusForbidden:
		return "forbidden"
	case http.StatusNotFound:
		return "not_found"
	case http.StatusMethodNotAllowed:
		return "method_not_allowed"
	case http.StatusConflict:
		return "conflict"
	case http.StatusRequestEntityTooLarge:
		return "too_large"
	case http.StatusTooManyRequests:
		return "rate_limited"
	}
	return "internal"
}

// errNotFound marks a missing resource (answered 404 by apiReply).
type errNotFound string

func (e errNotFound) Error() string { return string(e) }

// apiReply answers ok as JSON, or the error: 404 for errNotFound, 413 for an oversized body,
// otherwise 400 (the operations validate their input; failures are almost always the request).
func apiReply(w http.ResponseWriter, err error, ok any) {
	if err != nil {
		var nf errNotFound
		var tooBig *http.MaxBytesError
		switch {
		case errors.As(err, &nf):
			apiError(w, http.StatusNotFound, err.Error())
		case errors.As(err, &tooBig):
			apiError(w, http.StatusRequestEntityTooLarge, err.Error())
		default:
			apiError(w, http.StatusBadRequest, err.Error())
		}
		return
	}
	_ = json.NewEncoder(w).Encode(ok)
}

// apiAccepted answers 202 for work that continues in the background.
func apiAccepted(w http.ResponseWriter, msg string) {
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(APIMessage{Status: "accepted", Message: msg})
}

// decodeStrict reads a JSON body of at most max bytes, rejecting unknown fields; an empty body
// leaves v unchanged.
func decodeStrict(w http.ResponseWriter, r *http.Request, v any, max int64) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, max))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("bad request body: %w", err)
	}
	return nil
}

// decodeBody is decodeStrict with the common 16 KiB limit, answering the error itself.
func decodeBody(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := decodeStrict(w, r, v, 16<<10); err != nil {
		apiReply(w, err, nil)
		return false
	}
	return true
}

// ---- server ----

type apiRoleKey struct{}

// apiRole is the caller's role (set by the middleware).
func apiRole(r *http.Request) string {
	role, _ := r.Context().Value(apiRoleKey{}).(string)
	return role
}

// statusRecorder captures the status and an error message for the audit trail.
type statusRecorder struct {
	http.ResponseWriter
	status int
	body   bytes.Buffer // the start of an error body
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	if s.status >= 400 && s.body.Len() < 512 {
		s.body.Write(b[:min(len(b), 512-s.body.Len())])
	}
	return s.ResponseWriter.Write(b)
}

// Unwrap lets http.ResponseController reach the connection (deadlines, flushing).
func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// Flush lets streamed answers (logs, events) through the recorder.
func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

type apiServerConfig struct {
	legacyToken string
	cors        string
	perIP       *rateLimiter
	perToken    *rateLimiter
	now         func() time.Time
}

// newAPIHandler serves the route table: security headers, CORS, rate limits (per client IP,
// then per token), authentication, the route's minimum role, and an audit record for every
// change (any method but GET/HEAD).
func newAPIHandler(a *apiRouter, c apiServerConfig) http.Handler {
	if c.now == nil {
		c.now = time.Now
	}
	mux := http.NewServeMux()
	paths := map[string][]string{} // path -> methods, for 405 answers
	for _, rt := range a.routes {
		rt := rt
		paths[rt.Path] = append(paths[rt.Path], rt.Method)
		mux.HandleFunc(rt.Method+" "+rt.Path, func(w http.ResponseWriter, r *http.Request) {
			ip, _, _ := net.SplitHostPort(r.RemoteAddr)
			if ip == "" {
				ip = r.RemoteAddr
			}
			if c.perIP != nil && !c.perIP.allow(ip) {
				apiError(w, http.StatusTooManyRequests, "rate limit exceeded")
				return
			}
			caller := "anonymous"
			if rt.Role != "public" {
				auth := r.Header.Get("Authorization")
				name, role, ok := apiIdentity(trimBearer(auth), c.legacyToken, c.now())
				if !ok || !strings.HasPrefix(auth, "Bearer ") {
					apiError(w, http.StatusUnauthorized, "invalid or missing bearer token")
					return
				}
				if c.perToken != nil && !c.perToken.allow("token:"+name) {
					apiError(w, http.StatusTooManyRequests, "rate limit exceeded for this token")
					return
				}
				if apiRoleRank[role] < apiRoleRank[rt.Role] {
					apiError(w, http.StatusForbidden, "requires the "+rt.Role+" role")
					return
				}
				caller = "api-token:" + name + "(" + role + ")"
				r = r.WithContext(context.WithValue(context.WithValue(r.Context(), apiCallerKey{}, caller), apiRoleKey{}, role))
			}
			if rt.Method == http.MethodGet || rt.Method == http.MethodHead {
				rt.Handler(w, r)
				return
			}
			rec := &statusRecorder{ResponseWriter: w}
			rt.Handler(rec, r)
			var err error
			if rec.status >= 400 {
				var m APIMessage
				_ = json.Unmarshal(rec.body.Bytes(), &m)
				err = fmt.Errorf("HTTP %d: %s", rec.status, m.Message)
			}
			if aerr := auditLog(caller, "api:"+ip, "api "+rt.Method+" "+rt.Path, r.URL.Path, err); aerr != nil {
				fmt.Printf("[api] audit log: %v\n", aerr)
			}
		})
	}
	// Everything else: CORS preflight, then JSON 405 (with Allow) or 404.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions && c.cors != "" && r.Header.Get("Origin") != "" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		for p, methods := range paths {
			if pathMatches(p, r.URL.Path) {
				sort.Strings(methods)
				w.Header().Set("Allow", strings.Join(methods, ", "))
				apiError(w, http.StatusMethodNotAllowed, "method not allowed")
				return
			}
		}
		apiError(w, http.StatusNotFound, "no such route")
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Cache-Control", "no-store")
		h.Set("Content-Type", "application/json; charset=utf-8")
		if c.cors != "" && r.Header.Get("Origin") != "" {
			h.Set("Access-Control-Allow-Origin", c.cors)
			h.Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		}
		mux.ServeHTTP(w, r)
	})
}

// pathMatches matches a ServeMux pattern path ({x} = one segment, {x...} = the rest).
func pathMatches(pattern, path string) bool {
	ps, xs := strings.Split(pattern, "/"), strings.Split(path, "/")
	for i, p := range ps {
		if strings.HasSuffix(p, "...}") {
			return len(xs) > i
		}
		if i >= len(xs) || (!strings.HasPrefix(p, "{") && p != xs[i]) || (strings.HasPrefix(p, "{") && xs[i] == "") {
			return false
		}
	}
	return len(xs) == len(ps)
}
