// Package api holds the request and response types of the Ziro API server (/api/v1). The server
// (ziroctl api) and the client (package client) use these same types; sdk/openapi.yaml documents them.
package api

import "time"

type Message struct {
	Status  string      `json:"status"`         // ok, accepted, error
	Code    string      `json:"code,omitempty"` // errors: invalid, unauthorized, forbidden, not_found, conflict, rate_limited, ...
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

// AppDeployRequest is the body of POST /api/v1/apps/deploy.
type AppDeployRequest struct {
	App       string            `json:"app"` // name[:version]
	Name      string            `json:"name,omitempty"`
	Set       map[string]string `json:"set,omitempty"`
	Replicas  int               `json:"replicas,omitempty"`
	Publish   int               `json:"publish,omitempty"`
	AllowFrom []string          `json:"allow_from,omitempty"`
	Expose    string            `json:"expose,omitempty"`     // publish through the gateway on this hostname
	ExposeTLS string            `json:"expose_tls,omitempty"` // auto, internal, off or cert:<name>
	Secrets   map[string]string `json:"secrets,omitempty"`    // input secrets (API keys); never logged
}

type AppCatalogEntry struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Default     string   `json:"default"`
	Versions    []string `json:"versions"`
	Cluster     bool     `json:"cluster,omitempty"`
}

type AppStatus struct {
	Name       string   `json:"name"`
	App        string   `json:"app"`
	Version    string   `json:"version"`
	Mode       string   `json:"mode"`
	Publish    string   `json:"publish,omitempty"`
	Components []string `json:"components"`
	Running    string   `json:"running"`
}

type ModuleInfo struct {
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	Available   string   `json:"available,omitempty"` // a newer version in a catalog (upgrade)
	Description string   `json:"description"`
	Source      string   `json:"source,omitempty"`
	Requires    []string `json:"requires,omitempty"`
	Status      string   `json:"status"`
	Error       string   `json:"error,omitempty"`
	Auto        bool     `json:"auto,omitempty"`
}

type NFSExport struct {
	Path     string   `json:"path"`
	Clients  []string `json:"clients"` // IPv4 addresses or CIDRs
	ReadOnly bool     `json:"read_only,omitempty"`
	// Squash maps client identities: "root" (default: root becomes the anonymous user), "all"
	// (every client user becomes the owner below) or "none" (client root is root here).
	Squash string `json:"squash,omitempty"`
	// Owner ("uid:gid") is the anonymous identity squashed users write as; with Squash "all" every
	// client write lands as this owner, so files stay usable on the server.
	Owner string `json:"owner,omitempty"`
}

type NFSMount struct {
	Server   string `json:"server"` // IPv4 address
	Path     string `json:"path"`
	Target   string `json:"target"`
	ReadOnly bool   `json:"read_only,omitempty"`
}

type NFSConfig struct {
	Exports []NFSExport `json:"exports,omitempty"`
	Mounts  []NFSMount  `json:"mounts,omitempty"`
}

// NFSClient is a connected NFSv4 client, from /proc/fs/nfsd/clients.
type NFSClient struct {
	Address      string   `json:"address"`
	Name         string   `json:"name"`
	MinorVersion string   `json:"minor_version"`
	Status       string   `json:"status"`
	OpenFiles    int      `json:"open_files"`
	Exports      []string `json:"exports"` // exports whose client list admits this address
}

// GatewayStatus is what the admin endpoint (and GET /api/v1/gateway/status) reports.
type GatewayStatus struct {
	Routes []GatewayRouteStatus `json:"routes"`
	CA     string               `json:"internal_ca,omitempty"` // PEM, to trust "internal" routes
}

type GatewayRouteStatus struct {
	Name      string            `json:"name"`
	Kind      string            `json:"kind"`
	Match     string            `json:"match"`
	TLS       string            `json:"tls,omitempty"`
	Upstreams []UpstreamHealth  `json:"upstreams"`
	Requests  map[string]uint64 `json:"requests,omitempty"` // status -> count
}

type UpstreamHealth struct {
	Addr    string `json:"addr"`
	Share   int    `json:"share"` // percent of the route's traffic by weight
	Healthy bool   `json:"healthy"`
	Active  int64  `json:"active"`
}

// Backup is one archive in the host's backup directory.
type Backup struct {
	Name     string    `json:"name"`
	Bytes    int64     `json:"bytes"`
	Created  time.Time `json:"created"`
	Checksum bool      `json:"checksum"` // a .sha256 manifest sits next to it
}

// AuditRecord is one entry of the tamper-evident audit trail (each carries the previous
// record's SHA-256 in Prev).
type AuditRecord struct {
	TS     string `json:"ts"`
	Actor  string `json:"actor"`
	Source string `json:"source,omitempty"`
	Action string `json:"action"`
	Target string `json:"target,omitempty"`
	Result string `json:"result"`
	Prev   string `json:"prev"`
}

// Token describes an API token (never the token itself, except Secret once on creation).
type Token struct {
	Name    string `json:"name"`
	Role    string `json:"role"`
	ID      string `json:"id,omitempty"`
	Created string `json:"created,omitempty"`
	Expires string `json:"expires,omitempty"`
	Secret  string `json:"token,omitempty"`
}
