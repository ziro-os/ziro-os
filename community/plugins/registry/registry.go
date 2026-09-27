package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/mux"
)

type Plugin struct {
	Name        string            `json:"name"`
	Version     string            `json:"version"`
	Description string            `json:"description"`
	Author      string            `json:"author"`
	Repository  string            `json:"repository"`
	Image       string            `json:"image"`
	Type        string            `json:"type"` // cni, csi, device, monitoring, security
	Tags        []string          `json:"tags"`
	Downloads   int64             `json:"downloads"`
	Rating      float64           `json:"rating"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
	Metadata    map[string]string `json:"metadata"`
}

type Registry struct {
	plugins map[string]*Plugin
}

func NewRegistry() *Registry {
	return &Registry{
		plugins: make(map[string]*Plugin),
	}
}

func (r *Registry) Start(port int) error {
	// Initialize with some example plugins
	r.initializePlugins()

	router := mux.NewRouter()
	
	// API routes
	api := router.PathPrefix("/api/v1").Subrouter()
	api.HandleFunc("/plugins", r.listPlugins).Methods("GET")
	api.HandleFunc("/plugins/{name}", r.getPlugin).Methods("GET")
	api.HandleFunc("/plugins/{name}/download", r.downloadPlugin).Methods("POST")
	api.HandleFunc("/plugins", r.publishPlugin).Methods("POST")
	api.HandleFunc("/search", r.searchPlugins).Methods("GET")

	// Static files for web interface
	router.PathPrefix("/").Handler(http.FileServer(http.Dir("./web/")))

	fmt.Printf("Ziro-OS Plugin Registry starting on port %d\n", port)
	return http.ListenAndServe(fmt.Sprintf(":%d", port), router)
}

func (r *Registry) initializePlugins() {
	plugins := []*Plugin{
		{
			Name:        "flannel-cni",
			Version:     "1.2.0",
			Description: "Flannel CNI plugin for overlay networking",
			Author:      "Flannel Team",
			Repository:  "https://github.com/flannel-io/flannel",
			Image:       "quay.io/coreos/flannel:v0.22.3",
			Type:        "cni",
			Tags:        []string{"networking", "overlay", "kubernetes"},
			Downloads:   15420,
			Rating:      4.8,
			CreatedAt:   time.Now().AddDate(0, -6, 0),
			UpdatedAt:   time.Now().AddDate(0, -1, 0),
			Metadata: map[string]string{
				"kubernetes": ">=1.20",
				"arch":       "amd64,arm64",
			},
		},
		{
			Name:        "nvidia-device-plugin",
			Version:     "0.14.3",
			Description: "NVIDIA GPU device plugin for Kubernetes",
			Author:      "NVIDIA",
			Repository:  "https://github.com/NVIDIA/k8s-device-plugin",
			Image:       "nvcr.io/nvidia/k8s-device-plugin:v0.14.3",
			Type:        "device",
			Tags:        []string{"gpu", "nvidia", "ml", "ai"},
			Downloads:   8932,
			Rating:      4.6,
			CreatedAt:   time.Now().AddDate(0, -4, 0),
			UpdatedAt:   time.Now().AddDate(0, 0, -15),
			Metadata: map[string]string{
				"gpu":        "required",
				"driver":     ">=470.0",
				"kubernetes": ">=1.19",
			},
		},
		{
			Name:        "falco-security",
			Version:     "0.36.2",
			Description: "Runtime security monitoring and threat detection",
			Author:      "Falco Community",
			Repository:  "https://github.com/falcosecurity/falco",
			Image:       "falcosecurity/falco:0.36.2",
			Type:        "security",
			Tags:        []string{"security", "monitoring", "threat-detection", "ebpf"},
			Downloads:   12654,
			Rating:      4.7,
			CreatedAt:   time.Now().AddDate(0, -8, 0),
			UpdatedAt:   time.Now().AddDate(0, 0, -7),
			Metadata: map[string]string{
				"kernel":     ">=4.14",
				"ebpf":       "required",
				"privileges": "privileged",
			},
		},
		{
			Name:        "longhorn-csi",
			Version:     "1.5.3",
			Description: "Distributed block storage for Kubernetes",
			Author:      "Longhorn Team",
			Repository:  "https://github.com/longhorn/longhorn",
			Image:       "longhornio/longhorn-manager:v1.5.3",
			Type:        "csi",
			Tags:        []string{"storage", "distributed", "block", "backup"},
			Downloads:   9876,
			Rating:      4.5,
			CreatedAt:   time.Now().AddDate(0, -5, 0),
			UpdatedAt:   time.Now().AddDate(0, 0, -10),
			Metadata: map[string]string{
				"storage":    "block",
				"replicas":   ">=3",
				"kubernetes": ">=1.21",
			},
		},
		{
			Name:        "jaeger-tracing",
			Version:     "1.51.0",
			Description: "Distributed tracing system for microservices",
			Author:      "Jaeger Team",
			Repository:  "https://github.com/jaegertracing/jaeger",
			Image:       "jaegertracing/all-in-one:1.51",
			Type:        "monitoring",
			Tags:        []string{"tracing", "observability", "microservices", "opentelemetry"},
			Downloads:   7543,
			Rating:      4.4,
			CreatedAt:   time.Now().AddDate(0, -3, 0),
			UpdatedAt:   time.Now().AddDate(0, 0, -5),
			Metadata: map[string]string{
				"protocol":   "grpc,http",
				"storage":    "memory,elasticsearch,cassandra",
				"opentelemetry": "compatible",
			},
		},
	}

	for _, plugin := range plugins {
		r.plugins[plugin.Name] = plugin
	}
}

func (r *Registry) listPlugins(w http.ResponseWriter, req *http.Request) {
	pluginType := req.URL.Query().Get("type")
	tag := req.URL.Query().Get("tag")

	var filtered []*Plugin
	for _, plugin := range r.plugins {
		if pluginType != "" && plugin.Type != pluginType {
			continue
		}
		if tag != "" {
			found := false
			for _, t := range plugin.Tags {
				if t == tag {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		filtered = append(filtered, plugin)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"plugins": filtered,
		"total":   len(filtered),
	})
}

func (r *Registry) getPlugin(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	name := vars["name"]

	plugin, exists := r.plugins[name]
	if !exists {
		http.Error(w, "Plugin not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(plugin)
}

func (r *Registry) downloadPlugin(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	name := vars["name"]

	plugin, exists := r.plugins[name]
	if !exists {
		http.Error(w, "Plugin not found", http.StatusNotFound)
		return
	}

	// Increment download counter
	plugin.Downloads++

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":      "Download initiated",
		"plugin":       plugin.Name,
		"version":      plugin.Version,
		"image":        plugin.Image,
		"install_cmd":  fmt.Sprintf("ziroctl plugin install %s", plugin.Name),
	})
}

func (r *Registry) publishPlugin(w http.ResponseWriter, req *http.Request) {
	var plugin Plugin
	if err := json.NewDecoder(req.Body).Decode(&plugin); err != nil {
		http.Error(w, "Invalid plugin data", http.StatusBadRequest)
		return
	}

	// Validate plugin
	if plugin.Name == "" || plugin.Version == "" || plugin.Image == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	// Set metadata
	plugin.CreatedAt = time.Now()
	plugin.UpdatedAt = time.Now()
	plugin.Downloads = 0
	plugin.Rating = 0.0

	// Store plugin
	r.plugins[plugin.Name] = &plugin

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Plugin published successfully",
		"plugin":  plugin.Name,
		"version": plugin.Version,
	})
}

func (r *Registry) searchPlugins(w http.ResponseWriter, req *http.Request) {
	query := req.URL.Query().Get("q")
	if query == "" {
		r.listPlugins(w, req)
		return
	}

	var results []*Plugin
	for _, plugin := range r.plugins {
		if contains(plugin.Name, query) || 
		   contains(plugin.Description, query) ||
		   containsTag(plugin.Tags, query) {
			results = append(results, plugin)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"plugins": results,
		"total":   len(results),
		"query":   query,
	})
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || 
		(len(s) > len(substr) && 
		 (s[:len(substr)] == substr || 
		  s[len(s)-len(substr):] == substr ||
		  containsSubstring(s, substr))))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func containsTag(tags []string, tag string) bool {
	for _, t := range tags {
		if contains(t, tag) {
			return true
		}
	}
	return false
}