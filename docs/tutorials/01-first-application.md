# Tutorial: Deploy Your First Application on Ziro-OS

In this tutorial, you'll learn how to deploy your first application on Ziro-OS, from development to production.

## Prerequisites

- Ziro-OS cluster running (local or cloud)
- `ziroctl` CLI installed
- `ziro-dev` SDK installed
- Basic knowledge of containers and Kubernetes

## Step 1: Create a New Application

Let's create a simple web application using the Ziro-OS SDK:

```bash
# Initialize a new Go web application
ziro-dev init hello-ziro --type=web --language=go

# Navigate to the project
cd hello-ziro
```

This creates a project structure optimized for Ziro-OS:

```
hello-ziro/
├── src/
│   └── main.go          # Application code
├── tests/
│   └── main_test.go     # Test files
├── deploy/
│   └── kubernetes.yaml  # Kubernetes manifests
├── Dockerfile           # Container definition
├── ziropkg.yaml        # Package manifest
├── go.mod              # Go dependencies
└── .github/workflows/  # CI/CD pipeline
```

## Step 2: Understand the Generated Code

Let's examine the generated application:

```go
// src/main.go
package main

import (
	"fmt"
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello from Ziro-OS!")
	})

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "OK")
	})

	http.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Ready")
	})

	fmt.Println("Server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
```

Key features:
- **Health endpoint**: `/health` for liveness probes
- **Readiness endpoint**: `/ready` for readiness probes
- **Port 8080**: Standard port for web applications

## Step 3: Customize Your Application

Let's add some functionality to make it more interesting:

```go
// src/main.go (enhanced version)
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

type Response struct {
	Message   string    `json:"message"`
	Hostname  string    `json:"hostname"`
	Timestamp time.Time `json:"timestamp"`
	Version   string    `json:"version"`
}

func main() {
	hostname, _ := os.Hostname()
	version := os.Getenv("APP_VERSION")
	if version == "" {
		version = "1.0.0"
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		response := Response{
			Message:   "Hello from Ziro-OS!",
			Hostname:  hostname,
			Timestamp: time.Now(),
			Version:   version,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "OK")
	})

	http.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Ready")
	})

	// New endpoint for system information
	http.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
		info := map[string]string{
			"os":       "Ziro-OS",
			"runtime":  "containerd",
			"hostname": hostname,
			"version":  version,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(info)
	})

	fmt.Printf("Server starting on :8080 (version %s)\n", version)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
```

## Step 4: Build the Application

Build your application using the Ziro-OS SDK:

```bash
# Build the container image
ziro-dev build

# This will:
# 1. Compile the Go application
# 2. Create an optimized container image
# 3. Apply Ziro-OS specific optimizations
```

The build process creates a multi-stage Docker image optimized for Ziro-OS:

```dockerfile
# Multi-stage build for Go application
FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY src/ ./src/
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main ./src

# Final stage - minimal image
FROM scratch
COPY --from=builder /app/main /main
EXPOSE 8080
ENTRYPOINT ["/main"]
```

## Step 5: Test Locally

Test your application before deployment:

```bash
# Run tests
ziro-dev test

# Start local development server
ziro-dev dev

# In another terminal, test the endpoints
curl http://localhost:8080/
curl http://localhost:8080/health
curl http://localhost:8080/info
```

## Step 6: Deploy to Ziro-OS

Deploy your application to the Ziro-OS cluster:

```bash
# Deploy to development environment
ziro-dev deploy --environment=dev

# Check deployment status
kubectl get pods -l app=hello-ziro

# Get service information
kubectl get service hello-ziro-service
```

## Step 7: Access Your Application

Once deployed, access your application:

```bash
# Get the service URL
kubectl get service hello-ziro-service

# If using a LoadBalancer
curl http://<EXTERNAL-IP>/

# If using port-forward for testing
kubectl port-forward service/hello-ziro-service 8080:80
curl http://localhost:8080/
```

Expected response:
```json
{
  "message": "Hello from Ziro-OS!",
  "hostname": "hello-ziro-deployment-abc123",
  "timestamp": "2024-01-15T10:30:00Z",
  "version": "1.0.0"
}
```

## Step 8: Scale Your Application

Scale your application to handle more traffic:

```bash
# Scale to 3 replicas
kubectl scale deployment hello-ziro --replicas=3

# Enable auto-scaling
kubectl autoscale deployment hello-ziro --cpu-percent=50 --min=1 --max=10

# Check scaling status
kubectl get hpa hello-ziro
```

## Step 9: Monitor Your Application

Monitor your application using Ziro-OS built-in monitoring:

```bash
# View application metrics
curl http://localhost:9090/api/v1/query?query=container_cpu_usage_seconds_total{pod=~"hello-ziro.*"}

# Check logs
kubectl logs -f deployment/hello-ziro

# View monitoring dashboard
/opt/monitoring/dashboard.sh
```

## Step 10: Update Your Application

Make changes and deploy updates:

```bash
# Update the application code
# Edit src/main.go to change the message

# Build new version
ziro-dev build --tag=v1.1.0

# Deploy update with rolling update
ziro-dev deploy --environment=dev --version=v1.1.0

# Monitor rollout
kubectl rollout status deployment/hello-ziro
```

## Step 11: Production Deployment

Deploy to production with additional configurations:

```bash
# Deploy to production
ziro-dev deploy --environment=production --replicas=5

# Apply production configurations
kubectl apply -f deploy/production/

# Verify production deployment
kubectl get pods -n production -l app=hello-ziro
```

## Advanced Features

### Custom Health Checks

Enhance health checks for better reliability:

```go
// Add to src/main.go
var healthy = true
var ready = true

http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
	if !healthy {
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprintf(w, "Unhealthy")
		return
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "OK")
})

http.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
	if !ready {
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprintf(w, "Not Ready")
		return
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Ready")
})
```

### Environment Configuration

Use environment variables for configuration:

```go
// Add configuration struct
type Config struct {
	Port     string
	LogLevel string
	Database string
}

func loadConfig() Config {
	return Config{
		Port:     getEnv("PORT", "8080"),
		LogLevel: getEnv("LOG_LEVEL", "info"),
		Database: getEnv("DATABASE_URL", ""),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
```

### Metrics and Observability

Add Prometheus metrics:

```go
import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	requestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"method", "endpoint", "status"},
	)
)

func init() {
	prometheus.MustRegister(requestsTotal)
}

// Add metrics endpoint
http.Handle("/metrics", promhttp.Handler())
```

## Troubleshooting

### Common Issues

#### Container Won't Start
```bash
# Check pod status
kubectl describe pod <pod-name>

# Check logs
kubectl logs <pod-name>

# Check resource limits
kubectl top pod <pod-name>
```

#### Service Not Accessible
```bash
# Check service configuration
kubectl describe service hello-ziro-service

# Verify endpoints
kubectl get endpoints hello-ziro-service

# Test internal connectivity
kubectl exec -it <pod-name> -- wget -qO- http://hello-ziro-service/health
```

#### Performance Issues
```bash
# Check resource usage
kubectl top pods -l app=hello-ziro

# View detailed metrics
curl http://localhost:9090/api/v1/query?query=rate(container_cpu_usage_seconds_total[5m])

# Analyze slow requests
kubectl logs -f deployment/hello-ziro | grep "slow"
```

## Next Steps

1. **Add Database**: Connect to PostgreSQL or Redis
2. **Implement Authentication**: Add JWT or OAuth
3. **Add Caching**: Implement Redis caching
4. **Set up CI/CD**: Automate deployments
5. **Monitor Production**: Set up alerts and dashboards

Congratulations! You've successfully deployed your first application on Ziro-OS. The container-native architecture provides excellent performance, security, and scalability for your workloads.

## Additional Resources

- [Ziro-OS Documentation](../README.md)
- [SDK Reference](../sdk/README.md)
- [Best Practices](./best-practices.md)
- [Production Deployment](./production-deployment.md)