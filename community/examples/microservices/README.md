# Microservices Example on Ziro-OS

This example demonstrates how to deploy a complete microservices application on Ziro-OS, showcasing the platform's container-native capabilities.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Load Balancer                        │
└─────────────────────┬───────────────────────────────────┘
                      │
┌─────────────────────┴───────────────────────────────────┐
│                  API Gateway                            │
│                 (nginx + lua)                           │
└─────┬─────────────────────┬─────────────────────────────┘
      │                     │
┌─────▼─────┐         ┌─────▼─────┐         ┌─────────────┐
│   User    │         │  Product  │         │   Order     │
│  Service  │         │  Service  │         │  Service    │
│   (Go)    │         │  (Python) │         │   (Rust)    │
└─────┬─────┘         └─────┬─────┘         └─────┬───────┘
      │                     │                     │
┌─────▼─────┐         ┌─────▼─────┐         ┌─────▼───────┐
│   Redis   │         │PostgreSQL │         │   MongoDB   │
│  (Cache)  │         │ (Products)│         │  (Orders)   │
└───────────┘         └───────────┘         └─────────────┘
```

## Services

### 1. User Service (Go)
- User authentication and management
- JWT token generation
- Redis for session storage

### 2. Product Service (Python/FastAPI)
- Product catalog management
- PostgreSQL for data persistence
- Full-text search capabilities

### 3. Order Service (Rust/Actix)
- Order processing and management
- MongoDB for document storage
- Event-driven architecture

### 4. API Gateway (Nginx + Lua)
- Request routing and load balancing
- Authentication middleware
- Rate limiting and caching

## Quick Start

### 1. Deploy with ZiroPkg
```bash
# Install the complete microservices stack
ziropkg install examples/microservices

# Check deployment status
kubectl get pods -n microservices
```

### 2. Manual Deployment
```bash
# Create namespace
kubectl create namespace microservices

# Deploy databases
kubectl apply -f databases/

# Deploy services
kubectl apply -f services/

# Deploy API gateway
kubectl apply -f gateway/

# Deploy monitoring
kubectl apply -f monitoring/
```

### 3. Access the Application
```bash
# Get the load balancer IP
kubectl get service api-gateway -n microservices

# Test the API
curl http://<EXTERNAL-IP>/api/v1/health

# Create a user
curl -X POST http://<EXTERNAL-IP>/api/v1/users \
  -H "Content-Type: application/json" \
  -d '{"username": "john", "email": "john@example.com"}'
```

## Service Details

### User Service Configuration
```yaml
# ziropkg.yaml for user-service
name: user-service
version: 1.0.0
type: microservice
image: ziro-examples/user-service:latest

runtime:
  ports: [8080]
  environment:
    - REDIS_URL=redis://redis:6379
    - JWT_SECRET=your-secret-key

resources:
  requests:
    memory: 64Mi
    cpu: 50m
  limits:
    memory: 128Mi
    cpu: 200m

dependencies:
  - redis
```

### Product Service Configuration
```yaml
# ziropkg.yaml for product-service
name: product-service
version: 1.0.0
type: microservice
image: ziro-examples/product-service:latest

runtime:
  ports: [8000]
  environment:
    - DATABASE_URL=postgresql://postgres:password@postgresql:5432/products

resources:
  requests:
    memory: 128Mi
    cpu: 100m
  limits:
    memory: 256Mi
    cpu: 500m

dependencies:
  - postgresql
```

### Order Service Configuration
```yaml
# ziropkg.yaml for order-service
name: order-service
version: 1.0.0
type: microservice
image: ziro-examples/order-service:latest

runtime:
  ports: [3000]
  environment:
    - MONGODB_URL=mongodb://mongodb:27017/orders

resources:
  requests:
    memory: 96Mi
    cpu: 75m
  limits:
    memory: 192Mi
    cpu: 300m

dependencies:
  - mongodb
```

## Development Workflow

### 1. Local Development
```bash
# Initialize each service
ziro-dev init user-service --type=microservice --language=go
ziro-dev init product-service --type=microservice --language=python --framework=fastapi
ziro-dev init order-service --type=microservice --language=rust --framework=actix

# Build all services
for service in user-service product-service order-service; do
  cd $service
  ziro-dev build
  cd ..
done
```

### 2. Testing
```bash
# Run integration tests
ziro-dev test --integration

# Load testing
ziro-dev benchmark --concurrent=100 --duration=60s
```

### 3. Deployment
```bash
# Deploy to staging
ziro-dev deploy --environment=staging

# Deploy to production
ziro-dev deploy --environment=production --replicas=3
```

## Monitoring and Observability

### Metrics
- **Prometheus**: Service metrics and alerting
- **Grafana**: Dashboards and visualization
- **Jaeger**: Distributed tracing

### Logging
- **Fluentd**: Log aggregation
- **Elasticsearch**: Log storage and search
- **Kibana**: Log visualization

### Health Checks
```bash
# Check service health
curl http://<API-GATEWAY>/api/v1/health

# Detailed health check
curl http://<API-GATEWAY>/api/v1/health/detailed
```

## Scaling

### Horizontal Pod Autoscaler
```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: user-service-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: user-service
  minReplicas: 2
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
```

### Cluster Autoscaler
```bash
# Enable cluster autoscaling
kubectl apply -f cluster-autoscaler.yaml

# Monitor scaling events
kubectl get events --sort-by=.metadata.creationTimestamp
```

## Security

### Network Policies
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: microservices-network-policy
spec:
  podSelector:
    matchLabels:
      app: microservices
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: api-gateway
    ports:
    - protocol: TCP
      port: 8080
```

### Service Mesh (Optional)
```bash
# Install Istio service mesh
istioctl install --set values.defaultRevision=default

# Enable sidecar injection
kubectl label namespace microservices istio-injection=enabled

# Apply security policies
kubectl apply -f istio/security-policies.yaml
```

## Performance Optimization

### Container Optimization
- **Multi-stage builds**: Minimal container images
- **Distroless images**: Reduced attack surface
- **Resource limits**: Optimal resource allocation

### Database Optimization
- **Connection pooling**: Efficient database connections
- **Read replicas**: Distributed read workloads
- **Caching**: Redis for frequently accessed data

### Network Optimization
- **Service mesh**: Intelligent traffic routing
- **CDN**: Static asset delivery
- **Compression**: Reduced bandwidth usage

## Troubleshooting

### Common Issues

#### Service Discovery
```bash
# Check DNS resolution
kubectl exec -it user-service-pod -- nslookup product-service

# Verify service endpoints
kubectl get endpoints -n microservices
```

#### Database Connectivity
```bash
# Test database connection
kubectl exec -it product-service-pod -- pg_isready -h postgresql

# Check database logs
kubectl logs postgresql-pod -n microservices
```

#### Performance Issues
```bash
# Check resource usage
kubectl top pods -n microservices

# Analyze slow queries
kubectl exec -it postgresql-pod -- psql -c "SELECT * FROM pg_stat_activity;"
```

## CI/CD Pipeline

### GitHub Actions
```yaml
name: Microservices CI/CD

on:
  push:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    - name: Run tests
      run: |
        for service in user-service product-service order-service; do
          cd $service
          ziro-dev test
          cd ..
        done

  build:
    needs: test
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    - name: Build containers
      run: |
        for service in user-service product-service order-service; do
          cd $service
          ziro-dev build --push
          cd ..
        done

  deploy:
    needs: build
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    - name: Deploy to production
      run: |
        ziro-dev deploy --environment=production
```

## Next Steps

1. **Customize Services**: Modify services for your use case
2. **Add Features**: Implement additional microservices
3. **Scale Up**: Deploy to production with auto-scaling
4. **Monitor**: Set up comprehensive monitoring and alerting
5. **Secure**: Implement advanced security policies

This example showcases Ziro-OS's power for microservices deployment with minimal overhead and maximum performance! 🚀