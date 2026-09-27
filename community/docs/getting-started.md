# Getting Started with Ziro-OS

Welcome to Ziro-OS, the container-native operating system built for cloud-native workloads! This guide will help you get up and running quickly.

## 🚀 Quick Start

### 1. Installation

#### Cloud Deployment (Recommended)
```bash
# AWS
make cloud-aws
aws ec2 run-instances --image-id ami-ziro-os-latest --instance-type t3.medium

# Azure
make cloud-azure
az vm create --resource-group ziro-rg --name ziro-vm --image ziro-os-latest

# GCP
make cloud-gcp
gcloud compute instances create ziro-vm --image-family=ziro-os
```

#### Local Development
```bash
# Clone the repository
git clone https://github.com/ziro-os/ziro-os.git
cd ziro-os

# Build the system
make all

# Test in QEMU
make dev-qemu
```

### 2. First Container

Once Ziro-OS is running, deploy your first container:

```bash
# Using ziroctl
ziroctl container run nginx:alpine

# Using standard containerd
ctr run --rm -t docker.io/library/nginx:alpine nginx

# Check running containers
ziroctl container list
```

### 3. Install Packages

Use ZiroPkg to install pre-built applications:

```bash
# Install popular packages
ziropkg install nginx redis postgresql

# Search for packages
ziropkg search monitoring

# Install monitoring stack
ziropkg install monitoring/prometheus
```

## 🏗️ Architecture Overview

Ziro-OS is built with a minimal, container-first architecture:

```
┌─────────────────────────────────────────┐
│              Applications               │
│  ┌─────────┐ ┌─────────┐ ┌─────────────┐ │
│  │   Web   │ │   API   │ │  Database   │ │
│  └─────────┘ └─────────┘ └─────────────┘ │
└─────────────────────────────────────────┘
┌─────────────────────────────────────────┐
│            Container Runtime            │
│  ┌─────────┐ ┌─────────┐ ┌─────────────┐ │
│  │containerd│ │   CNI   │ │   Storage   │ │
│  └─────────┘ └─────────┘ └─────────────┘ │
└─────────────────────────────────────────┘
┌─────────────────────────────────────────┐
│              Ziro-OS Kernel             │
│        Minimal Linux + Security        │
└─────────────────────────────────────────┘
```

## 🛠️ Development Workflow

### Create a New Project

```bash
# Initialize a new project
ziro-dev init my-app --type=web --language=go

# Navigate to project
cd my-app

# Build container
ziro-dev build

# Test locally
ziro-dev test

# Deploy to cluster
ziro-dev deploy
```

### Project Structure
```
my-app/
├── src/                 # Application source code
├── tests/              # Test files
├── deploy/             # Kubernetes manifests
├── Dockerfile          # Container definition
├── ziropkg.yaml        # Package manifest
└── .github/workflows/  # CI/CD configuration
```

## 🔧 System Management

### Container Operations
```bash
# List containers
ziroctl container list

# Run a container
ziroctl container run alpine:latest /bin/sh

# Stop a container
ziroctl container stop <container-id>

# Pull images
ziroctl container pull nginx:alpine
```

### System Information
```bash
# System status
ziroctl system status

# System information
ziroctl system info

# Resource usage
ziroctl system resources
```

### Package Management
```bash
# List installed packages
ziropkg list

# Install a package
ziropkg install <package-name>

# Remove a package
ziropkg remove <package-name>

# Update packages
ziropkg update
```

## 🌐 Kubernetes Integration

Ziro-OS works seamlessly with Kubernetes:

### Join Existing Cluster
```bash
# Install Kubernetes components
make install-k8s

# Join cluster
kubeadm join <master-ip>:6443 --token <token> --discovery-token-ca-cert-hash <hash>
```

### Create New Cluster
```bash
# Initialize master node
kubeadm init --pod-network-cidr=10.244.0.0/16

# Install CNI plugin
kubectl apply -f https://raw.githubusercontent.com/flannel-io/flannel/master/Documentation/kube-flannel.yml
```

## 🔒 Security

Ziro-OS includes comprehensive security hardening:

### Apply Security Policies
```bash
# Enable security hardening
make harden

# Check security status
ziroctl security status

# View security policies
ziroctl security policies
```

### Container Security
- **Seccomp profiles**: Default security policies for containers
- **AppArmor**: Mandatory access control
- **Network policies**: Container network isolation
- **Resource limits**: CPU and memory constraints

## 📊 Monitoring

Built-in monitoring and observability:

### Install Monitoring Stack
```bash
# Install Prometheus, Grafana, and alerting
make monitoring

# View monitoring dashboard
/opt/monitoring/dashboard.sh
```

### Access Monitoring
- **Prometheus**: http://localhost:9090
- **Node Exporter**: http://localhost:9100
- **cAdvisor**: http://localhost:8080

## 🚀 Production Deployment

### Infrastructure as Code

#### Terraform (AWS)
```bash
# Deploy AWS infrastructure
cd deploy/terraform/aws
terraform init
terraform apply
```

#### Helm (Kubernetes)
```bash
# Install Ziro-OS operator
helm install ziro-os-operator deploy/helm/ziro-os-operator/

# Scale cluster
kubectl scale deployment ziro-os-operator --replicas=5
```

### Auto-scaling
```bash
# Enable cluster autoscaler
kubectl apply -f deploy/kubernetes/cluster-autoscaler.yaml

# Configure horizontal pod autoscaler
kubectl autoscale deployment my-app --cpu-percent=50 --min=1 --max=10
```

## 🔧 Troubleshooting

### Common Issues

#### Container Won't Start
```bash
# Check container logs
ziroctl container logs <container-id>

# Check system resources
ziroctl system resources

# Verify image
ziroctl container images
```

#### Network Issues
```bash
# Check CNI configuration
ls -la /etc/cni/net.d/

# Verify bridge setup
ip link show

# Test connectivity
ping 8.8.8.8
```

#### Storage Issues
```bash
# Check disk space
df -h

# Verify container storage
ziroctl container inspect <container-id>

# Clean up unused images
ziroctl container prune
```

### Getting Help

- **Documentation**: https://docs.ziro-os.io
- **Community Forum**: https://community.ziro-os.io
- **GitHub Issues**: https://github.com/ziro-os/ziro-os/issues
- **Discord**: https://discord.gg/ziro-os

## 🎯 Next Steps

1. **Explore Examples**: Check out the `examples/` directory
2. **Join Community**: Connect with other Ziro-OS users
3. **Contribute**: Help improve Ziro-OS
4. **Deploy Production**: Scale your workloads

Welcome to the future of container-native computing! 🚀