# Ziro-OS Advanced Deployment Guide

This guide covers advanced deployment scenarios for Ziro-OS Enhanced, including cloud deployments, enterprise installations, and production configurations.

## 🚀 Quick Start

### Build Enhanced Images
```bash
# Build all enhanced images
make image-advanced

# Build specific image types
make image-uefi        # UEFI bootable images
make image-cloud       # Cloud-ready images (AWS, Azure, GCP)
make image-enhanced    # Enhanced ISO with advanced installer
```

### Test Enhanced System
```bash
# Interactive testing suite
make test-advanced

# Specific test scenarios
make test-uefi         # Test UEFI boot
make test-cloud-init   # Test cloud-init integration
make test-containers   # Test container workloads
make test-security     # Test security features
```

## 🏗️ Image Types and Use Cases

### 1. UEFI Images
**Files:** `ziro-os-uefi-*.img`, `ziro-os-uefi-*.qcow2`

**Use Cases:**
- Modern hardware with UEFI firmware
- Virtual machines with UEFI support
- Cloud instances requiring UEFI boot

**Features:**
- GPT partition table
- UEFI boot support
- Secure Boot ready (when enabled)
- Enhanced security features

### 2. Cloud Images
**Files:** `ziro-os-aws-*.img`, `ziro-os-azure-*.vhd`, `ziro-os-gcp-*.img`, `ziro-os-vmware-*.vmdk`

**Use Cases:**
- AWS EC2 instances (AMI)
- Azure Virtual Machines
- Google Cloud Platform instances
- VMware vSphere environments

**Features:**
- Cloud-init integration
- Automatic hardware detection
- Network auto-configuration
- SSH server ready
- Monitoring capabilities

### 3. Enhanced ISO
**Files:** `ziro-os-enhanced-*.iso`

**Use Cases:**
- Hardware installation
- USB/DVD boot media
- Live environment testing
- Advanced installation scenarios

**Features:**
- Multiple boot options
- Advanced installer with encryption
- Live environment
- Recovery mode
- Hardware compatibility testing

## ☁️ Cloud Deployment

### AWS Deployment

#### 1. Create AMI from Image
```bash
# Build AWS-ready image
make image-cloud

# Upload to S3 (requires AWS CLI)
aws s3 cp images/bootable/output/ziro-os-aws-*.img s3://your-bucket/

# Import as AMI
aws ec2 import-image \
    --description "Ziro-OS Enhanced" \
    --disk-containers Format=raw,UserBucket='{S3Bucket=your-bucket,S3Key=ziro-os-aws-*.img}'
```

#### 2. Launch EC2 Instance
```bash
# Launch instance with cloud-init
aws ec2 run-instances \
    --image-id ami-xxxxxxxxx \
    --instance-type t3.medium \
    --key-name your-key-pair \
    --security-group-ids sg-xxxxxxxxx \
    --user-data file://cloud-init-config.yaml
```

#### 3. Cloud-Init Configuration Example
```yaml
#cloud-config
hostname: ziro-production

users:
  - name: admin
    sudo: ALL=(ALL) NOPASSWD:ALL
    ssh_authorized_keys:
      - ssh-rsa AAAAB3NzaC1yc2E... # Your SSH key

packages:
  - curl
  - wget
  - htop

runcmd:
  - systemctl enable containerd
  - systemctl start containerd
  - echo "Ziro-OS production ready" > /var/log/deployment.log

write_files:
  - path: /etc/ziro/production.conf
    content: |
      ENVIRONMENT=production
      LOG_LEVEL=info
      MONITORING_ENABLED=true
    permissions: '0644'
```

### Azure Deployment

#### 1. Upload VHD to Azure
```bash
# Build Azure-ready image
make image-cloud

# Upload VHD (requires Azure CLI)
az storage blob upload \
    --account-name yourstorageaccount \
    --container-name images \
    --name ziro-os-enhanced.vhd \
    --file images/bootable/output/ziro-os-azure-*.vhd
```

#### 2. Create VM Image
```bash
# Create image from VHD
az image create \
    --resource-group your-rg \
    --name ziro-os-enhanced \
    --source https://yourstorageaccount.blob.core.windows.net/images/ziro-os-enhanced.vhd
```

#### 3. Deploy VM
```bash
# Create VM from custom image
az vm create \
    --resource-group your-rg \
    --name ziro-vm \
    --image ziro-os-enhanced \
    --size Standard_B2s \
    --admin-username admin \
    --ssh-key-values ~/.ssh/id_rsa.pub
```

### Google Cloud Platform Deployment

#### 1. Upload Image to GCS
```bash
# Build GCP-ready image
make image-cloud

# Upload to Google Cloud Storage
gsutil cp images/bootable/output/ziro-os-gcp-*.img gs://your-bucket/
```

#### 2. Create Custom Image
```bash
# Create GCP image
gcloud compute images create ziro-os-enhanced \
    --source-uri gs://your-bucket/ziro-os-gcp-*.img \
    --family ziro-os
```

#### 3. Launch Instance
```bash
# Create instance
gcloud compute instances create ziro-instance \
    --image-family ziro-os \
    --machine-type e2-medium \
    --zone us-central1-a \
    --metadata-from-file startup-script=startup.sh
```

## 🏢 Enterprise Deployment

### 1. Network Boot (PXE)
```bash
# Set up PXE server with Ziro-OS
mkdir -p /var/lib/tftpboot/ziro-os
cp images/bootable/output/vmlinuz-ziro /var/lib/tftpboot/ziro-os/
cp images/bootable/output/initramfs-ziro.gz /var/lib/tftpboot/ziro-os/

# Configure PXE menu
cat > /var/lib/tftpboot/pxelinux.cfg/default << 'EOF'
DEFAULT ziro-os
LABEL ziro-os
    KERNEL ziro-os/vmlinuz-ziro
    APPEND initrd=ziro-os/initramfs-ziro.gz console=tty0 console=ttyS0,115200n8 init=/etc/init-enhanced
EOF
```

### 2. Mass Deployment with Ansible
```yaml
# ansible-playbook.yml
---
- hosts: all
  become: yes
  tasks:
    - name: Download Ziro-OS ISO
      get_url:
        url: "{{ ziro_iso_url }}"
        dest: /tmp/ziro-os.iso
    
    - name: Create bootable USB
      command: dd if=/tmp/ziro-os.iso of={{ usb_device }} bs=4M
      when: usb_device is defined
    
    - name: Install Ziro-OS
      script: install-ziro-os.sh
      args:
        creates: /etc/ziro-release
```

### 3. Configuration Management
```bash
# Use ziroctl for configuration management
ziroctl config apply --file production-config.yaml

# Example production-config.yaml
apiVersion: ziro.os/v1
kind: SystemConfig
metadata:
  name: production
spec:
  networking:
    mode: bridge
    subnet: "10.0.0.0/16"
  security:
    firewall: enabled
    selinux: enforcing
  monitoring:
    enabled: true
    exporters:
      - node_exporter
      - cadvisor
  containers:
    runtime: containerd
    registry_mirrors:
      - "https://registry.company.com"
```

## 🔒 Security Hardening

### 1. Secure Boot Configuration
```bash
# Enable Secure Boot during build
ENABLE_SECURE_BOOT=true make image-advanced

# Verify Secure Boot status
mokutil --sb-state
```

### 2. Disk Encryption
```bash
# Install with encryption
ziro-install-advanced
# Select option 4 (Encrypted Installation)
# Follow prompts to set encryption passphrase
```

### 3. Network Security
```bash
# Configure firewall rules
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dport 2376 -j ACCEPT  # Docker daemon
iptables -A INPUT -j DROP

# Save rules
iptables-save > /etc/iptables/rules.v4
```

### 4. Container Security
```bash
# Configure containerd security
cat > /etc/containerd/config.toml << 'EOF'
version = 2

[plugins."io.containerd.grpc.v1.cri"]
  enable_selinux = true
  
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc]
  runtime_type = "io.containerd.runc.v2"
  
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc.options]
  SystemdCgroup = true
  
[plugins."io.containerd.grpc.v1.cri".registry.mirrors]
  [plugins."io.containerd.grpc.v1.cri".registry.mirrors."docker.io"]
    endpoint = ["https://registry-1.docker.io"]
EOF
```

## 📊 Monitoring and Observability

### 1. Built-in Monitoring
```bash
# Node exporter is included and runs on port 9100
curl http://localhost:9100/metrics

# Container metrics via cAdvisor
curl http://localhost:8080/metrics
```

### 2. Prometheus Configuration
```yaml
# prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'ziro-os-nodes'
    static_configs:
      - targets: ['node1:9100', 'node2:9100', 'node3:9100']
  
  - job_name: 'ziro-os-containers'
    static_configs:
      - targets: ['node1:8080', 'node2:8080', 'node3:8080']
```

### 3. Grafana Dashboard
```json
{
  "dashboard": {
    "title": "Ziro-OS Monitoring",
    "panels": [
      {
        "title": "CPU Usage",
        "type": "graph",
        "targets": [
          {
            "expr": "100 - (avg by (instance) (rate(node_cpu_seconds_total{mode=\"idle\"}[5m])) * 100)"
          }
        ]
      },
      {
        "title": "Memory Usage",
        "type": "graph",
        "targets": [
          {
            "expr": "(1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) * 100"
          }
        ]
      },
      {
        "title": "Container Count",
        "type": "singlestat",
        "targets": [
          {
            "expr": "sum(container_last_seen)"
          }
        ]
      }
    ]
  }
}
```

## 🔧 Troubleshooting

### Common Issues

#### 1. Boot Issues
```bash
# Check boot logs
dmesg | grep -i error

# Verify GRUB configuration
cat /boot/grub/grub.cfg

# Test different kernel parameters
# Add to GRUB: debug ignore_loglevel
```

#### 2. Container Runtime Issues
```bash
# Check containerd status
systemctl status containerd

# Debug containerd
containerd --log-level debug

# Check container logs
ctr containers list
ctr tasks list
```

#### 3. Network Issues
```bash
# Check network interfaces
ip addr show

# Test connectivity
ping 8.8.8.8

# Check CNI configuration
cat /etc/cni/net.d/*.conf

# Debug CNI
CNI_PATH=/opt/cni/bin cnitool add ziro-bridge /proc/1/ns/net
```

#### 4. Cloud-Init Issues
```bash
# Check cloud-init logs
cat /var/log/cloud-init.log
cat /var/log/cloud-init-output.log

# Debug cloud-init
cloud-init analyze show

# Re-run cloud-init
cloud-init clean
cloud-init init
```

### Performance Tuning

#### 1. Kernel Parameters
```bash
# Add to GRUB configuration
GRUB_CMDLINE_LINUX="cgroup_enable=memory swapaccount=1 systemd.unified_cgroup_hierarchy=1"
```

#### 2. Container Runtime Tuning
```bash
# Optimize containerd
cat > /etc/containerd/config.toml << 'EOF'
[plugins."io.containerd.grpc.v1.cri"]
  max_container_log_line_size = 16384
  
[plugins."io.containerd.grpc.v1.cri".containerd]
  snapshotter = "overlayfs"
  
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc.options]
  SystemdCgroup = true
EOF
```

#### 3. Storage Optimization
```bash
# Use faster storage drivers
mount -o noatime,nodiratime /dev/sda1 /var/lib/containerd

# Configure storage cleanup
cat > /etc/systemd/system/containerd-cleanup.timer << 'EOF'
[Unit]
Description=Cleanup containerd images and containers

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
EOF
```

## 📚 Additional Resources

- [Ziro-OS Architecture Guide](./architecture.md)
- [Container Runtime Configuration](./container-runtime.md)
- [Security Best Practices](./security.md)
- [Performance Optimization](./performance.md)
- [Troubleshooting Guide](./troubleshooting.md)

## 🤝 Support

For enterprise support and custom deployments:
- Documentation: [docs/](../docs/)
- Issues: [GitHub Issues](https://github.com/ziro-os/ziro-os/issues)
- Community: [Discussions](https://github.com/ziro-os/ziro-os/discussions)