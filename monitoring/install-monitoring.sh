#!/bin/bash
# Install monitoring and observability for Ziro-OS

set -e

PROMETHEUS_VERSION="${PROMETHEUS_VERSION:-2.47.2}"
NODE_EXPORTER_VERSION="${NODE_EXPORTER_VERSION:-1.6.1}"
CADVISOR_VERSION="${CADVISOR_VERSION:-v0.47.2}"

echo "=== Installing Ziro-OS Monitoring Stack ==="

# Create monitoring directories
mkdir -p /opt/monitoring/{prometheus,node-exporter,cadvisor}
mkdir -p /etc/prometheus
mkdir -p /var/lib/prometheus

echo "1. Installing Prometheus..."

# Download Prometheus
cd /opt/monitoring/prometheus
curl -L "https://github.com/prometheus/prometheus/releases/download/v${PROMETHEUS_VERSION}/prometheus-${PROMETHEUS_VERSION}.linux-amd64.tar.gz" | tar -xz --strip-components=1

# Create Prometheus configuration
cat > /etc/prometheus/prometheus.yml << 'EOF'
# Ziro-OS Prometheus configuration

global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "/etc/prometheus/rules/*.yml"

scrape_configs:
  # Prometheus itself
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']

  # Node Exporter
  - job_name: 'node-exporter'
    static_configs:
      - targets: ['localhost:9100']

  # cAdvisor for container metrics
  - job_name: 'cadvisor'
    static_configs:
      - targets: ['localhost:8080']

  # Containerd metrics
  - job_name: 'containerd'
    static_configs:
      - targets: ['localhost:1338']

  # Kubernetes components (if available)
  - job_name: 'kubelet'
    scheme: https
    tls_config:
      ca_file: /var/lib/kubelet/pki/kubelet-ca.crt
      cert_file: /var/lib/kubelet/pki/kubelet-client.crt
      key_file: /var/lib/kubelet/pki/kubelet-client.key
      insecure_skip_verify: true
    static_configs:
      - targets: ['localhost:10250']
    metrics_path: /metrics

  - job_name: 'kubelet-cadvisor'
    scheme: https
    tls_config:
      ca_file: /var/lib/kubelet/pki/kubelet-ca.crt
      cert_file: /var/lib/kubelet/pki/kubelet-client.crt
      key_file: /var/lib/kubelet/pki/kubelet-client.key
      insecure_skip_verify: true
    static_configs:
      - targets: ['localhost:10250']
    metrics_path: /metrics/cadvisor
EOF

# Create Prometheus alerting rules
mkdir -p /etc/prometheus/rules
cat > /etc/prometheus/rules/ziro-os.yml << 'EOF'
groups:
- name: ziro-os
  rules:
  - alert: HighCPUUsage
    expr: 100 - (avg by(instance) (irate(node_cpu_seconds_total{mode="idle"}[5m])) * 100) > 80
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "High CPU usage on {{ $labels.instance }}"
      description: "CPU usage is above 80% for more than 5 minutes"

  - alert: HighMemoryUsage
    expr: (node_memory_MemTotal_bytes - node_memory_MemAvailable_bytes) / node_memory_MemTotal_bytes * 100 > 90
    for: 5m
    labels:
      severity: critical
    annotations:
      summary: "High memory usage on {{ $labels.instance }}"
      description: "Memory usage is above 90% for more than 5 minutes"

  - alert: ContainerdDown
    expr: up{job="containerd"} == 0
    for: 1m
    labels:
      severity: critical
    annotations:
      summary: "Containerd is down"
      description: "Containerd has been down for more than 1 minute"

  - alert: HighContainerCount
    expr: container_tasks_state{state="running"} > 50
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "High number of running containers"
      description: "More than 50 containers are running"
EOF

echo "2. Installing Node Exporter..."

# Download Node Exporter
cd /opt/monitoring/node-exporter
curl -L "https://github.com/prometheus/node_exporter/releases/download/v${NODE_EXPORTER_VERSION}/node_exporter-${NODE_EXPORTER_VERSION}.linux-amd64.tar.gz" | tar -xz --strip-components=1

echo "3. Installing cAdvisor..."

# Download cAdvisor
cd /opt/monitoring/cadvisor
curl -L "https://github.com/google/cadvisor/releases/download/${CADVISOR_VERSION}/cadvisor-${CADVISOR_VERSION}-linux-amd64" -o cadvisor
chmod +x cadvisor

echo "4. Creating systemd services..."

# Prometheus service
cat > /etc/systemd/system/prometheus.service << 'EOF'
[Unit]
Description=Prometheus Server
Documentation=https://prometheus.io/docs/
After=network-online.target

[Service]
User=prometheus
Group=prometheus
Type=simple
ExecStart=/opt/monitoring/prometheus/prometheus \
  --config.file=/etc/prometheus/prometheus.yml \
  --storage.tsdb.path=/var/lib/prometheus/ \
  --web.console.templates=/opt/monitoring/prometheus/consoles \
  --web.console.libraries=/opt/monitoring/prometheus/console_libraries \
  --web.listen-address=0.0.0.0:9090 \
  --web.external-url=http://localhost:9090 \
  --storage.tsdb.retention.time=15d
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# Node Exporter service
cat > /etc/systemd/system/node-exporter.service << 'EOF'
[Unit]
Description=Prometheus Node Exporter
Documentation=https://prometheus.io/docs/guides/node-exporter/
After=network-online.target

[Service]
User=node-exporter
Group=node-exporter
Type=simple
ExecStart=/opt/monitoring/node-exporter/node_exporter \
  --web.listen-address=0.0.0.0:9100 \
  --path.procfs=/proc \
  --path.sysfs=/sys \
  --collector.filesystem.ignored-mount-points="^/(sys|proc|dev|host|etc|rootfs/var/lib/docker/containers|rootfs/var/lib/docker/overlay2|rootfs/run/docker/netns|rootfs/var/lib/docker/aufs)($$|/)"
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# cAdvisor service
cat > /etc/systemd/system/cadvisor.service << 'EOF'
[Unit]
Description=cAdvisor
Documentation=https://github.com/google/cadvisor
After=network-online.target

[Service]
User=root
Group=root
Type=simple
ExecStart=/opt/monitoring/cadvisor/cadvisor \
  --port=8080 \
  --logtostderr \
  --docker_only=false \
  --housekeeping_interval=30s \
  --max_housekeeping_interval=35s \
  --event_storage_event_limit=default=0 \
  --event_storage_age_limit=default=0 \
  --disable_metrics=percpu,sched,tcp,udp,disk,diskIO,accelerator,hugetlb,referenced_memory,cpu_topology,resctrl
Restart=always

[Install]
WantedBy=multi-user.target
EOF

echo "5. Creating monitoring users..."

# Create users for monitoring services
useradd --no-create-home --shell /bin/false prometheus || true
useradd --no-create-home --shell /bin/false node-exporter || true

# Set permissions
chown -R prometheus:prometheus /etc/prometheus /var/lib/prometheus
chown -R prometheus:prometheus /opt/monitoring/prometheus
chown -R node-exporter:node-exporter /opt/monitoring/node-exporter

echo "6. Creating monitoring dashboard..."

# Simple monitoring dashboard script
cat > /opt/monitoring/dashboard.sh << 'EOF'
#!/bin/bash
# Simple monitoring dashboard for Ziro-OS

echo "=== Ziro-OS System Dashboard ==="
echo "Timestamp: $(date)"
echo ""

echo "System Resources:"
echo "  CPU Usage: $(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)%"
echo "  Memory: $(free -h | awk 'NR==2{printf "%.1f%%", $3*100/$2 }')"
echo "  Disk: $(df -h / | awk 'NR==2{print $5}')"
echo ""

echo "Container Runtime:"
if pgrep containerd > /dev/null; then
    echo "  Containerd: ✓ Running"
    echo "  Containers: $(ctr containers list -q | wc -l) total"
    echo "  Images: $(ctr images list -q | wc -l) total"
else
    echo "  Containerd: ✗ Not running"
fi
echo ""

echo "Kubernetes (if available):"
if command -v kubectl > /dev/null && kubectl cluster-info > /dev/null 2>&1; then
    echo "  Cluster: ✓ Connected"
    echo "  Nodes: $(kubectl get nodes --no-headers | wc -l)"
    echo "  Pods: $(kubectl get pods --all-namespaces --no-headers | wc -l)"
else
    echo "  Cluster: ✗ Not available"
fi
echo ""

echo "Network:"
echo "  Interfaces: $(ip link show | grep -E '^[0-9]+:' | wc -l)"
echo "  Bridge: $(ip link show | grep -c 'ziro-br0\|ziro0\|cni0' || echo '0')"
echo ""

echo "Monitoring Services:"
systemctl is-active prometheus 2>/dev/null | sed 's/^/  Prometheus: /'
systemctl is-active node-exporter 2>/dev/null | sed 's/^/  Node Exporter: /'
systemctl is-active cadvisor 2>/dev/null | sed 's/^/  cAdvisor: /'
EOF

chmod +x /opt/monitoring/dashboard.sh

echo "7. Enabling services..."

# Enable and start services
systemctl daemon-reload
systemctl enable prometheus node-exporter cadvisor

echo ""
echo "✅ Monitoring installation complete!"
echo ""
echo "Services installed:"
echo "  - Prometheus: http://localhost:9090"
echo "  - Node Exporter: http://localhost:9100"
echo "  - cAdvisor: http://localhost:8080"
echo ""
echo "To start monitoring:"
echo "  systemctl start prometheus node-exporter cadvisor"
echo ""
echo "To view dashboard:"
echo "  /opt/monitoring/dashboard.sh"
echo ""
echo "Monitoring data locations:"
echo "  - Prometheus config: /etc/prometheus/"
echo "  - Prometheus data: /var/lib/prometheus/"
echo "  - Binaries: /opt/monitoring/"