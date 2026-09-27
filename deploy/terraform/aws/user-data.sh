#!/bin/bash
# AWS user-data script for Ziro-OS nodes

set -e

CLUSTER_NAME="${cluster_name}"
NODE_NAME=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)

echo "=== Ziro-OS Node Bootstrap ==="
echo "Cluster: $CLUSTER_NAME"
echo "Node: $NODE_NAME"

# Wait for Ziro-OS to be ready
while ! systemctl is-active containerd > /dev/null 2>&1; do
    echo "Waiting for containerd to be ready..."
    sleep 5
done

echo "✓ Containerd is ready"

# Install Kubernetes components
if [ ! -f /opt/bin/kubelet ]; then
    echo "Installing Kubernetes..."
    curl -fsSL https://raw.githubusercontent.com/ziro-os/ziro-os/main/kubernetes/install-k8s.sh | bash
fi

# Configure node labels
cat > /etc/kubernetes/kubelet-extra-args << EOF
--node-labels=node.kubernetes.io/instance-type=ziro-os
--node-labels=topology.kubernetes.io/zone=$(curl -s http://169.254.169.254/latest/meta-data/placement/availability-zone)
--node-labels=node.kubernetes.io/cluster=$CLUSTER_NAME
EOF

# Start kubelet
systemctl enable kubelet
systemctl start kubelet

# Install monitoring
if [ ! -f /opt/monitoring/prometheus/prometheus ]; then
    echo "Installing monitoring..."
    curl -fsSL https://raw.githubusercontent.com/ziro-os/ziro-os/main/monitoring/install-monitoring.sh | bash
    systemctl enable prometheus node-exporter cadvisor
    systemctl start prometheus node-exporter cadvisor
fi

# Apply security hardening
if [ ! -f /etc/security/limits.d/ziro-os.conf ]; then
    echo "Applying security hardening..."
    curl -fsSL https://raw.githubusercontent.com/ziro-os/ziro-os/main/security/harden-system.sh | bash
fi

# Signal completion
/opt/aws/bin/cfn-signal -e $? --stack ${AWS::StackName} --resource AutoScalingGroup --region ${AWS::Region} || true

echo "✅ Ziro-OS node bootstrap complete"