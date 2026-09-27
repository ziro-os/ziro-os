#!/bin/bash
# Install Kubernetes components on Ziro-OS

set -e

K8S_VERSION="${K8S_VERSION:-v1.28.3}"
CRICTL_VERSION="${CRICTL_VERSION:-v1.28.0}"

echo "=== Installing Kubernetes on Ziro-OS ==="
echo "Kubernetes version: $K8S_VERSION"
echo "CRI-CTL version: $CRICTL_VERSION"

# Create directories
mkdir -p /opt/bin
mkdir -p /etc/kubernetes/manifests
mkdir -p /var/lib/kubelet
mkdir -p /var/lib/kubernetes

# Download Kubernetes binaries
echo "Downloading Kubernetes binaries..."
cd /opt/bin

# Download kubelet
curl -L "https://dl.k8s.io/release/${K8S_VERSION}/bin/linux/amd64/kubelet" -o kubelet
chmod +x kubelet

# Download kubectl
curl -L "https://dl.k8s.io/release/${K8S_VERSION}/bin/linux/amd64/kubectl" -o kubectl
chmod +x kubectl

# Download kube-proxy
curl -L "https://dl.k8s.io/release/${K8S_VERSION}/bin/linux/amd64/kube-proxy" -o kube-proxy
chmod +x kube-proxy

# Download crictl
curl -L "https://github.com/kubernetes-sigs/cri-tools/releases/download/${CRICTL_VERSION}/crictl-${CRICTL_VERSION}-linux-amd64.tar.gz" | tar -xz
chmod +x crictl

echo "✓ Kubernetes binaries installed"

# Create kubelet service
cat > /etc/systemd/system/kubelet.service << 'EOF'
[Unit]
Description=kubelet: The Kubernetes Node Agent
Documentation=https://kubernetes.io/docs/
Wants=network-online.target
After=network-online.target

[Service]
ExecStart=/opt/bin/kubelet
Restart=always
StartLimitInterval=0
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Create kubelet configuration directory
mkdir -p /etc/systemd/system/kubelet.service.d

# Create kubelet service configuration
cat > /etc/systemd/system/kubelet.service.d/10-kubeadm.conf << 'EOF'
[Service]
Environment="KUBELET_KUBECONFIG_ARGS=--bootstrap-kubeconfig=/etc/kubernetes/bootstrap-kubelet.conf --kubeconfig=/etc/kubernetes/kubelet.conf"
Environment="KUBELET_CONFIG_ARGS=--config=/var/lib/kubelet/config.yaml"
Environment="KUBELET_KUBEADM_ARGS=--container-runtime-endpoint=unix:///run/containerd/containerd.sock --pod-infra-container-image=registry.k8s.io/pause:3.9"
Environment="KUBELET_EXTRA_ARGS="
ExecStart=
ExecStart=/opt/bin/kubelet $KUBELET_KUBECONFIG_ARGS $KUBELET_CONFIG_ARGS $KUBELET_KUBEADM_ARGS $KUBELET_EXTRA_ARGS
EOF

# Configure crictl
cat > /etc/crictl.yaml << 'EOF'
runtime-endpoint: unix:///run/containerd/containerd.sock
image-endpoint: unix:///run/containerd/containerd.sock
timeout: 2
debug: false
pull-image-on-create: false
EOF

# Create CNI configuration for Kubernetes
cat > /etc/cni/net.d/10-containerd-net.conflist << 'EOF'
{
  "cniVersion": "1.0.0",
  "name": "containerd-net",
  "plugins": [
    {
      "type": "bridge",
      "bridge": "cni0",
      "isGateway": true,
      "ipMasq": true,
      "promiscMode": true,
      "ipam": {
        "type": "host-local",
        "ranges": [
          [{
            "subnet": "10.88.0.0/16"
          }]
        ],
        "routes": [
          { "dst": "0.0.0.0/0" }
        ]
      }
    },
    {
      "type": "portmap",
      "capabilities": {"portMappings": true}
    }
  ]
}
EOF

# Enable and start services
systemctl daemon-reload
systemctl enable kubelet

echo ""
echo "✅ Kubernetes installation complete!"
echo ""
echo "Next steps:"
echo "1. Join cluster: kubeadm join <master-ip>:6443 --token <token> --discovery-token-ca-cert-hash <hash>"
echo "2. Or initialize cluster: kubeadm init --pod-network-cidr=10.244.0.0/16"
echo ""
echo "Installed components:"
echo "  - kubelet: /opt/bin/kubelet"
echo "  - kubectl: /opt/bin/kubectl"
echo "  - kube-proxy: /opt/bin/kube-proxy"
echo "  - crictl: /opt/bin/crictl"