#!/bin/bash
# Build GCP image for Ziro-OS

set -e

PROJECT_ID="${GCP_PROJECT_ID:-$(gcloud config get-value project)}"
ZONE="${GCP_ZONE:-us-central1-a}"
IMAGE_NAME="ziro-os-$(date +%Y%m%d-%H%M%S)"
IMAGE_FAMILY="ziro-os"
OUTPUT_DIR="./output"

echo "=== Building Ziro-OS GCP Image ==="
echo "Project ID: $PROJECT_ID"
echo "Zone: $ZONE"
echo "Image Name: $IMAGE_NAME"
echo "Image Family: $IMAGE_FAMILY"

mkdir -p "$OUTPUT_DIR"

# Check prerequisites
if ! command -v gcloud > /dev/null; then
    echo "❌ Google Cloud SDK not found. Please install gcloud."
    exit 1
fi

if ! command -v packer > /dev/null; then
    echo "❌ Packer not found. Please install Packer."
    exit 1
fi

# Verify GCP authentication
if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" | head -1 > /dev/null; then
    echo "❌ Not authenticated with GCP. Please run 'gcloud auth login'."
    exit 1
fi

if [ -z "$PROJECT_ID" ]; then
    echo "❌ GCP project not set. Please run 'gcloud config set project PROJECT_ID'."
    exit 1
fi

echo "✓ Prerequisites checked"

# Enable required APIs
echo "Enabling required GCP APIs..."
gcloud services enable compute.googleapis.com --project="$PROJECT_ID" || true

# Create Packer template for GCP
cat > "$OUTPUT_DIR/ziro-os-gcp.pkr.hcl" << 'EOF'
packer {
  required_plugins {
    googlecompute = {
      version = ">= 1.1.1"
      source  = "github.com/hashicorp/googlecompute"
    }
  }
}

variable "project_id" {
  type = string
}

variable "zone" {
  type = string
}

variable "image_name" {
  type = string
}

variable "image_family" {
  type = string
}

source "googlecompute" "ziro-os" {
  project_id   = var.project_id
  source_image = "ubuntu-2204-jammy-v20231030"
  zone         = var.zone
  
  image_name        = var.image_name
  image_family      = var.image_family
  image_description = "Ziro-OS - Container-native operating system"
  
  machine_type = "e2-micro"
  disk_size    = 10
  
  ssh_username = "packer"
  
  image_labels = {
    os   = "ziro-os"
    type = "container-native"
  }
}

build {
  name = "ziro-os"
  sources = [
    "source.googlecompute.ziro-os"
  ]

  # Upload Ziro-OS files
  provisioner "file" {
    source      = "../../kernel/bzImage"
    destination = "/tmp/bzImage"
  }
  
  provisioner "file" {
    source      = "../../rootfs/"
    destination = "/tmp/rootfs/"
  }

  # Install and configure Ziro-OS
  provisioner "shell" {
    script = "./install-ziro-os-gcp.sh"
  }
}
EOF

# Create GCP-specific installation script
cat > "$OUTPUT_DIR/install-ziro-os-gcp.sh" << 'EOF'
#!/bin/bash
# Install Ziro-OS on GCP instance

set -e

echo "Installing Ziro-OS for GCP..."

# Install required packages
sudo apt-get update
sudo apt-get install -y qemu-utils cloud-init google-cloud-ops-agent

# Create Ziro-OS boot configuration
sudo mkdir -p /boot/ziro-os
sudo cp /tmp/bzImage /boot/ziro-os/vmlinuz

# Create initramfs from rootfs
cd /tmp
sudo find rootfs | sudo cpio -o -H newc | sudo gzip > /boot/ziro-os/initramfs.cpio.gz

# Configure GRUB for Ziro-OS
sudo tee /etc/grub.d/40_custom << 'GRUB_EOF'
#!/bin/sh
exec tail -n +3 $0

menuentry 'Ziro-OS' --class ziro --class gnu-linux --class gnu --class os {
    recordfail
    load_video
    gfxmode $linux_gfx_mode
    insmod gzio
    insmod part_gpt
    insmod ext2
    
    linux /boot/ziro-os/vmlinuz console=tty0 console=ttyS0,38400n8 init=/etc/init
    initrd /boot/ziro-os/initramfs.cpio.gz
}
GRUB_EOF

sudo chmod +x /etc/grub.d/40_custom
sudo update-grub

# Set Ziro-OS as default
sudo sed -i 's/GRUB_DEFAULT=0/GRUB_DEFAULT="Ziro-OS"/' /etc/default/grub
sudo update-grub

# Configure GCP-specific services
sudo systemctl enable google-cloud-ops-agent

# Configure cloud-init for GCP
sudo tee /etc/cloud/cloud.cfg.d/99-ziro-os-gcp.cfg << 'CLOUD_EOF'
# Ziro-OS GCP cloud-init configuration
datasource_list: [ GCE, None ]

# GCP-specific settings
system_info:
  default_user:
    name: ziro
    lock_passwd: true
    gecos: Ziro-OS User
    groups: [adm, audio, cdrom, dialout, dip, floppy, lxd, netdev, plugdev, sudo, video]
    sudo: ["ALL=(ALL) NOPASSWD:ALL"]
    shell: /bin/bash
CLOUD_EOF

echo "Ziro-OS GCP installation complete"
EOF

chmod +x "$OUTPUT_DIR/install-ziro-os-gcp.sh"

# Build GCP image with Packer
echo "Building GCP image with Packer..."
cd "$OUTPUT_DIR"
packer build \
    -var "project_id=$PROJECT_ID" \
    -var "zone=$ZONE" \
    -var "image_name=$IMAGE_NAME" \
    -var "image_family=$IMAGE_FAMILY" \
    ziro-os-gcp.pkr.hcl

echo ""
echo "✅ GCP image build complete!"
echo "Image Name: $IMAGE_NAME"
echo "Image Family: $IMAGE_FAMILY"
echo "Project: $PROJECT_ID"
echo ""
echo "To create an instance from this image:"
echo "  gcloud compute instances create ziro-os-vm --image-family=$IMAGE_FAMILY --zone=$ZONE"