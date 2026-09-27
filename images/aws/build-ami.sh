#!/bin/bash
# Build AWS AMI for Ziro-OS

set -e

REGION="${AWS_REGION:-us-west-2}"
INSTANCE_TYPE="${INSTANCE_TYPE:-t3.micro}"
AMI_NAME="ziro-os-$(date +%Y%m%d-%H%M%S)"
OUTPUT_DIR="./output"

echo "=== Building Ziro-OS AWS AMI ==="
echo "Region: $REGION"
echo "Instance Type: $INSTANCE_TYPE"
echo "AMI Name: $AMI_NAME"

mkdir -p "$OUTPUT_DIR"

# Check prerequisites
if ! command -v packer > /dev/null; then
    echo "❌ Packer not found. Please install Packer."
    exit 1
fi

if ! command -v aws > /dev/null; then
    echo "❌ AWS CLI not found. Please install AWS CLI."
    exit 1
fi

# Verify AWS credentials
if ! aws sts get-caller-identity > /dev/null 2>&1; then
    echo "❌ AWS credentials not configured. Please run 'aws configure'."
    exit 1
fi

echo "✓ Prerequisites checked"

# Create Packer template
cat > "$OUTPUT_DIR/ziro-os.pkr.hcl" << 'EOF'
packer {
  required_plugins {
    amazon = {
      version = ">= 1.2.8"
      source  = "github.com/hashicorp/amazon"
    }
  }
}

variable "region" {
  type    = string
  default = "us-west-2"
}

variable "instance_type" {
  type    = string
  default = "t3.micro"
}

variable "ami_name" {
  type = string
}

source "amazon-ebs" "ziro-os" {
  ami_name      = var.ami_name
  instance_type = var.instance_type
  region        = var.region
  
  source_ami_filter {
    filters = {
      name                = "ubuntu/images/*ubuntu-jammy-22.04-amd64-server-*"
      root-device-type    = "ebs"
      virtualization-type = "hvm"
    }
    most_recent = true
    owners      = ["099720109477"] # Canonical
  }
  
  ssh_username = "ubuntu"
  
  tags = {
    Name = "Ziro-OS"
    OS   = "Ziro-OS"
    Type = "Container-Native"
  }
}

build {
  name = "ziro-os"
  sources = [
    "source.amazon-ebs.ziro-os"
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
    script = "./install-ziro-os.sh"
  }
}
EOF

# Create installation script
cat > "$OUTPUT_DIR/install-ziro-os.sh" << 'EOF'
#!/bin/bash
# Install Ziro-OS on AWS instance

set -e

echo "Installing Ziro-OS..."

# Install required packages
sudo apt-get update
sudo apt-get install -y qemu-utils cloud-init

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
    
    linux /boot/ziro-os/vmlinuz console=tty0 console=ttyS0,115200n8 init=/etc/init
    initrd /boot/ziro-os/initramfs.cpio.gz
}
GRUB_EOF

sudo chmod +x /etc/grub.d/40_custom
sudo update-grub

# Set Ziro-OS as default
sudo sed -i 's/GRUB_DEFAULT=0/GRUB_DEFAULT="Ziro-OS"/' /etc/default/grub
sudo update-grub

# Configure cloud-init for Ziro-OS
sudo tee /etc/cloud/cloud.cfg.d/99-ziro-os.cfg << 'CLOUD_EOF'
# Ziro-OS cloud-init configuration
datasource_list: [ Ec2, None ]
cloud_init_modules:
 - migrator
 - seed_random
 - bootcmd
 - write-files
 - growpart
 - resizefs
 - disk_setup
 - mounts
 - set_hostname
 - update_hostname
 - update_etc_hosts
 - ca-certs
 - rsyslog
 - users-groups
 - ssh

cloud_config_modules:
 - emit_upstart
 - snap
 - ssh-import-id
 - locale
 - set-passwords
 - grub-dpkg
 - apt-pipelining
 - apt-configure
 - ubuntu-advantage
 - ntp
 - timezone
 - disable-ec2-metadata
 - runcmd

cloud_final_modules:
 - package-update-upgrade-install
 - fan
 - landscape
 - lxd
 - ubuntu-drivers
 - puppet
 - chef
 - mcollective
 - salt-minion
 - rightscale_userdata
 - scripts-vendor
 - scripts-per-once
 - scripts-per-boot
 - scripts-per-instance
 - scripts-user
 - ssh-authkey-fingerprints
 - keys-to-console
 - phone-home
 - final-message
 - power-state-change
CLOUD_EOF

echo "Ziro-OS installation complete"
EOF

chmod +x "$OUTPUT_DIR/install-ziro-os.sh"

# Build AMI with Packer
echo "Building AMI with Packer..."
cd "$OUTPUT_DIR"
packer build \
    -var "region=$REGION" \
    -var "instance_type=$INSTANCE_TYPE" \
    -var "ami_name=$AMI_NAME" \
    ziro-os.pkr.hcl

echo ""
echo "✅ AWS AMI build complete!"
echo "AMI Name: $AMI_NAME"
echo "Region: $REGION"
echo ""
echo "To launch an instance:"
echo "  aws ec2 describe-images --filters 'Name=name,Values=$AMI_NAME' --region $REGION"