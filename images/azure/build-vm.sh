#!/bin/bash
# Build Azure VM image for Ziro-OS

set -e

RESOURCE_GROUP="${AZURE_RESOURCE_GROUP:-ziro-os-rg}"
LOCATION="${AZURE_LOCATION:-westus2}"
IMAGE_NAME="ziro-os-$(date +%Y%m%d-%H%M%S)"
OUTPUT_DIR="./output"

echo "=== Building Ziro-OS Azure VM Image ==="
echo "Resource Group: $RESOURCE_GROUP"
echo "Location: $LOCATION"
echo "Image Name: $IMAGE_NAME"

mkdir -p "$OUTPUT_DIR"

# Check prerequisites
if ! command -v az > /dev/null; then
    echo "❌ Azure CLI not found. Please install Azure CLI."
    exit 1
fi

# Verify Azure login
if ! az account show > /dev/null 2>&1; then
    echo "❌ Not logged into Azure. Please run 'az login'."
    exit 1
fi

echo "✓ Prerequisites checked"

# Create resource group if it doesn't exist
echo "Creating resource group..."
az group create --name "$RESOURCE_GROUP" --location "$LOCATION" || true

# Create Packer template for Azure
cat > "$OUTPUT_DIR/ziro-os-azure.pkr.hcl" << 'EOF'
packer {
  required_plugins {
    azure = {
      version = ">= 1.4.0"
      source  = "github.com/hashicorp/azure"
    }
  }
}

variable "resource_group" {
  type = string
}

variable "location" {
  type = string
}

variable "image_name" {
  type = string
}

source "azure-arm" "ziro-os" {
  use_azure_cli_auth = true
  
  managed_image_resource_group_name = var.resource_group
  managed_image_name               = var.image_name
  
  os_type         = "Linux"
  image_publisher = "Canonical"
  image_offer     = "0001-com-ubuntu-server-jammy"
  image_sku       = "22_04-lts-gen2"
  
  location = var.location
  vm_size  = "Standard_B1s"
  
  azure_tags = {
    Name = "Ziro-OS"
    OS   = "Ziro-OS"
    Type = "Container-Native"
  }
}

build {
  name = "ziro-os"
  sources = [
    "source.azure-arm.ziro-os"
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
    script = "./install-ziro-os-azure.sh"
  }
  
  # Deprovision for Azure
  provisioner "shell" {
    execute_command = "chmod +x {{ .Path }}; {{ .Vars }} sudo -E sh '{{ .Path }}'"
    inline = [
      "/usr/sbin/waagent -force -deprovision+user && export HISTSIZE=0 && sync"
    ]
    inline_shebang = "/bin/sh -x"
  }
}
EOF

# Create Azure-specific installation script
cat > "$OUTPUT_DIR/install-ziro-os-azure.sh" << 'EOF'
#!/bin/bash
# Install Ziro-OS on Azure VM

set -e

echo "Installing Ziro-OS for Azure..."

# Install required packages
sudo apt-get update
sudo apt-get install -y qemu-utils cloud-init walinuxagent

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
    
    linux /boot/ziro-os/vmlinuz console=tty0 console=ttyS0,115200n8 init=/etc/init rootdelay=300
    initrd /boot/ziro-os/initramfs.cpio.gz
}
GRUB_EOF

sudo chmod +x /etc/grub.d/40_custom
sudo update-grub

# Set Ziro-OS as default
sudo sed -i 's/GRUB_DEFAULT=0/GRUB_DEFAULT="Ziro-OS"/' /etc/default/grub
sudo update-grub

# Configure Azure Linux Agent
sudo systemctl enable walinuxagent

echo "Ziro-OS Azure installation complete"
EOF

chmod +x "$OUTPUT_DIR/install-ziro-os-azure.sh"

# Build VM image with Packer
echo "Building Azure VM image with Packer..."
cd "$OUTPUT_DIR"
packer build \
    -var "resource_group=$RESOURCE_GROUP" \
    -var "location=$LOCATION" \
    -var "image_name=$IMAGE_NAME" \
    ziro-os-azure.pkr.hcl

echo ""
echo "✅ Azure VM image build complete!"
echo "Image Name: $IMAGE_NAME"
echo "Resource Group: $RESOURCE_GROUP"
echo "Location: $LOCATION"
echo ""
echo "To create a VM from this image:"
echo "  az vm create --resource-group $RESOURCE_GROUP --name ziro-os-vm --image $IMAGE_NAME --admin-username azureuser --generate-ssh-keys"