# Image Building

Scripts and configurations for building Ziro-OS images.

## Structure
- `qemu/` - QEMU VM images and scripts
- `aws/` - AWS AMI builder scripts  
- `azure/` - Azure VM image scripts
- `generic/` - Generic VM/ISO builder
- `cloud-init/` - Cloud-init configurations

## Usage
Run `make image-qemu` to build a QEMU-compatible image for testing.