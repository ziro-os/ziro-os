#!/bin/sh
# Ziro-OS Fast Cloud-Native Disk Installer (TUI & Unattended)
# Minimal by design. Born for the cloud.

set -eu

# Color constants
BOLD="\033[1m"
GREEN="\033[1;32m"
CYAN="\033[1;36m"
YELLOW="\033[1;33m"
RED="\033[1;31m"
BLUE="\033[1;34m"
RESET="\033[0m"

print_banner() {
    printf "${CYAN}"
    cat << "EOF"
  _____  _               ___  ____  
 |__  / (_) _ __  ___   / _ \/ ___| 
   / /  | || '__/ _ \ | | | \___ \ 
  / /_  | || |  | (_) || |_| |___) |
 |____| |_||_|   \___/  \___/|____/ 

 Minimal by design. Born for the cloud.
 Ziro-OS Fast Cloud-Native Disk Installer
EOF
    printf "${RESET}\n"
}

usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS]

Options:
  -d, --disk <device>        Target disk device (e.g. /dev/vda, /dev/sda, /dev/nvme0n1)
  -n, --hostname <name>      System hostname (default: ziro-host)
  -k, --ssh-key <key|file>   SSH public key string or path to public key file
  -p, --password <pass>      Root password (visible in ps; prefer env ZIRO_ROOT_PASSWORD)
  -u, --user-data <url|file> Cloud user-data / post-installation script (URL or local path)
      --net-mode <mode>      Network mode: 'dhcp' (default), 'static', or 'skip'
      --ip <ip/cidr>         Static IPv4 address and CIDR (e.g. 192.168.1.50/24)
      --gateway <gw>         Default gateway IPv4 address
      --dns <servers>        Space-separated DNS nameservers (default: 1.1.1.1 8.8.8.8)
      --iface <interface>    Target network interface (default: first active interface)
  -y, --yes                  Auto-confirm installation without interactive prompts
  -h, --help                 Show this help message

Examples:
  # Interactive guided TUI installation:
  $(basename "$0")

  # Automated unattended installation with DHCP:
  $(basename "$0") -d /dev/sda -n ziro-node-1 -k "ssh-ed25519 AAAA..." -y

  # Automated installation with Static IP (Rocky/RHEL style):
  $(basename "$0") -d /dev/vda -n ziro-node-1 --ip 192.168.1.50/24 --gateway 192.168.1.1 --dns "1.1.1.1 8.8.8.8" -y

  # Automated with remote cloud user-data script:
  $(basename "$0") -d /dev/sda -u https://example.com/user-data.sh -y
EOF
}

TARGET_DISK=""
TARGET_HOSTNAME="ziro-host"
SSH_KEY=""
PASSWORD="${ZIRO_ROOT_PASSWORD:-}"
USER_DATA=""
AUTO_CONFIRM=0
NET_MODE="dhcp"
NET_IFACE=""
NET_IP=""
NET_GATEWAY=""
NET_DNS="1.1.1.1 8.8.8.8"

# Parse kernel command line for automated cloud provisioning
parse_cmdline() {
    if [ -f /proc/cmdline ]; then
        for arg in $(cat /proc/cmdline); do
            case "$arg" in
                ziro.install=*)
                    TARGET_DISK="${arg#ziro.install=}"
                    AUTO_CONFIRM=1
                    ;;
                ziro.hostname=*)
                    TARGET_HOSTNAME="${arg#ziro.hostname=}"
                    ;;
                ziro.sshkey=*)
                    SSH_KEY="${arg#ziro.sshkey=}"
                    ;;
                ziro.userdata=*)
                    USER_DATA="${arg#ziro.userdata=}"
                    ;;
                ziro.autoinstall)
                    AUTO_CONFIRM=1
                    ;;
                ziro.net=*)
                    NET_MODE="${arg#ziro.net=}"
                    ;;
                ziro.ip=*)
                    NET_IP="${arg#ziro.ip=}"
                    NET_MODE="static"
                    ;;
                ziro.gw=*|ziro.gateway=*)
                    NET_GATEWAY="${arg#*=}"
                    ;;
                ziro.dns=*)
                    NET_DNS="${arg#ziro.dns=}"
                    ;;
                ziro.iface=*)
                    NET_IFACE="${arg#ziro.iface=}"
                    ;;
            esac
        done
    fi
}

# Parse CLI arguments
parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            -d|--disk)
                TARGET_DISK="$2"
                shift 2
                ;;
            -n|--hostname)
                TARGET_HOSTNAME="$2"
                shift 2
                ;;
            -k|--ssh-key)
                SSH_KEY="$2"
                shift 2
                ;;
            -p|--password)
                PASSWORD="$2"
                shift 2
                ;;
            -u|--user-data)
                USER_DATA="$2"
                shift 2
                ;;
            --net-mode)
                NET_MODE="$2"
                shift 2
                ;;
            --ip)
                NET_IP="$2"
                NET_MODE="static"
                shift 2
                ;;
            --gateway|--gw)
                NET_GATEWAY="$2"
                shift 2
                ;;
            --dns)
                NET_DNS="$2"
                shift 2
                ;;
            --iface)
                NET_IFACE="$2"
                shift 2
                ;;
            -y|--yes)
                AUTO_CONFIRM=1
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
}

detect_disks() {
    # 1. Proactively probe virtualization, SCSI, SATA, and NVMe kernel drivers
    for mod in virtio_pci virtio_blk virtio_scsi scsi_mod sd_mod sr_mod ahci ata_piix ata_generic nvme nvme_core; do
        modprobe -q "$mod" 2>/dev/null || true
    done
    mdev -s 2>/dev/null || true

    DISKS=""
    # 2. Scan /sys/block for candidate drives
    for devpath in /sys/block/*; do
        devname=$(basename "$devpath")
        case "$devname" in
            loop*|ram*|sr*|fd*|dm-*|zram*)
                continue
                ;;
        esac

        # Dynamically create device node in /dev if missing
        if [ ! -b "/dev/$devname" ] && [ -f "$devpath/dev" ]; then
            majmin=$(cat "$devpath/dev" 2>/dev/null || echo "")
            if [ -n "$majmin" ]; then
                maj="${majmin%:*}"
                min="${majmin#*:}"
                mknod -m 660 "/dev/$devname" b "$maj" "$min" 2>/dev/null || true
            fi
        fi

        # Verify device node exists in /dev
        if [ -b "/dev/$devname" ]; then
            # Check if read-only
            if [ -f "$devpath/ro" ] && [ "$(cat "$devpath/ro" 2>/dev/null || echo 0)" = "1" ]; then
                continue
            fi
            
            # Fetch human-readable size
            size_bytes=$(cat "$devpath/size" 2>/dev/null || echo 0)
            size_mb=$((size_bytes * 512 / 1024 / 1024))
            if [ "$size_mb" -lt 100 ]; then
                continue # Skip devices smaller than 100MB
            fi
            
            DISKS="$DISKS /dev/$devname"
        fi
    done
    echo "$DISKS"
}

interactive_prompts() {
    print_banner

    echo "Scanning available storage drives..."
    AVAILABLE_DISKS=$(detect_disks)
    
    if [ -z "$AVAILABLE_DISKS" ]; then
        printf "${RED}❌ No candidate storage drives found!${RESET}\n"
        echo "Ensure a virtual hard disk (VirtIO, SCSI, SATA, NVMe) is attached to the VM."
        exit 1
    fi

    echo ""
    printf "${BOLD}Available Storage Disks:${RESET}\n"
    i=1
    disk_array=""
    for d in $AVAILABLE_DISKS; do
        devbase=$(basename "$d")
        size_bytes=$(cat "/sys/block/$devbase/size" 2>/dev/null || echo 0)
        size_gb=$((size_bytes * 512 / 1024 / 1024 / 1024))
        model=$(cat "/sys/block/$devbase/device/model" 2>/dev/null || echo "Generic Disk")
        printf "  ${CYAN}[%d]${RESET} %-12s (%d GB, %s)\n" "$i" "$d" "$size_gb" "$model"
        eval "disk_${i}='$d'"
        i=$((i + 1))
    done
    total_disks=$((i - 1))

    if [ -z "$TARGET_DISK" ]; then
        echo ""
        printf "${BOLD}Select target disk [1-%d] (default: 1): ${RESET}" "$total_disks"
        read -r choice || choice="1"
        choice="${choice:-1}"
        # Only a plain number may reach eval
        case "$choice" in
            ''|*[!0-9]*) choice=1 ;;
        esac
        eval "TARGET_DISK=\$disk_${choice}"
        if [ -z "$TARGET_DISK" ]; then
            eval "TARGET_DISK=\$disk_1"
        fi
    fi
    printf "Target Disk selected: ${GREEN}%s${RESET}\n\n" "$TARGET_DISK"

    # Hostname prompt
    printf "${BOLD}Enter system hostname [default: %s]: ${RESET}" "$TARGET_HOSTNAME"
    read -r input_host || input_host=""
    if [ -n "$input_host" ]; then
        TARGET_HOSTNAME="$input_host"
    fi
    printf "Hostname: ${GREEN}%s${RESET}\n\n" "$TARGET_HOSTNAME"

    # SSH key / Security prompt
    if [ -z "$SSH_KEY" ]; then
        printf "${CYAN}Cloud-Native Security: SSH Public Key authentication is strongly recommended.${RESET}\n"
        printf "${BOLD}Enter SSH Public Key (or press Enter to set password): ${RESET}\n"
        read -r input_key || input_key=""
        if [ -n "$input_key" ]; then
            SSH_KEY="$input_key"
            printf "SSH Key configured: ${GREEN}Key-based auth enforced${RESET}\n\n"
        else
            printf "${BOLD}Enter Root Password: ${RESET}"
            stty -echo
            read -r PASSWORD || PASSWORD=""
            stty echo
            echo ""
            if [ -z "$PASSWORD" ]; then
                printf "${RED}Error: an SSH public key or a root password is required.${RESET}\n"
                exit 1
            fi
        fi
    fi

    # User-data prompt
    if [ -z "$USER_DATA" ]; then
        printf "${BOLD}User-data / cloud script URL or file (press Enter to skip): ${RESET}"
        read -r input_ud || input_ud=""
        if [ -n "$input_ud" ]; then
            USER_DATA="$input_ud"
            printf "User-data script: ${GREEN}%s${RESET}\n\n" "$USER_DATA"
        fi
    fi

    # Network configuration prompt (Rocky/RHEL wizard style)
    printf "${BOLD}--- Network Configuration ---${RESET}\n"
    DETECTED_IFACES=""
    for ifpath in /sys/class/net/*; do
        ifname=$(basename "$ifpath")
        if [ "$ifname" != "lo" ] && [ "$ifname" != "*" ]; then
            DETECTED_IFACES="$DETECTED_IFACES $ifname"
        fi
    done
    DETECTED_IFACES=$(echo "$DETECTED_IFACES" | xargs)
    if [ -z "$NET_IFACE" ]; then
        NET_IFACE=$(echo "$DETECTED_IFACES" | awk '{print $1}')
        NET_IFACE="${NET_IFACE:-eth0}"
    fi

    printf "Detected network interfaces: ${CYAN}%s${RESET}\n" "${DETECTED_IFACES:-none}"
    printf "  ${CYAN}[1]${RESET} Auto (DHCP) - Recommended for Cloud & Proxmox [default]\n"
    printf "  ${CYAN}[2]${RESET} Static IP Configuration (Rocky/RHEL wizard style)\n"
    printf "  ${CYAN}[3]${RESET} Skip Network Setup\n"
    printf "${BOLD}Select network mode [1-3] (default: 1): ${RESET}"
    read -r net_choice || net_choice="1"
    net_choice="${net_choice:-1}"
    case "$net_choice" in
        2)
            NET_MODE="static"
            printf "${BOLD}Enter network interface [default: %s]: ${RESET}" "$NET_IFACE"
            read -r in_iface || in_iface=""
            NET_IFACE="${in_iface:-$NET_IFACE}"

            printf "${BOLD}Enter IPv4 address with CIDR (e.g. 192.168.1.50/24): ${RESET}"
            read -r in_ip || in_ip=""
            NET_IP="${in_ip:-$NET_IP}"

            printf "${BOLD}Enter Default Gateway (e.g. 192.168.1.1): ${RESET}"
            read -r in_gw || in_gw=""
            NET_GATEWAY="${in_gw:-$NET_GATEWAY}"

            printf "${BOLD}Enter DNS Nameservers [default: 1.1.1.1 8.8.8.8]: ${RESET}"
            read -r in_dns || in_dns=""
            NET_DNS="${in_dns:-1.1.1.1 8.8.8.8}"
            printf "Static Network: ${GREEN}%s on %s via %s (DNS: %s)${RESET}\n\n" "$NET_IP" "$NET_IFACE" "$NET_GATEWAY" "$NET_DNS"
            ;;
        3)
            NET_MODE="skip"
            printf "Network configuration skipped.\n\n"
            ;;
        *)
            NET_MODE="dhcp"
            printf "Network mode: ${GREEN}DHCP (Auto-configuration)${RESET}\n\n"
            ;;
    esac

    # Final Confirmation
    echo "=================================================="
    printf "${YELLOW}${BOLD}⚠️  WARNING: ALL DATA ON %s WILL BE PERMANENTLY ERASED!${RESET}\n" "$TARGET_DISK"
    echo "Target Disk:     $TARGET_DISK"
    echo "Hostname:        $TARGET_HOSTNAME"
    echo "Authentication:  $([ -n "$SSH_KEY" ] && echo "SSH Public Key" || echo "Password")"
    echo "Network:         $NET_MODE $([ "$NET_MODE" = "static" ] && echo "($NET_IP on $NET_IFACE)" || echo "(Auto-DHCP)")"
    echo "User-Data:       $([ -n "$USER_DATA" ] && echo "$USER_DATA" || echo "None")"
    echo "=================================================="
    printf "${BOLD}Type 'yes' to proceed with installation: ${RESET}"
    read -r confirm || confirm=""
    if [ "$confirm" != "yes" ]; then
        printf "${RED}Installation cancelled by user.${RESET}\n"
        exit 0
    fi
}

perform_install() {
    START_TIME=$(date +%s)
    printf "\n${CYAN}🚀 Beginning Ziro-OS Installation to %s...${RESET}\n" "$TARGET_DISK"

    # Verify prerequisites
    for tool in sfdisk mkfs.vfat mkfs.ext4; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            printf "${RED}❌ Required tool not found: %s${RESET}\n" "$tool"
            exit 1
        fi
    done

    # 1. Unmount any existing partitions on target disk
    printf "\n${BOLD}[1/6] Preparing disk %s...${RESET}\n" "$TARGET_DISK"
    for part in $(ls "${TARGET_DISK}"* 2>/dev/null || true); do
        if [ "$part" != "$TARGET_DISK" ]; then
            umount "$part" 2>/dev/null || true
        fi
    done
    swapoff -a 2>/dev/null || true

    # 2. Partitioning Disk (GPT Hybrid: BIOS Boot + EFI System + Linux Root)
    printf "${BOLD}[2/6] Partitioning disk (GPT Hybrid: BIOS Boot + EFI + Linux Root)...${RESET}\n"
    sfdisk --wipe always --wipe-partitions always "$TARGET_DISK" <<EOF
label: gpt
,2M,21686148-6449-6E6F-744E-656564454649
,512M,U,*
,,L
EOF
    sync
    partprobe "$TARGET_DISK" 2>/dev/null || mdev -s 2>/dev/null || true
    sleep 1

    # Resolve partition names (e.g., /dev/sda1/2/3 vs /dev/nvme0n1p1/p2/p3)
    PART_BIOS=""
    PART_EFI=""
    PART_ROOT=""
    if [ -b "${TARGET_DISK}3" ]; then
        PART_BIOS="${TARGET_DISK}1"
        PART_EFI="${TARGET_DISK}2"
        PART_ROOT="${TARGET_DISK}3"
    elif [ -b "${TARGET_DISK}p3" ]; then
        PART_BIOS="${TARGET_DISK}p1"
        PART_EFI="${TARGET_DISK}p2"
        PART_ROOT="${TARGET_DISK}p3"
    else
        mdev -s 2>/dev/null || true
        sleep 1
        if [ -b "${TARGET_DISK}3" ]; then
            PART_BIOS="${TARGET_DISK}1"
            PART_EFI="${TARGET_DISK}2"
            PART_ROOT="${TARGET_DISK}3"
        elif [ -b "${TARGET_DISK}p3" ]; then
            PART_BIOS="${TARGET_DISK}p1"
            PART_EFI="${TARGET_DISK}p2"
            PART_ROOT="${TARGET_DISK}p3"
        else
            printf "${RED}❌ Could not detect created partitions on %s${RESET}\n" "$TARGET_DISK"
            exit 1
        fi
    fi

    # 3. Format filesystems (PART_BIOS is kept raw for GRUB core.img embedding)
    printf "${BOLD}[3/6] Formatting partitions (FAT32 & ext4)...${RESET}\n"
    mkfs.vfat -F 32 -n ZIRO_ESP "$PART_EFI" >/dev/null 2>&1
    mkfs.ext4 -F -L ZIRO_ROOT "$PART_ROOT" >/dev/null 2>&1

    # 4. Mount target filesystems
    TARGET_MNT="/mnt/ziro-target"
    mkdir -p "$TARGET_MNT"
    umount -R "$TARGET_MNT" 2>/dev/null || true
    mount "$PART_ROOT" "$TARGET_MNT"
    mkdir -p "$TARGET_MNT/boot/efi"
    mount "$PART_EFI" "$TARGET_MNT/boot/efi"

    # 5. Deploy Ziro-OS rootfs
    printf "${BOLD}[4/6] Installing Ziro-OS container host files...${RESET}\n"
    # Copy live operating system directories (guarantees exact, complete host OS with containerd, SSH, and drivers)
    for dir in bin sbin etc home lib lib64 opt root usr var; do
        if [ -e "/$dir" ]; then
            cp -a "/$dir" "$TARGET_MNT/" 2>/dev/null || true
        fi
    done

    # Ensure kernel modules are installed to target disk
    if [ -d /lib/modules ]; then
        mkdir -p "$TARGET_MNT/lib/modules"
        cp -a /lib/modules/* "$TARGET_MNT/lib/modules/" 2>/dev/null || true
    fi

    # Create virtual mountpoint directories
    mkdir -p "$TARGET_MNT/dev" "$TARGET_MNT/proc" "$TARGET_MNT/sys" \
             "$TARGET_MNT/run" "$TARGET_MNT/tmp" "$TARGET_MNT/mnt" "$TARGET_MNT/boot/grub"
    chmod 1777 "$TARGET_MNT/tmp"
    chmod 0700 "$TARGET_MNT/root"

    # Static device nodes on target rootfs (required by BusyBox switch_root)
    mknod -m 600 "$TARGET_MNT/dev/console" c 5 1 2>/dev/null || true
    mknod -m 666 "$TARGET_MNT/dev/null" c 1 3 2>/dev/null || true
    mknod -m 666 "$TARGET_MNT/dev/zero" c 1 5 2>/dev/null || true
    mknod -m 666 "$TARGET_MNT/dev/tty" c 5 0 2>/dev/null || true
    mknod -m 666 "$TARGET_MNT/dev/tty0" c 4 0 2>/dev/null || true
    mknod -m 666 "$TARGET_MNT/dev/tty1" c 4 1 2>/dev/null || true
    mknod -m 660 "$TARGET_MNT/dev/ttyS0" c 4 64 2>/dev/null || true
    mknod -m 660 "$TARGET_MNT/dev/urandom" c 1 9 2>/dev/null || true

    # Copy Kernel into /boot
    mkdir -p "$TARGET_MNT/boot"
    for kern in /boot/vmlinuz* /vmlinuz* /build/vmlinuz*; do
        if [ -f "$kern" ]; then
            cp "$kern" "$TARGET_MNT/boot/vmlinuz"
            break
        fi
    done

    # Locate or extract boot initramfs
    INITR_SRC=""
    for candidate in /boot/initramfs* /initramfs* /build/ziro-initramfs*.cpio.gz; do
        if [ -f "$candidate" ]; then
            INITR_SRC="$candidate"
            break
        fi
    done

    # If not on current rootfs, check mounted CD-ROM or ISO devices
    if [ -z "$INITR_SRC" ]; then
        for mod in sr_mod isofs ata_piix ahci virtio_scsi scsi_mod; do
            modprobe -q "$mod" 2>/dev/null || true
        done
        mdev -s 2>/dev/null || true
        mkdir -p /mnt/cdrom
        for cddev in /dev/sr* /dev/cdrom /dev/iso*; do
            if [ -b "$cddev" ]; then
                mount -r "$cddev" /mnt/cdrom 2>/dev/null || true
                if [ -f /mnt/cdrom/boot/initramfs.cpio.gz ]; then
                    INITR_SRC="/mnt/cdrom/boot/initramfs.cpio.gz"
                    if [ ! -f "$TARGET_MNT/boot/vmlinuz" ] && [ -f /mnt/cdrom/boot/vmlinuz ]; then
                        cp /mnt/cdrom/boot/vmlinuz "$TARGET_MNT/boot/vmlinuz"
                    fi
                    break
                fi
                umount /mnt/cdrom 2>/dev/null || true
            fi
        done
    fi

    if [ -n "$INITR_SRC" ] && [ -f "$INITR_SRC" ]; then
        cp "$INITR_SRC" "$TARGET_MNT/boot/initramfs.cpio.gz"
        echo "✓ Boot initramfs copied from $INITR_SRC"
    fi

    # Fallback: if initramfs was not found anywhere, generate standalone initramfs from target disk
    if [ ! -f "$TARGET_MNT/boot/initramfs.cpio.gz" ]; then
        echo "Generating standalone boot initramfs for installed disk..."
        TEMP_INITR=$(mktemp -d /tmp/ziro-initr.XXXXXX 2>/dev/null || mktemp -d)
        mkdir -p "$TEMP_INITR/bin" "$TEMP_INITR/sbin" "$TEMP_INITR/dev" "$TEMP_INITR/proc" "$TEMP_INITR/sys" "$TEMP_INITR/mnt" "$TEMP_INITR/lib" "$TEMP_INITR/sysroot" "$TEMP_INITR/etc"
        mknod -m 600 "$TEMP_INITR/dev/console" c 5 1 2>/dev/null || true
        mknod -m 666 "$TEMP_INITR/dev/null" c 1 3 2>/dev/null || true
        mknod -m 666 "$TEMP_INITR/dev/zero" c 1 5 2>/dev/null || true
        mknod -m 666 "$TEMP_INITR/dev/tty" c 5 0 2>/dev/null || true
        mknod -m 666 "$TEMP_INITR/dev/tty0" c 4 0 2>/dev/null || true
        mknod -m 666 "$TEMP_INITR/dev/tty1" c 4 1 2>/dev/null || true
        mknod -m 660 "$TEMP_INITR/dev/ttyS0" c 4 64 2>/dev/null || true
        mknod -m 660 "$TEMP_INITR/dev/urandom" c 1 9 2>/dev/null || true
        [ -f /init ] && cp -a /init "$TEMP_INITR/init" || cp -a "$TARGET_MNT/init" "$TEMP_INITR/init"
        [ -f /sbin/init ] && cp -a /sbin/init "$TEMP_INITR/sbin/init" || cp -a "$TARGET_MNT/sbin/init" "$TEMP_INITR/sbin/init"
        [ -f /bin/busybox ] && cp -a /bin/busybox "$TEMP_INITR/bin/busybox" || cp -a "$TARGET_MNT/bin/busybox" "$TEMP_INITR/bin/busybox"
        for util in sh mount umount mknod mkdir ls cat cp rm blkid findfs switch_root modprobe; do
            ln -sf /bin/busybox "$TEMP_INITR/bin/$util" 2>/dev/null || true
            ln -sf /bin/busybox "$TEMP_INITR/sbin/$util" 2>/dev/null || true
        done
        if [ -d "$TARGET_MNT/lib/modules" ]; then
            cp -a "$TARGET_MNT/lib/modules" "$TEMP_INITR/lib/"
        fi
        (
            cd "$TEMP_INITR"
            find . | cpio -H newc -o 2>/dev/null | gzip -9 > "$TARGET_MNT/boot/initramfs.cpio.gz"
        )
        rm -rf "$TEMP_INITR"
        echo "✓ Standalone boot initramfs generated"
    fi

    # 6. Install Bootloader (Hybrid UEFI + BIOS/MBR)
    printf "${BOLD}[5/6] Installing GRUB Bootloader (Hybrid UEFI + BIOS)...${RESET}\n"
    
    # Bind mount system filesystems for grub-install
    mkdir -p "$TARGET_MNT/dev" "$TARGET_MNT/proc" "$TARGET_MNT/sys" "$TARGET_MNT/run"
    mount --bind /dev "$TARGET_MNT/dev"
    mount --bind /proc "$TARGET_MNT/proc"
    mount --bind /sys "$TARGET_MNT/sys"

    # Install BIOS/MBR bootloader (embeds core.img into Partition 1 on GPT)
    echo "Installing GRUB for SeaBIOS / Legacy BIOS (i386-pc)..."
    if grub-install --target=i386-pc --boot-directory="$TARGET_MNT/boot" --recheck "$TARGET_DISK"; then
        echo "✓ SeaBIOS / BIOS bootloader installed to $TARGET_DISK"
    else
        echo "Retrying grub-install i386-pc inside chroot..."
        chroot "$TARGET_MNT" grub-install --target=i386-pc --recheck "$TARGET_DISK" || true
    fi

    # Install UEFI bootloader (writes EFI binaries to Partition 2)
    echo "Installing GRUB for UEFI / OVMF (x86_64-efi)..."
    if grub-install --target=x86_64-efi --efi-directory="$TARGET_MNT/boot/efi" \
                 --boot-directory="$TARGET_MNT/boot" --bootloader-id=ziro-os \
                 --recheck --removable; then
        echo "✓ UEFI bootloader installed to /boot/efi"
    else
        echo "Retrying grub-install x86_64-efi inside chroot..."
        chroot "$TARGET_MNT" grub-install --target=x86_64-efi --efi-directory=/boot/efi \
                     --bootloader-id=ziro-os --recheck --removable || true
    fi

    # Write GRUB configuration with Dual Console support (VGA/NoVNC screen + Serial COM1)
    cat > "$TARGET_MNT/boot/grub/grub.cfg" << EOF
insmod part_gpt
insmod part_msdos
insmod ext2
insmod fat
insmod all_video
insmod gfxterm

set default=0
set timeout=3

# Configure Dual Console (Screen/VGA + Serial COM1)
serial --speed=115200 --unit=0 --word=8 --parity=no --stop=1
terminal_input --append console serial
terminal_output --append console serial

menuentry "Ziro-OS Container Host" {
    search --no-floppy --label --set=root ZIRO_ROOT
    linux /boot/vmlinuz root=LABEL=ZIRO_ROOT rootflags=rw console=ttyS0,115200 console=tty0
    initrd /boot/initramfs.cpio.gz
}

menuentry "Ziro-OS Container Host (Quiet)" {
    search --no-floppy --label --set=root ZIRO_ROOT
    linux /boot/vmlinuz root=LABEL=ZIRO_ROOT rootflags=rw console=ttyS0,115200 console=tty0 quiet
    initrd /boot/initramfs.cpio.gz
}

menuentry "Ziro-OS Container Host (Serial Console Primary)" {
    search --no-floppy --label --set=root ZIRO_ROOT
    linux /boot/vmlinuz root=LABEL=ZIRO_ROOT rootflags=rw console=tty0 console=ttyS0,115200
    initrd /boot/initramfs.cpio.gz
}

menuentry "Ziro-OS (Recovery Shell)" {
    search --no-floppy --label --set=root ZIRO_ROOT
    linux /boot/vmlinuz root=LABEL=ZIRO_ROOT rootflags=rw console=ttyS0,115200 console=tty0 ziro.recovery
    initrd /boot/initramfs.cpio.gz
}
EOF

    # Copy GRUB config to EFI partition as well for standalone UEFI loaders
    mkdir -p "$TARGET_MNT/boot/efi/EFI/BOOT" "$TARGET_MNT/boot/efi/boot/grub" "$TARGET_MNT/boot/efi/EFI/ziro-os"
    cp "$TARGET_MNT/boot/grub/grub.cfg" "$TARGET_MNT/boot/efi/boot/grub/grub.cfg" 2>/dev/null || true
    cp "$TARGET_MNT/boot/grub/grub.cfg" "$TARGET_MNT/boot/efi/EFI/BOOT/grub.cfg" 2>/dev/null || true
    cp "$TARGET_MNT/boot/grub/grub.cfg" "$TARGET_MNT/boot/efi/EFI/ziro-os/grub.cfg" 2>/dev/null || true

    # 7. System Configuration
    printf "${BOLD}[6/6] Configuring hostname, network, security, and fstab...${RESET}\n"
    
    # Mark target system as permanently installed container host
    date -u +"%Y-%m-%dT%H:%M:%SZ" > "$TARGET_MNT/etc/ziro-installed"
    echo "INSTALL_DATE=\"$(date -u)\"" >> "$TARGET_MNT/etc/ziro-installed"
    echo "TARGET_DISK=\"$TARGET_DISK\"" >> "$TARGET_MNT/etc/ziro-installed"

    # Write /etc/fstab
    cat > "$TARGET_MNT/etc/fstab" << EOF
LABEL=ZIRO_ROOT  /          ext4  defaults,noatime,errors=remount-ro  0  1
LABEL=ZIRO_ESP   /boot/efi  vfat  defaults,noatime                    0  2
proc             /proc      proc  defaults                            0  0
sysfs            /sys       sysfs defaults                            0  0
devpts           /dev/pts   devpts defaults,gid=5,mode=620            0  0
tmpfs            /run       tmpfs defaults,nosuid,nodev,mode=0755     0  0
EOF

    # Set hostname
    echo "$TARGET_HOSTNAME" > "$TARGET_MNT/etc/hostname"
    sed -i "s/127.0.1.1.*/127.0.1.1\t$TARGET_HOSTNAME/" "$TARGET_MNT/etc/hosts" 2>/dev/null || \
        echo "127.0.1.1\t$TARGET_HOSTNAME" >> "$TARGET_MNT/etc/hosts"

    # Configure networking (/etc/network/interfaces and /etc/resolv.conf)
    mkdir -p "$TARGET_MNT/etc/network"
    cat > "$TARGET_MNT/etc/network/interfaces" << EOF
auto lo
iface lo inet loopback

EOF
    if [ "$NET_MODE" = "dhcp" ]; then
        for ifn in ${DETECTED_IFACES:-eth0}; do
            cat >> "$TARGET_MNT/etc/network/interfaces" << EOF
auto $ifn
iface $ifn inet dhcp

EOF
        done
        if [ ! -f "$TARGET_MNT/etc/resolv.conf" ]; then
            cat > "$TARGET_MNT/etc/resolv.conf" << EOF
nameserver 1.1.1.1
nameserver 8.8.8.8
EOF
        fi
    elif [ "$NET_MODE" = "static" ] && [ -n "$NET_IP" ]; then
        cat >> "$TARGET_MNT/etc/network/interfaces" << EOF
auto $NET_IFACE
iface $NET_IFACE inet static
    address $NET_IP
EOF
        if [ -n "$NET_GATEWAY" ]; then
            cat >> "$TARGET_MNT/etc/network/interfaces" << EOF
    gateway $NET_GATEWAY
EOF
        fi
        cat > "$TARGET_MNT/etc/resolv.conf" << EOF
# Configured by Ziro-OS Installer
EOF
        for ns in $NET_DNS; do
            echo "nameserver $ns" >> "$TARGET_MNT/etc/resolv.conf"
        done
    fi

    # Configure SSH security
    mkdir -p "$TARGET_MNT/root/.ssh"
    chmod 0700 "$TARGET_MNT/root/.ssh"

    if [ -n "$SSH_KEY" ]; then
        if [ -f "$SSH_KEY" ]; then
            cat "$SSH_KEY" >> "$TARGET_MNT/root/.ssh/authorized_keys"
        else
            echo "$SSH_KEY" >> "$TARGET_MNT/root/.ssh/authorized_keys"
        fi
        chmod 0600 "$TARGET_MNT/root/.ssh/authorized_keys"
        
        # Enforce high-security key-only login
        if [ -f "$TARGET_MNT/etc/ssh/sshd_config" ]; then
            sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' "$TARGET_MNT/etc/ssh/sshd_config" 2>/dev/null || true
            sed -i 's/^#*PermitRootLogin.*/PermitRootLogin prohibit-password/' "$TARGET_MNT/etc/ssh/sshd_config" 2>/dev/null || true
        fi
    elif [ -z "$PASSWORD" ]; then
        printf "${YELLOW}Warning: no SSH key or root password set. Console login is disabled;${RESET}\n"
        printf "${YELLOW}access is only possible via cloud metadata SSH keys (cloud-init) or ziro.recovery.${RESET}\n"
    else
        # Set root password
        # Password goes through stdin only: never interpolated into a shell command.
        if command -v chpasswd >/dev/null 2>&1; then
            printf 'root:%s\n' "$PASSWORD" | chpasswd -R "$TARGET_MNT" 2>/dev/null || \
                printf 'root:%s\n' "$PASSWORD" | chroot "$TARGET_MNT" chpasswd 2>/dev/null || \
                printf "${YELLOW}Warning: failed to set root password.${RESET}\n"
        fi
    fi

    # Execute Cloud User-Data Script if provided
    if [ -n "$USER_DATA" ]; then
        printf "${CYAN}Executing cloud user-data configuration script...${RESET}\n"
        UD_SCRIPT="$TARGET_MNT/tmp/ziro-userdata.sh"
        if echo "$USER_DATA" | grep -qE '^https?://'; then
            if command -v curl >/dev/null 2>&1; then
                curl -fsSL "$USER_DATA" -o "$UD_SCRIPT"
            elif command -v wget >/dev/null 2>&1; then
                wget -q "$USER_DATA" -O "$UD_SCRIPT"
            fi
        elif [ -f "$USER_DATA" ]; then
            cp "$USER_DATA" "$UD_SCRIPT"
        fi

        if [ -f "$UD_SCRIPT" ]; then
            chmod +x "$UD_SCRIPT"
            chroot "$TARGET_MNT" /bin/sh /tmp/ziro-userdata.sh || printf "${YELLOW}Warning: User-data script finished with errors.${RESET}\n"
            rm -f "$UD_SCRIPT"
        fi
    fi

    # Install dedicated reboot, poweroff, halt, and shutdown control scripts
    mkdir -p "$TARGET_MNT/sbin" "$TARGET_MNT/bin" "$TARGET_MNT/usr/bin"
    rm -f "$TARGET_MNT/sbin/reboot" "$TARGET_MNT/sbin/poweroff" "$TARGET_MNT/sbin/halt" "$TARGET_MNT/sbin/shutdown"
    rm -f "$TARGET_MNT/bin/reboot" "$TARGET_MNT/bin/poweroff" "$TARGET_MNT/bin/halt" "$TARGET_MNT/bin/shutdown"
    rm -f "$TARGET_MNT/usr/bin/reboot" "$TARGET_MNT/usr/bin/poweroff" "$TARGET_MNT/usr/bin/shutdown"

    cat > "$TARGET_MNT/sbin/reboot" << 'EOF'
#!/bin/sh
sync
kill -TERM 1 2>/dev/null || busybox reboot -f
EOF
    cat > "$TARGET_MNT/sbin/poweroff" << 'EOF'
#!/bin/sh
sync
kill -USR2 1 2>/dev/null || busybox poweroff -f
EOF
    cat > "$TARGET_MNT/sbin/halt" << 'EOF'
#!/bin/sh
sync
kill -USR1 1 2>/dev/null || busybox halt -f
EOF
    cat > "$TARGET_MNT/sbin/shutdown" << 'EOF'
#!/bin/sh
case "$1" in
    -r|--reboot|reboot) exec /sbin/reboot ;;
    *) exec /sbin/poweroff ;;
esac
EOF
    chmod 755 "$TARGET_MNT/sbin/reboot" "$TARGET_MNT/sbin/poweroff" "$TARGET_MNT/sbin/halt" "$TARGET_MNT/sbin/shutdown"
    cp -f "$TARGET_MNT/sbin/reboot" "$TARGET_MNT/bin/reboot" 2>/dev/null || true
    cp -f "$TARGET_MNT/sbin/reboot" "$TARGET_MNT/usr/bin/reboot" 2>/dev/null || true
    cp -f "$TARGET_MNT/sbin/poweroff" "$TARGET_MNT/bin/poweroff" 2>/dev/null || true
    cp -f "$TARGET_MNT/sbin/poweroff" "$TARGET_MNT/usr/bin/poweroff" 2>/dev/null || true
    cp -f "$TARGET_MNT/sbin/halt" "$TARGET_MNT/bin/halt" 2>/dev/null || true
    cp -f "$TARGET_MNT/sbin/shutdown" "$TARGET_MNT/bin/shutdown" 2>/dev/null || true
    cp -f "$TARGET_MNT/sbin/shutdown" "$TARGET_MNT/usr/bin/shutdown" 2>/dev/null || true

    # Verify and restore authentic BusyBox binary on target installation
    if [ ! -f "$TARGET_MNT/bin/busybox" ] || [ -L "$TARGET_MNT/bin/busybox" ] || [ $(wc -c < "$TARGET_MNT/bin/busybox") -lt 100000 ]; then
        echo "Restoring authentic BusyBox binary on target disk..."
        if [ -f /bin/busybox ] && [ ! -L /bin/busybox ] && [ $(wc -c < /bin/busybox) -gt 100000 ]; then
            cp -f /bin/busybox "$TARGET_MNT/bin/busybox"
        fi
    fi

    # Also make control scripts available in live system immediately without clobbering symlinks
    rm -f /sbin/reboot /sbin/poweroff /sbin/halt /sbin/shutdown
    cp "$TARGET_MNT/sbin/reboot" /sbin/reboot 2>/dev/null || true
    cp "$TARGET_MNT/sbin/poweroff" /sbin/poweroff 2>/dev/null || true
    cp "$TARGET_MNT/sbin/halt" /sbin/halt 2>/dev/null || true
    cp "$TARGET_MNT/sbin/shutdown" /sbin/shutdown 2>/dev/null || true

    # Unmount system filesystems
    sync
    umount "$TARGET_MNT/dev" 2>/dev/null || true
    umount "$TARGET_MNT/proc" 2>/dev/null || true
    umount "$TARGET_MNT/sys" 2>/dev/null || true

    # Re-affirm static devnodes directly on persistent ext4 rootfs (critical for BusyBox switch_root)
    mknod -m 600 "$TARGET_MNT/dev/console" c 5 1 2>/dev/null || true
    mknod -m 666 "$TARGET_MNT/dev/null" c 1 3 2>/dev/null || true
    mknod -m 666 "$TARGET_MNT/dev/zero" c 1 5 2>/dev/null || true
    mknod -m 666 "$TARGET_MNT/dev/tty" c 5 0 2>/dev/null || true
    mknod -m 666 "$TARGET_MNT/dev/tty0" c 4 0 2>/dev/null || true
    mknod -m 666 "$TARGET_MNT/dev/tty1" c 4 1 2>/dev/null || true
    mknod -m 660 "$TARGET_MNT/dev/ttyS0" c 4 64 2>/dev/null || true
    mknod -m 660 "$TARGET_MNT/dev/urandom" c 1 9 2>/dev/null || true

    umount "$TARGET_MNT/boot/efi" 2>/dev/null || true
    umount "$TARGET_MNT" 2>/dev/null || true

    END_TIME=$(date +%s)
    DURATION=$((END_TIME - START_TIME))

    printf "\n${GREEN}============================================================${RESET}\n"
    printf "${GREEN}🎉 Ziro-OS Installed Successfully in %d seconds!${RESET}\n" "$DURATION"
    printf "${GREEN}============================================================${RESET}\n"
    echo " Target Disk:    $TARGET_DISK"
    echo " Bootloader:     Hybrid UEFI & BIOS (GRUB)"
    echo " Rootfs:         LABEL=ZIRO_ROOT (ext4)"
    echo " Hostname:       $TARGET_HOSTNAME"
    echo " Security:       $([ -n "$SSH_KEY" ] && echo "SSH Public Key Auth (Password Disabled)" || echo "Configured")"
    echo ""
    echo "To reboot into your newly installed Ziro-OS:"
    printf "  ${CYAN}reboot${RESET}  (Remember to disconnect the ISO/install media in Proxmox)\n\n"
}

main() {
    # Must be root
    if [ "$(id -u)" -ne 0 ]; then
        printf "${RED}❌ ziro-install must be run as root (UID 0).${RESET}\n"
        exit 1
    fi

    parse_cmdline
    parse_args "$@"

    if [ "$AUTO_CONFIRM" -eq 0 ] || [ -z "$TARGET_DISK" ]; then
        interactive_prompts
    fi

    perform_install
}

main "$@"
