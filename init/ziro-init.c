/*
 * Ziro-OS Container Operating System - PID 1 Supervisor Init
 * Lightweight, high-performance, container-first init system.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/reboot.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <dirent.h>
#include <sys/vfs.h>
#include <sys/sysmacros.h>
#include <time.h>

#ifndef MS_REC
#define MS_REC 16384
#endif
#ifndef MS_SHARED
#define MS_SHARED (1 << 20)
#endif
#ifndef RAMFS_MAGIC
#define RAMFS_MAGIC 0x858458f6UL
#endif
#ifndef TMPFS_MAGIC
#define TMPFS_MAGIC 0x01021994UL
#endif

#define BANNER \
    "\n" \
    "  _____  _               ___  ____  \n" \
    " |__  / (_) _ __  ___   / _ \\/ ___| \n" \
    "   / /  | || '__|/ _ \\ | | | \\___ \\ \n" \
    "  / /_  | || |  | (_) || |_| |___) |\n" \
    " |____| |_||_|   \\___/  \\___/|____/ \n" \
    "\n" \
    " Minimal by design. Born for the cloud.\n" \
    " Ziro-OS Container Host (PID 1 Init)\n\n"

static pid_t containerd_pid = 0;
static pid_t sshd_pid = 0;
static volatile sig_atomic_t shutdown_requested = 0;
static volatile sig_atomic_t reboot_requested = 0;

static void safe_mkdir(const char *dir, mode_t mode) {
    if (mkdir(dir, mode) < 0 && errno != EEXIST) {
        // ignore if exists
    }
}

static void init_devices(void);

static void resolve_root_device(const char *spec, char *out_dev, size_t max_len) {
    out_dev[0] = '\0';
    if (!spec || strlen(spec) == 0) return;

    if (strncmp(spec, "LABEL=", 6) == 0) {
        const char *label = spec + 6;
        char by_label[512];
        snprintf(by_label, sizeof(by_label), "/dev/disk/by-label/%.200s", label);
        if (access(by_label, F_OK) == 0) {
            char resolved[1024];
            if (realpath(by_label, resolved)) {
                snprintf(out_dev, max_len, "%.250s", resolved);
                return;
            }
            snprintf(out_dev, max_len, "%.250s", by_label);
            return;
        }

        // Fast resolution via findfs or blkid -L
        char fcmd[512];
        snprintf(fcmd, sizeof(fcmd), "findfs LABEL=%.128s 2>/dev/null || blkid -L %.128s 2>/dev/null", label, label);
        FILE *fp = popen(fcmd, "r");
        if (fp) {
            char line[256];
            if (fgets(line, sizeof(line), fp)) {
                char *nl = strchr(line, '\n');
                if (nl) *nl = '\0';
                char *cr = strchr(line, '\r');
                if (cr) *cr = '\0';
                if (strlen(line) > 0 && access(line, F_OK) == 0) {
                    snprintf(out_dev, max_len, "%.200s", line);
                    pclose(fp);
                    return;
                }
            }
            pclose(fp);
        }

        // Exhaustive partition scan via /proc/partitions
        FILE *pf = fopen("/proc/partitions", "r");
        if (pf) {
            char pline[256];
            while (fgets(pline, sizeof(pline), pf)) {
                int maj = 0, min = 0;
                long long blocks = 0;
                char pname[128];
                if (sscanf(pline, "%d %d %lld %127s", &maj, &min, &blocks, pname) == 4) {
                    if (pname[0] == '\0' || strcmp(pname, "name") == 0) continue;
                    char devpath[256];
                    snprintf(devpath, sizeof(devpath), "/dev/%s", pname);
                    if (access(devpath, F_OK) != 0) {
                        mknod(devpath, S_IFBLK | 0660, makedev(maj, min));
                    }
                    if (access(devpath, F_OK) == 0) {
                        char bcmd[512];
                        snprintf(bcmd, sizeof(bcmd), "blkid -s LABEL -o value %s 2>/dev/null", devpath);
                        FILE *bfp = popen(bcmd, "r");
                        if (bfp) {
                            char blabel[128];
                            if (fgets(blabel, sizeof(blabel), bfp)) {
                                char *bnl = strchr(blabel, '\n');
                                if (bnl) *bnl = '\0';
                                char *bcr = strchr(blabel, '\r');
                                if (bcr) *bcr = '\0';
                                if (strcmp(blabel, label) == 0) {
                                    snprintf(out_dev, max_len, "%s", devpath);
                                    pclose(bfp);
                                    fclose(pf);
                                    return;
                                }
                            }
                            pclose(bfp);
                        }
                    }
                }
            }
            fclose(pf);
        }

        // Search common partition nodes directly
        static const char *prefixes[] = {"/dev/sda", "/dev/vda", "/dev/sdb", "/dev/vdb", "/dev/nvme0n1p", "/dev/hda", NULL};
        for (int p = 0; prefixes[p] != NULL; p++) {
            for (int part = 1; part <= 8; part++) {
                char candidate[64];
                snprintf(candidate, sizeof(candidate), "%s%d", prefixes[p], part);
                if (access(candidate, F_OK) == 0) {
                    char cmd[512];
                    snprintf(cmd, sizeof(cmd), "blkid -s LABEL -o value %s 2>/dev/null", candidate);
                    FILE *bfp = popen(cmd, "r");
                    if (bfp) {
                        char blabel[128];
                        if (fgets(blabel, sizeof(blabel), bfp)) {
                            char *bnl = strchr(blabel, '\n');
                            if (bnl) *bnl = '\0';
                            char *br = strchr(blabel, '\r');
                            if (br) *br = '\0';
                            if (strcmp(blabel, label) == 0) {
                                snprintf(out_dev, max_len, "%s", candidate);
                                pclose(bfp);
                                return;
                            }
                        }
                        pclose(bfp);
                    }
                }
            }
        }
    } else if (strncmp(spec, "UUID=", 5) == 0) {
        const char *uuid = spec + 5;
        char cmd[1024];
        snprintf(cmd, sizeof(cmd), "findfs UUID=%.128s 2>/dev/null || blkid -U %.128s 2>/dev/null", uuid, uuid);
        FILE *fp = popen(cmd, "r");
        if (fp) {
            char line[256];
            if (fgets(line, sizeof(line), fp)) {
                char *nl = strchr(line, '\n');
                if (nl) *nl = '\0';
                char *cr = strchr(line, '\r');
                if (cr) *cr = '\0';
                if (strlen(line) > 0 && access(line, F_OK) == 0) {
                    snprintf(out_dev, max_len, "%.200s", line);
                    pclose(fp);
                    return;
                }
            }
            pclose(fp);
        }

        // Exhaustive partition scan via /proc/partitions
        FILE *pf = fopen("/proc/partitions", "r");
        if (pf) {
            char pline[256];
            while (fgets(pline, sizeof(pline), pf)) {
                int maj = 0, min = 0;
                long long blocks = 0;
                char pname[128];
                if (sscanf(pline, "%d %d %lld %127s", &maj, &min, &blocks, pname) == 4) {
                    if (pname[0] == '\0' || strcmp(pname, "name") == 0) continue;
                    char devpath[256];
                    snprintf(devpath, sizeof(devpath), "/dev/%s", pname);
                    if (access(devpath, F_OK) != 0) {
                        mknod(devpath, S_IFBLK | 0660, makedev(maj, min));
                    }
                    if (access(devpath, F_OK) == 0) {
                        char bcmd[512];
                        snprintf(bcmd, sizeof(bcmd), "blkid -s UUID -o value %s 2>/dev/null", devpath);
                        FILE *bfp = popen(bcmd, "r");
                        if (bfp) {
                            char buuid[128];
                            if (fgets(buuid, sizeof(buuid), bfp)) {
                                char *bnl = strchr(buuid, '\n');
                                if (bnl) *bnl = '\0';
                                char *bcr = strchr(buuid, '\r');
                                if (bcr) *bcr = '\0';
                                if (strcasecmp(buuid, uuid) == 0) {
                                    snprintf(out_dev, max_len, "%s", devpath);
                                    pclose(bfp);
                                    fclose(pf);
                                    return;
                                }
                            }
                            pclose(bfp);
                        }
                    }
                }
            }
            fclose(pf);
        }
    } else if (strncmp(spec, "/dev/", 5) == 0) {
        snprintf(out_dev, max_len, "%.200s", spec);
    }
}

static void check_and_switch_root(void) {
    if (access("/etc/.ziro_switched", F_OK) == 0) {
        return; // Already running on switched root!
    }

    struct statfs st;
    memset(&st, 0, sizeof(st));
    statfs("/", &st);
    unsigned long ftype = (unsigned long)st.f_type & 0xffffffffUL;

    // Skip switch if already running on a persistent filesystem (ext4, xfs, btrfs, overlayfs)
    if (ftype == 0xef53UL || ftype == 0x58465342UL || ftype == 0x9123683eUL || ftype == 0x794c7630UL) {
        printf("[init] running on persistent root filesystem (0x%lx); continuing boot\n", ftype);
        return;
    }

    // 1. Mount essential virtual filesystems in initramfs for device detection
    safe_mkdir("/dev", 0755);
    mount("devtmpfs", "/dev", "devtmpfs", MS_NOSUID, "mode=0755");
    safe_mkdir("/proc", 0755);
    mount("proc", "/proc", "proc", MS_NOSUID | MS_NOEXEC | MS_NODEV, NULL);
    safe_mkdir("/sys", 0755);
    mount("sysfs", "/sys", "sysfs", MS_NOSUID | MS_NOEXEC | MS_NODEV, NULL);

    // 2. Discover hardware and load kernel modules (virtio_scsi, virtio_blk, sd_mod, ahci, nvme)
    init_devices();

    // 3. Inspect kernel command line
    char root_spec[256] = {0};
    int live_requested = 0;
    FILE *cmdline = fopen("/proc/cmdline", "r");
    if (cmdline) {
        char buf[1024];
        if (fgets(buf, sizeof(buf), cmdline)) {
            if (strstr(buf, "ziro.live") != NULL) {
                live_requested = 1;
            }
            char *p = strstr(buf, "root=");
            if (p) {
                p += 5;
                char *end = p;
                while (*end && *end != ' ' && *end != '\t' && *end != '\r' && *end != '\n') {
                    end++;
                }
                size_t len = (size_t)(end - p);
                if (len < sizeof(root_spec)) {
                    strncpy(root_spec, p, len);
                    root_spec[len] = '\0';
                }
            }
        }
        fclose(cmdline);
    }

    // 4. If persistent root is requested (e.g. root=LABEL=ZIRO_ROOT), locate and mount disk
    if (!live_requested && root_spec[0] != '\0') {
        printf("[init] root device requested: %s\n", root_spec);
        char root_dev[256] = {0};

        // Poll for disk readiness (up to 6 seconds)
        for (int retries = 0; retries < 30; retries++) {
            resolve_root_device(root_spec, root_dev, sizeof(root_dev));
            if (root_dev[0] != '\0' && access(root_dev, F_OK) == 0) {
                break;
            }
            usleep(200000); // 200ms
        }

        if (root_dev[0] != '\0' && access(root_dev, F_OK) == 0) {
            printf("[init] resolved root device: %s\n", root_dev);
            safe_mkdir("/sysroot", 0755);
            if (mount(root_dev, "/sysroot", "ext4", MS_RELATIME, NULL) == 0) {
                printf("[init] mounted %s on /sysroot (ext4)\n", root_dev);

                // Verify real init exists in persistent sysroot
                if (access("/sysroot/sbin/init", X_OK) == 0 || access("/sysroot/init", X_OK) == 0) {
                    int mfd = open("/sysroot/etc/.ziro_switched", O_WRONLY | O_CREAT, 0644);
                    if (mfd >= 0) close(mfd);

                    // Ensure essential devnodes exist in /sysroot/dev for switch_root
                    safe_mkdir("/sysroot/dev", 0755);
                    mknod("/sysroot/dev/console", S_IFCHR | 0600, makedev(5, 1));
                    mknod("/sysroot/dev/null", S_IFCHR | 0666, makedev(1, 3));
                    mknod("/sysroot/dev/zero", S_IFCHR | 0666, makedev(1, 5));
                    mknod("/sysroot/dev/tty", S_IFCHR | 0666, makedev(5, 0));
                    mknod("/sysroot/dev/tty0", S_IFCHR | 0666, makedev(4, 0));
                    mknod("/sysroot/dev/tty1", S_IFCHR | 0666, makedev(4, 1));
                    mknod("/sysroot/dev/ttyS0", S_IFCHR | 0660, makedev(4, 64));
                    mknod("/sysroot/dev/urandom", S_IFCHR | 0660, makedev(1, 9));

                    umount2("/dev", MNT_DETACH);
                    umount2("/proc", MNT_DETACH);
                    umount2("/sys", MNT_DETACH);

                    printf("[init] switching root to persistent disk (%s)...\n", root_dev);
                    fflush(stdout);
                    fflush(stderr);

                    const char *init_target = (access("/sysroot/sbin/init", X_OK) == 0) ? "/sbin/init" : "/init";
                    execl("/sbin/switch_root", "switch_root", "/sysroot", init_target, NULL);
                    execl("/bin/switch_root", "switch_root", "/sysroot", init_target, NULL);
                    execl("/bin/busybox", "switch_root", "/sysroot", init_target, NULL);
                    execl("/sbin/busybox", "switch_root", "/sysroot", init_target, NULL);
                    fprintf(stderr, "[init] switch_root to %s failed: %s\n", root_dev, strerror(errno));
                } else {
                    fprintf(stderr, "[init] /sysroot/sbin/init not found on %s, unmounting\n", root_dev);
                    umount2("/sysroot", MNT_DETACH);
                }
            } else {
                fprintf(stderr, "[init] failed to mount %s on /sysroot: %s\n", root_dev, strerror(errno));
            }
        } else {
            printf("[init] persistent root device (%s) not found; falling back to live tmpfs\n", root_spec);
        }
    }

    // 5. Fallback: Live ISO tmpfs migration
    printf("[init] migrating live environment to tmpfs...\n");
    safe_mkdir("/sysroot", 0755);
    if (mount("tmpfs", "/sysroot", "tmpfs", 0, "mode=0755,size=100%") < 0) {
        fprintf(stderr, "[init] failed to mount tmpfs on /sysroot: %s\n", strerror(errno));
        return;
    }

    pid_t cpid = fork();
    if (cpid == 0) {
        char *argv[] = {
            "/bin/sh", "-c",
            "for d in bin sbin etc home lib lib64 opt root usr var; do "
            "  if [ -e \"/$d\" ]; then cp -a \"/$d\" /sysroot/ 2>/dev/null || true; fi; "
            "done; "
            "mkdir -p /sysroot/dev /sysroot/proc /sysroot/sys /sysroot/run /sysroot/tmp /sysroot/mnt; "
            "chmod 1777 /sysroot/tmp; "
            "chmod 0700 /sysroot/root; "
            "touch /sysroot/etc/.ziro_switched; "
            "mknod -m 600 /sysroot/dev/console c 5 1 2>/dev/null || true; "
            "mknod -m 666 /sysroot/dev/null c 1 3 2>/dev/null || true; "
            "mknod -m 666 /sysroot/dev/zero c 1 5 2>/dev/null || true; "
            "mknod -m 666 /sysroot/dev/tty c 5 0 2>/dev/null || true; "
            "mknod -m 666 /sysroot/dev/tty0 c 4 0 2>/dev/null || true; "
            "mknod -m 666 /sysroot/dev/tty1 c 4 1 2>/dev/null || true; "
            "mknod -m 660 /sysroot/dev/ttyS0 c 4 64 2>/dev/null || true",
            NULL
        };
        execv("/bin/sh", argv);
        _exit(1);
    } else if (cpid > 0) {
        int status;
        waitpid(cpid, &status, 0);
    }

    safe_mkdir("/sysroot/dev", 0755);
    mknod("/sysroot/dev/console", S_IFCHR | 0600, makedev(5, 1));
    mknod("/sysroot/dev/null", S_IFCHR | 0666, makedev(1, 3));
    mknod("/sysroot/dev/zero", S_IFCHR | 0666, makedev(1, 5));
    mknod("/sysroot/dev/tty", S_IFCHR | 0666, makedev(5, 0));
    mknod("/sysroot/dev/tty0", S_IFCHR | 0666, makedev(4, 0));
    mknod("/sysroot/dev/tty1", S_IFCHR | 0666, makedev(4, 1));
    mknod("/sysroot/dev/ttyS0", S_IFCHR | 0660, makedev(4, 64));
    int fd = open("/sysroot/etc/.ziro_switched", O_WRONLY | O_CREAT, 0644);
    if (fd >= 0) close(fd);

    umount2("/dev", MNT_DETACH);
    umount2("/proc", MNT_DETACH);
    umount2("/sys", MNT_DETACH);

    printf("[init] performing switch_root to live tmpfs...\n");
    fflush(stdout);
    fflush(stderr);
    execl("/sbin/switch_root", "switch_root", "/sysroot", "/sbin/init", NULL);
    execl("/bin/switch_root", "switch_root", "/sysroot", "/sbin/init", NULL);
    execl("/bin/busybox", "switch_root", "/sysroot", "/sbin/init", NULL);
    execl("/sbin/busybox", "switch_root", "/sysroot", "/sbin/init", NULL);
    fprintf(stderr, "[init] failed to switch_root: %s\n", strerror(errno));
}

static void mount_essential(const char *source, const char *target, const char *type, unsigned long flags, const void *data) {
    safe_mkdir(target, 0755);
    if (mount(source, target, type, flags, data) < 0) {
        if (errno != EBUSY) {
            fprintf(stderr, "[init] warning: mount %s -> %s (%s) failed: %s\n", source, target, type, strerror(errno));
        }
    } else {
        printf("[init] mounted %s on %s\n", type, target);
    }
}

static void init_filesystems(void) {
    printf("[init] initializing virtual filesystems...\n");

    // Make root mount private recursively so runc pivot_root succeeds
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0) {
        mount(NULL, "/", NULL, MS_PRIVATE, NULL);
    }
    printf("[init] marked root mount as private (MS_PRIVATE for OCI pivot_root)\n");

    mount_essential("proc", "/proc", "proc", MS_NOSUID | MS_NOEXEC | MS_NODEV, NULL);
    mount_essential("sysfs", "/sys", "sysfs", MS_NOSUID | MS_NOEXEC | MS_NODEV, NULL);
    mount_essential("devtmpfs", "/dev", "devtmpfs", MS_NOSUID, "mode=0755");
    safe_mkdir("/dev/pts", 0755);
    mount_essential("devpts", "/dev/pts", "devpts", MS_NOSUID | MS_NOEXEC, "gid=5,mode=620");
    safe_mkdir("/dev/shm", 0755);
    mount_essential("shm", "/dev/shm", "tmpfs", MS_NOSUID | MS_NODEV, "mode=1777");
    safe_mkdir("/run", 0755);
    mount_essential("run", "/run", "tmpfs", MS_NOSUID | MS_NODEV, "mode=0755");
    safe_mkdir("/tmp", 0777);
    mount_essential("tmp", "/tmp", "tmpfs", MS_NOSUID | MS_NODEV, "mode=1777");

    safe_mkdir("/var", 0755);
    safe_mkdir("/var/log", 0755);
    safe_mkdir("/var/lib", 0755);
    safe_mkdir("/var/lib/containerd", 0755);
    safe_mkdir("/var/lib/containers", 0755);
    safe_mkdir("/var/empty", 0700);
}

static void init_devices(void) {
    printf("[init] discovering hardware and loading kernel modules...\n");

    // 1. Essential virtualization, storage, and networking kernel modules
    static const char *modules[] = {
        // VirtIO subsystems
        "virtio", "virtio_ring", "virtio_pci", "virtio_pci_modern_dev",
        "virtio_blk", "virtio_scsi", "virtio_net",
        // SCSI & SATA controllers and disks
        "scsi_mod", "sd_mod", "sr_mod", "sg",
        "libata", "ata_generic", "ata_piix", "ahci", "sata_nv", "sata_via",
        // NVMe controllers
        "nvme", "nvme_core",
        // Network adapters
        "e1000", "e1000e", "igb", "r8169", "vmxnet3",
        // Filesystems
        "ext4", "vfat", "isofs", "overlay",
        NULL
    };

    for (int i = 0; modules[i] != NULL; i++) {
        pid_t p = fork();
        if (p == 0) {
            char *margs[] = {"modprobe", "-q", (char *)modules[i], NULL};
            execv("/sbin/modprobe", margs);
            execv("/bin/modprobe", margs);
            execv("/usr/sbin/modprobe", margs);
            _exit(0);
        } else if (p > 0) {
            int st;
            waitpid(p, &st, 0);
        }
    }

    // 2. Hardware coldplug: probe modalias for all detected devices in /sys
    DIR *sys_bus = opendir("/sys/bus");
    if (sys_bus) {
        closedir(sys_bus);
        system("find /sys/bus /sys/devices -name modalias 2>/dev/null | while read -r f; do [ -f \"$f\" ] && read -r m < \"$f\" && [ -n \"$m\" ] && modprobe -q \"$m\" 2>/dev/null; done 2>/dev/null || true");
    }

    // 3. Trigger mdev -s to populate /dev
    pid_t mp = fork();
    if (mp == 0) {
        char *mdev_args[] = {"mdev", "-s", NULL};
        execv("/sbin/mdev", mdev_args);
        execv("/bin/mdev", mdev_args);
        _exit(0);
    } else if (mp > 0) {
        int st;
        waitpid(mp, &st, 0);
    }

    // 4. Ensure block device nodes in /dev exist by reading /sys/block/*/dev
    DIR *blk_dir = opendir("/sys/block");
    if (blk_dir) {
        struct dirent *ent;
        while ((ent = readdir(blk_dir)) != NULL) {
            if (ent->d_name[0] == '.') continue;
            char dev_file[512];
            snprintf(dev_file, sizeof(dev_file), "/sys/block/%s/dev", ent->d_name);
            FILE *df = fopen(dev_file, "r");
            if (df) {
                int maj = 0, min = 0;
                if (fscanf(df, "%d:%d", &maj, &min) == 2) {
                    char node_path[512];
                    snprintf(node_path, sizeof(node_path), "/dev/%s", ent->d_name);
                    struct stat st;
                    if (stat(node_path, &st) != 0) {
                        mknod(node_path, S_IFBLK | 0660, makedev(maj, min));
                    }
                }
                fclose(df);
            }

            // Also ensure partitions (e.g. sda1, vda1, nvme0n1p1) have device nodes
            char sys_part_pattern[512];
            snprintf(sys_part_pattern, sizeof(sys_part_pattern), "/sys/block/%s", ent->d_name);
            DIR *pdir = opendir(sys_part_pattern);
            if (pdir) {
                struct dirent *pent;
                while ((pent = readdir(pdir)) != NULL) {
                    if (pent->d_name[0] == '.') continue;
                    char pdev_file[640];
                    snprintf(pdev_file, sizeof(pdev_file), "/sys/block/%s/%s/dev", ent->d_name, pent->d_name);
                    FILE *pdf = fopen(pdev_file, "r");
                    if (pdf) {
                        int pmaj = 0, pmin = 0;
                        if (fscanf(pdf, "%d:%d", &pmaj, &pmin) == 2) {
                            char pnode_path[512];
                            snprintf(pnode_path, sizeof(pnode_path), "/dev/%s", pent->d_name);
                            struct stat pst;
                            if (stat(pnode_path, &pst) != 0) {
                                mknod(pnode_path, S_IFBLK | 0660, makedev(pmaj, pmin));
                            }
                        }
                        fclose(pdf);
                    }
                }
                closedir(pdir);
            }

            // Log discovered block device
            if (strncmp(ent->d_name, "loop", 4) != 0 && strncmp(ent->d_name, "ram", 3) != 0) {
                printf("[init] storage drive detected: /dev/%s\n", ent->d_name);
            }
        }
        closedir(blk_dir);
    }
}

static void init_cgroups(void) {
    printf("[init] initializing cgroups v2...\n");
    safe_mkdir("/sys/fs/cgroup", 0755);
    if (mount("cgroup2", "/sys/fs/cgroup", "cgroup2", MS_NOSUID | MS_NOEXEC | MS_NODEV, "nsdelegate") < 0) {
        if (errno != EBUSY) {
            fprintf(stderr, "[init] warning: failed to mount cgroup2: %s\n", strerror(errno));
        }
    } else {
        printf("[init] mounted cgroups v2 at /sys/fs/cgroup\n");
    }

    // Enable all available subtree controllers for containers
    int fd_controllers = open("/sys/fs/cgroup/cgroup.controllers", O_RDONLY);
    if (fd_controllers >= 0) {
        char buf[256];
        ssize_t n = read(fd_controllers, buf, sizeof(buf) - 1);
        close(fd_controllers);
        if (n > 0) {
            buf[n] = '\0';
            int fd_subtree = open("/sys/fs/cgroup/cgroup.subtree_control", O_WRONLY);
            if (fd_subtree >= 0) {
                char *token = strtok(buf, " \n");
                while (token) {
                    char enable_cmd[64];
                    snprintf(enable_cmd, sizeof(enable_cmd), "+%s", token);
                    if (write(fd_subtree, enable_cmd, strlen(enable_cmd)) < 0) {
                        // ignore controller enable errors
                    }
                    token = strtok(NULL, " \n");
                }
                close(fd_subtree);
                printf("[init] enabled cgroup subtree controllers\n");
            }
        }
    }
}

static void init_hostname(void) {
    char hostname[64] = "ziro-os";
    FILE *f = fopen("/etc/hostname", "r");
    if (f) {
        if (fgets(hostname, sizeof(hostname), f)) {
            hostname[strcspn(hostname, "\r\n")] = '\0';
        }
        fclose(f);
    }
    if (sethostname(hostname, strlen(hostname)) != 0) {
        // ignore if not permitted
    }
    printf("[init] hostname set to: %s\n", hostname);
}

static void init_network(void) {
    printf("[init] configuring networking (lo & ethernet interfaces)...\n");

    // 1. Bring up loopback interface
    pid_t pid = fork();
    if (pid == 0) {
        if (access("/bin/ip", X_OK) == 0 || access("/sbin/ip", X_OK) == 0) {
            char *bin = access("/bin/ip", X_OK) == 0 ? "/bin/ip" : "/sbin/ip";
            char *argv[] = {"ip", "link", "set", "lo", "up", NULL};
            execv(bin, argv);
        }
        if (access("/sbin/ifconfig", X_OK) == 0 || access("/bin/ifconfig", X_OK) == 0) {
            char *bin = access("/sbin/ifconfig", X_OK) == 0 ? "/sbin/ifconfig" : "/bin/ifconfig";
            char *argv[] = {"ifconfig", "lo", "127.0.0.1", "up", NULL};
            execv(bin, argv);
        }
        _exit(1);
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
    }

    // 2. Discover physical / virtual network interfaces in /sys/class/net
    DIR *d = opendir("/sys/class/net");
    if (d) {
        struct dirent *dir;
        while ((dir = readdir(d)) != NULL) {
            if (dir->d_name[0] == '.' || strcmp(dir->d_name, "lo") == 0) {
                continue;
            }

            // Only configure Ethernet interfaces (ARPHRD_ETHER = 1)
            char type_path[320];
            snprintf(type_path, sizeof(type_path), "/sys/class/net/%s/type", dir->d_name);
            FILE *tf = fopen(type_path, "r");
            if (tf) {
                int if_type = 0;
                if (fscanf(tf, "%d", &if_type) == 1 && if_type != 1) {
                    fclose(tf);
                    continue; // Skip non-ethernet devices (e.g. sit0, tun, dummy)
                }
                fclose(tf);
            }

            printf("[init] configuring network interface: %s\n", dir->d_name);

            // Bring interface link up
            pid = fork();
            if (pid == 0) {
                char *bin = access("/bin/ip", X_OK) == 0 ? "/bin/ip" : "/sbin/ip";
                char *argv[] = {"ip", "link", "set", dir->d_name, "up", NULL};
                execv(bin, argv);
                _exit(1);
            } else if (pid > 0) {
                int status;
                waitpid(pid, &status, 0);
            }

            // Launch background udhcpc for DHCP auto-configuration
            pid = fork();
            if (pid == 0) {
                char log_path[320];
                snprintf(log_path, sizeof(log_path), "/var/log/udhcpc.%s.log", dir->d_name);
                int log_fd = open(log_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
                if (log_fd >= 0) {
                    dup2(log_fd, STDOUT_FILENO);
                    dup2(log_fd, STDERR_FILENO);
                    close(log_fd);
                }
                char *udhcpc_bin = access("/bin/udhcpc", X_OK) == 0 ? "/bin/udhcpc" : "/sbin/udhcpc";
                char pidfile[300];
                snprintf(pidfile, sizeof(pidfile), "/run/udhcpc.%s.pid", dir->d_name);
                char *argv[] = {
                    "udhcpc", "-b", "-i", dir->d_name,
                    "-s", "/usr/share/udhcpc/default.script",
                    "-p", pidfile, NULL
                };
                execv(udhcpc_bin, argv);
                _exit(1);
            } else if (pid > 0) {
                printf("[init] started background udhcpc for %s (PID: %d)\n", dir->d_name, pid);
            }
        }
        closedir(d);
    }
}

static void start_containerd(void) {
    if (access("/usr/bin/containerd", X_OK) != 0 && access("/bin/containerd", X_OK) != 0) {
        printf("[init] containerd not found; skipping container engine startup\n");
        return;
    }

    safe_mkdir("/run/containerd", 0755);
    safe_mkdir("/var/lib/containerd", 0755);
    safe_mkdir("/var/log", 0755);

    printf("[init] starting containerd daemon...\n");
    pid_t pid = fork();
    if (pid == 0) {
        char *bin = access("/usr/bin/containerd", X_OK) == 0 ? "/usr/bin/containerd" : "/bin/containerd";
        char *argv[] = {"containerd", "--config", "/etc/containerd/config.toml", NULL};
        int log_fd = open("/var/log/containerd.log", O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (log_fd >= 0) {
            dup2(log_fd, STDOUT_FILENO);
            dup2(log_fd, STDERR_FILENO);
            close(log_fd);
        }
        execv(bin, argv);
        fprintf(stderr, "[init] failed to execute containerd: %s\n", strerror(errno));
        _exit(1);
    } else if (pid > 0) {
        containerd_pid = pid;
        printf("[init] containerd spawned (PID: %d)\n", pid);

        // Quick check for socket readiness (up to 3 seconds)
        for (int i = 0; i < 30; i++) {
            if (access("/run/containerd/containerd.sock", F_OK) == 0) {
                printf("[init] containerd socket ready: /run/containerd/containerd.sock\n");
                break;
            }
            usleep(100000); // 100ms
        }
    }
}

static void start_sshd(void) {
    if (access("/usr/sbin/sshd", X_OK) != 0 && access("/sbin/sshd", X_OK) != 0) {
        printf("[init] sshd not found; skipping remote SSH daemon startup\n");
        return;
    }

    safe_mkdir("/var/empty", 0700);
    chmod("/var/empty", 0700);
    if (chown("/var/empty", 0, 0) != 0) {
        // ignore if not running as root
    }
    safe_mkdir("/run/sshd", 0755);
    safe_mkdir("/etc/ssh", 0755);
    safe_mkdir("/root/.ssh", 0700);
    chmod("/root/.ssh", 0700);
    if (chown("/root/.ssh", 0, 0) != 0) {
        // ignore if not running as root
    }

    // Auto-generate host keys if not present
    if (access("/etc/ssh/ssh_host_ed25519_key", F_OK) != 0) {
        printf("[init] generating OpenSSH host keys...\n");
        pid_t kpid = fork();
        if (kpid == 0) {
            char *keygen = access("/usr/bin/ssh-keygen", X_OK) == 0 ? "/usr/bin/ssh-keygen" : "/bin/ssh-keygen";
            char *argv[] = {"ssh-keygen", "-A", NULL};
            execv(keygen, argv);
            _exit(1);
        } else if (kpid > 0) {
            int st;
            waitpid(kpid, &st, 0);
        }
    }

    printf("[init] starting hardened OpenSSH daemon...\n");
    pid_t pid = fork();
    if (pid == 0) {
        char *bin = access("/usr/sbin/sshd", X_OK) == 0 ? "/usr/sbin/sshd" : "/sbin/sshd";
        char *argv[] = {bin, "-D", "-e", NULL};
        int log_fd = open("/var/log/sshd.log", O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (log_fd >= 0) {
            dup2(log_fd, STDOUT_FILENO);
            dup2(log_fd, STDERR_FILENO);
            close(log_fd);
        }
        execv(bin, argv);
        fprintf(stderr, "[init] failed to execute sshd: %s\n", strerror(errno));
        _exit(1);
    } else if (pid > 0) {
        sshd_pid = pid;
        printf("[init] OpenSSH daemon ready: port 22 (PID: %d)\n", pid);
    }
}

static void sig_handler(int sig) {
    switch (sig) {
        case SIGTERM:
        case SIGINT:
            // Busybox reboot or Ctrl-Alt-Del -> REBOOT
            reboot_requested = 1;
            shutdown_requested = 0;
            break;
        case SIGUSR2:
        case SIGPWR:
            // Busybox poweroff or ACPI poweroff -> POWER OFF
            shutdown_requested = 1;
            reboot_requested = 0;
            break;
        case SIGUSR1:
            // Busybox halt -> HALT / POWER OFF
            shutdown_requested = 1;
            reboot_requested = 0;
            break;
        case SIGCHLD:
            // Handled in main loop
            break;
    }
}

static void get_active_console(char *dev_path, size_t max_len) {
    snprintf(dev_path, max_len, "/dev/console");
    FILE *f = fopen("/sys/class/tty/console/active", "r");
    if (f) {
        char active_tty[128];
        if (fgets(active_tty, sizeof(active_tty), f)) {
            char *last_word = NULL;
            char *token = strtok(active_tty, " \t\r\n");
            while (token) {
                last_word = token;
                token = strtok(NULL, " \t\r\n");
            }
            if (last_word && strlen(last_word) > 0) {
                snprintf(dev_path, max_len, "/dev/%s", last_word);
            }
        }
        fclose(f);
    }
}

static void setup_controlling_tty(void) {
    setsid();

    char dev_path[64];
    get_active_console(dev_path, sizeof(dev_path));

    int fd = open(dev_path, O_RDWR);
    if (fd < 0) {
        fd = open("/dev/tty1", O_RDWR);
    }
    if (fd < 0) {
        fd = open("/dev/console", O_RDWR);
    }
    if (fd >= 0) {
        dup2(fd, STDIN_FILENO);
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        if (fd > 2) close(fd);

        ioctl(STDIN_FILENO, TIOCSCTTY, 1);
        tcsetpgrp(STDIN_FILENO, getpid());
    }
}

struct terminal_session {
    const char *dev;
    pid_t pid;
    time_t last_spawn;
    int respawn_fails;
    int disabled;
};

static struct terminal_session term_sessions[] = {
    {"/dev/tty1", 0, 0, 0, 0},
    {"/dev/ttyS0", 0, 0, 0, 0},
    {"/dev/ttyAMA0", 0, 0, 0, 0},
};
#define NUM_TERM_SESSIONS (sizeof(term_sessions)/sizeof(term_sessions[0]))

static pid_t console_fallback_pid = 0;

static void setup_terminal_attributes(int fd, const char *dev) {
    if (strstr(dev, "ttyS") != NULL || strstr(dev, "ttyAMA") != NULL) {
        struct termios tio;
        if (tcgetattr(fd, &tio) == 0) {
            cfsetispeed(&tio, B115200);
            cfsetospeed(&tio, B115200);
            tio.c_cflag |= (CLOCAL | CREAD | CS8);
            tio.c_cflag &= ~(PARENB | CSTOPB | CRTSCTS);
            tio.c_lflag |= (ICANON | ECHO | ECHOE | ISIG);
            tio.c_iflag |= ICRNL;
            tio.c_oflag |= (OPOST | ONLCR);
            tcsetattr(fd, TCSANOW, &tio);
        }
    }
}

static void spawn_terminal(struct terminal_session *s) {
    if (s->disabled) return;
    if (access(s->dev, F_OK) != 0) {
        return; // Device node does not exist
    }

    time_t now = time(NULL);
    if (s->respawn_fails >= 5) {
        if (now - s->last_spawn < 5) {
            return; // 5-second backoff after consecutive fast exits
        }
    }

    pid_t pid = fork();
    if (pid == 0) {
        int fd = open(s->dev, O_RDWR | O_NONBLOCK | O_NOCTTY);
        if (fd < 0) {
            _exit(2); // Failed to open device
        }

        setup_terminal_attributes(fd, s->dev);

        int flags = fcntl(fd, F_GETFL, 0);
        if (flags >= 0) {
            fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
        }

        setsid();
        ioctl(fd, TIOCSCTTY, 1);
        tcsetpgrp(fd, getpid());

        dup2(fd, STDIN_FILENO);
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        if (fd > 2) close(fd);

        setenv("TERM", "linux", 1);
        setenv("PATH", "/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin:/opt/cni/bin", 1);
        setenv("HOME", "/root", 1);
        setenv("USER", "root", 1);
        if (chdir("/root") != 0) {}

        if (access("/bin/sh", X_OK) == 0) {
            char *argv[] = {"sh", NULL};
            execv("/bin/sh", argv);
        }
        if (access("/bin/busybox", X_OK) == 0) {
            char *argv[] = {"busybox", "sh", NULL};
            execv("/bin/busybox", argv);
        }
        _exit(1);
    } else if (pid > 0) {
        s->pid = pid;
        s->last_spawn = now;
    }
}

static void spawn_fallback_console(void) {
    if (console_fallback_pid > 0) return;
    pid_t pid = fork();
    if (pid == 0) {
        int fd = open("/dev/console", O_RDWR);
        if (fd >= 0) {
            setsid();
            ioctl(fd, TIOCSCTTY, 1);
            tcsetpgrp(fd, getpid());
            dup2(fd, STDIN_FILENO);
            dup2(fd, STDOUT_FILENO);
            dup2(fd, STDERR_FILENO);
            if (fd > 2) close(fd);
        }
        setenv("TERM", "linux", 1);
        setenv("PATH", "/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin:/opt/cni/bin", 1);
        setenv("HOME", "/root", 1);
        setenv("USER", "root", 1);
        if (chdir("/root") != 0) {}

        if (access("/bin/sh", X_OK) == 0) {
            char *argv[] = {"sh", NULL};
            execv("/bin/sh", argv);
        }
        if (access("/bin/busybox", X_OK) == 0) {
            char *argv[] = {"busybox", "sh", NULL};
            execv("/bin/busybox", argv);
        }
        _exit(1);
    } else if (pid > 0) {
        console_fallback_pid = pid;
    }
}

static void supervise_terminals(void) {
    int any_active = 0;
    for (size_t i = 0; i < NUM_TERM_SESSIONS; i++) {
        if (term_sessions[i].pid <= 0 && !term_sessions[i].disabled) {
            spawn_terminal(&term_sessions[i]);
        }
        if (term_sessions[i].pid > 0) {
            any_active = 1;
        }
    }

    if (!any_active) {
        spawn_fallback_console();
    }
}

static void handle_child_exit(pid_t pid, int status) {
    time_t now = time(NULL);

    if (pid == containerd_pid) {
        printf("[init] containerd (PID %d) exited with status %d; restarting...\n", pid, status);
        containerd_pid = 0;
        start_containerd();
        return;
    }
    if (pid == sshd_pid) {
        printf("[init] sshd (PID %d) exited with status %d; restarting...\n", pid, status);
        sshd_pid = 0;
        start_sshd();
        return;
    }
    if (pid == console_fallback_pid) {
        console_fallback_pid = 0;
        return;
    }

    for (size_t i = 0; i < NUM_TERM_SESSIONS; i++) {
        if (term_sessions[i].pid == pid) {
            term_sessions[i].pid = 0;
            if (WIFEXITED(status) && WEXITSTATUS(status) == 2) {
                term_sessions[i].disabled = 1;
                return;
            }
            if (now - term_sessions[i].last_spawn < 2) {
                term_sessions[i].respawn_fails++;
            } else {
                term_sessions[i].respawn_fails = 0;
            }
            return;
        }
    }
}

static void perform_shutdown(int is_reboot) {
    printf("\n[init] syncing disks...\n");
    sync();

    printf("[init] stopping services (sshd, containerd)...\n");
    if (sshd_pid > 0) {
        kill(sshd_pid, SIGTERM);
    }
    if (containerd_pid > 0) {
        kill(containerd_pid, SIGTERM);
    }
    usleep(200000); // 200ms

    printf("[init] sending SIGTERM to all processes...\n");
    kill(-1, SIGTERM);
    sync();
    sleep(1);

    printf("[init] sending SIGKILL to remaining processes...\n");
    kill(-1, SIGKILL);
    sync();

    printf("[init] unmounting filesystems...\n");
    mount(NULL, "/", NULL, MS_REMOUNT | MS_RDONLY, NULL);
    sync();

    if (is_reboot) {
        printf("[init] rebooting system (ACPI/BIOS reset)...\n");
        reboot(RB_AUTOBOOT);
    } else {
        printf("[init] powering off system (ACPI powerdown)...\n");
        reboot(RB_POWER_OFF);
    }
}

int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;
    if (getpid() != 1) {
        fprintf(stderr, "ziro-init: must be run as PID 1\n");
        return 1;
    }

    // Standard system environment
    setenv("PATH", "/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin:/opt/cni/bin", 1);
    setenv("HOME", "/root", 1);
    setenv("USER", "root", 1);

    // If running on kernel ramfs, seamlessly migrate to tmpfs to enable container pivot_root
    check_and_switch_root();

    printf(BANNER);
    printf("[init] starting Ziro-OS PID 1 init...\n");

    // Signal setup
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sig_handler;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGPWR, &sa, NULL);
    sigaction(SIGUSR1, &sa, NULL);
    sigaction(SIGUSR2, &sa, NULL);
    signal(SIGCHLD, SIG_DFL);

    // Enable Ctrl-Alt-Del to send SIGINT to PID 1 for clean reboot
    reboot(RB_ENABLE_CAD);

    // Initialization phases
    init_filesystems();
    init_devices();
    init_cgroups();
    init_hostname();
    init_network();
    start_containerd();
    start_sshd();

    printf("\n[init] Ziro-OS initialization complete!\n");
    printf("[init] Type 'ziro-install' to install Ziro-OS to physical or virtual disk.\n");
    printf("[init] Type 'ziroctl help' for container OS commands.\n\n");

    // Check if auto-installer was requested on kernel command line
    FILE *cmdline = fopen("/proc/cmdline", "r");
    if (cmdline) {
        char buf[1024];
        if (fgets(buf, sizeof(buf), cmdline)) {
            if (strstr(buf, "ziro.autoinstall") != NULL) {
                printf("[init] Launching Ziro-OS Terminal Installer (ziro.autoinstall requested)...\n\n");
                pid_t ipid = fork();
                if (ipid == 0) {
                    setup_controlling_tty();
                    char *iargs[] = {"/usr/sbin/ziro-install", NULL};
                    execv(iargs[0], iargs);
                    _exit(1);
                } else if (ipid > 0) {
                    int st;
                    waitpid(ipid, &st, 0);
                }
            }
        }
        fclose(cmdline);
    }

    // Interactive supervisor loop (concurrent multi-terminal on tty1, ttyS0, ttyAMA0)
    while (!shutdown_requested && !reboot_requested) {
        supervise_terminals();

        int status;
        pid_t exited = waitpid(-1, &status, WNOHANG);
        if (exited > 0) {
            handle_child_exit(exited, status);
        } else {
            usleep(250000); // 250ms sleep -> zero CPU overhead when waiting
        }
    }

    perform_shutdown(reboot_requested);
    return 0;
}
