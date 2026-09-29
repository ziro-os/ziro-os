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
#include <limits.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

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
/* Crash-loop backoff for supervised daemons: restart at 1s, 2s, 4s ... capped at 60s. */
static time_t containerd_started = 0, containerd_restart_at = 0;
static time_t sshd_started = 0, sshd_restart_at = 0;
static int containerd_fails = 0, sshd_fails = 0;
static volatile sig_atomic_t shutdown_requested = 0;
static volatile sig_atomic_t reboot_requested = 0;

static void safe_mkdir(const char *dir, mode_t mode) {
    if (mkdir(dir, mode) < 0 && errno != EEXIST) {
        // ignore if exists
    }
}

static void init_devices(void);

/* devtmpfs has no /dev/fd or /dev/std* (udev/mdev normally add them). bash process
 * substitution, wg-quick and any "/dev/stdin" user need them. All devtmpfs mounts share
 * one superblock, so creating them once covers every later mount. */
static void dev_links(void) {
    safe_mkdir("/dev", 0755);
    symlink("/proc/self/fd", "/dev/fd");
    symlink("/proc/self/fd/0", "/dev/stdin");
    symlink("/proc/self/fd/1", "/dev/stdout");
    symlink("/proc/self/fd/2", "/dev/stderr");
}

/* Kernel cmdline is matched per whitespace-separated token, never by substring. */
static char kcmdline[1024];

static void read_cmdline(void) {
    kcmdline[0] = '\0';
    FILE *f = fopen("/proc/cmdline", "r");
    if (!f) return;
    if (!fgets(kcmdline, sizeof(kcmdline), f)) kcmdline[0] = '\0';
    fclose(f);
}

/* Returns the token equal to key, or the value after "key=" (key ending in '='). */
static const char *cmdline_find(const char *key, size_t *vlen) {
    size_t klen = strlen(key);
    int is_kv = key[klen - 1] == '=';
    const char *p = kcmdline;
    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == '\n') p++;
        const char *s = p;
        while (*p && *p != ' ' && *p != '\t' && *p != '\n') p++;
        size_t len = (size_t)(p - s);
        if (strncmp(s, key, klen) == 0 && (is_kv ? len >= klen : len == klen)) {
            // deepcode ignore IntegerOverflow: guarded by len >= klen on the same line; cannot underflow
            if (vlen) *vlen = (is_kv && len >= klen) ? len - klen : 0; /* never underflows */
            return s + klen;
        }
    }
    return NULL;
}

static int cmdline_has(const char *key) {
    return cmdline_find(key, NULL) != NULL;
}

/* Copy the value of "key=" from the kernel cmdline into out (empty if absent). */
static void cmdline_copy(const char *key, char *out, size_t max_len) {
    size_t vlen = 0;
    const char *v = cmdline_find(key, &vlen);
    if (!v || vlen >= max_len) return;
    memcpy(out, v, vlen);
    out[vlen] = '\0';
}

/* Make sure every partition listed by the kernel has a /dev node (no udev here). */
static void ensure_partition_nodes(void) {
    FILE *pf = fopen("/proc/partitions", "r");
    if (!pf) return;
    char pline[256];
    while (fgets(pline, sizeof(pline), pf)) {
        int maj = 0, min = 0;
        long long blocks = 0;
        char pname[128];
        if (sscanf(pline, "%d %d %lld %127s", &maj, &min, &blocks, pname) != 4) continue;
        char devpath[256];
        snprintf(devpath, sizeof(devpath), "/dev/%s", pname);
        struct stat st;
        if (stat(devpath, &st) != 0) mknod(devpath, S_IFBLK | 0660, makedev(maj, min));
    }
    fclose(pf);
}

/* Resolve root=LABEL=x | UUID=x | /dev/x with a single blkid scan (was one fork per partition). */
static void resolve_root_device(const char *spec, char *out_dev, size_t max_len) {
    out_dev[0] = '\0';
    if (!spec || !*spec) return;
    if (strncmp(spec, "/dev/", 5) == 0) {
        snprintf(out_dev, max_len, "%.200s", spec);
        return;
    }
    const char *pat, *want;
    int is_uuid = 0;
    if (strncmp(spec, "LABEL=", 6) == 0) {
        pat = " LABEL=\""; want = spec + 6;
    } else if (strncmp(spec, "UUID=", 5) == 0) {
        pat = " UUID=\""; want = spec + 5; is_uuid = 1;   /* leading space: not PARTUUID= */
    } else {
        return;
    }
    ensure_partition_nodes();
    FILE *bfp = popen("blkid 2>/dev/null", "r");
    if (!bfp) return;
    char line[512];
    while (fgets(line, sizeof(line), bfp)) {
        char *colon = strchr(line, ':');
        if (!colon) continue;
        char *v = strstr(colon, pat);
        if (!v) continue;
        v += strlen(pat);
        char *q = strchr(v, '"');
        if (!q) continue;
        *q = '\0';
        if (is_uuid ? strcasecmp(v, want) == 0 : strcmp(v, want) == 0) {
            *colon = '\0';
            snprintf(out_dev, max_len, "%.200s", line);
            break;
        }
    }
    pclose(bfp);
}

/*
 * The requested root disk is unusable. Never fall back to the live image (it has a
 * passwordless console and runs workloads in RAM). With the explicit 'ziro.recovery'
 * break-glass token, open a shell here; otherwise reboot so cloud VMs retry.
 */
static void root_fail(const char *what, const char *dev) {
    fprintf(stderr, "\n[init] FATAL: %s (%s)\n", what, dev);
    fprintf(stderr, "[init] Boot the 'Ziro-OS (Recovery Shell)' entry to repair the disk.\n");
    mount("devtmpfs", "/dev", "devtmpfs", MS_NOSUID, "mode=0755");
    mount("proc", "/proc", "proc", MS_NOSUID | MS_NOEXEC | MS_NODEV, NULL);
    mount("sysfs", "/sys", "sysfs", MS_NOSUID | MS_NOEXEC | MS_NODEV, NULL);
    if (cmdline_has("ziro.recovery")) {
        fprintf(stderr, "[init] ziro.recovery: starting emergency shell in the initramfs\n");
        char *rargs[] = {"-sh", NULL};
        execv("/bin/sh", rargs);
        execv("/bin/busybox", rargs);
    }
    fprintf(stderr, "[init] rebooting in 30s...\n");
    sync();
    sleep(30);
    reboot(RB_AUTOBOOT);
    for (;;) pause();
}

/* e2fsck -p before the read-write mount. Returns 0 to continue. */
static void check_root_fs(const char *dev, const char *fstype) {
    if (strncmp(fstype, "ext", 3) != 0) return;
    const char *fsck = access("/sbin/e2fsck", X_OK) == 0 ? "/sbin/e2fsck"
                     : access("/usr/sbin/e2fsck", X_OK) == 0 ? "/usr/sbin/e2fsck" : NULL;
    if (!fsck) {
        printf("[init] e2fsck not available; skipping root filesystem check\n");
        return;
    }
    pid_t pid = fork();
    if (pid == 0) {
        execl(fsck, "e2fsck", "-p", dev, (char *)NULL);
        _exit(8);
    }
    int st = 0;
    if (pid < 0 || waitpid(pid, &st, 0) < 0 || !WIFEXITED(st)) return;
    int rc = WEXITSTATUS(st);
    if (rc == 0) return;
    if (rc == 1) { printf("[init] e2fsck repaired %s\n", dev); return; }
    if (rc & 2) {
        printf("[init] e2fsck repaired %s and requires a reboot\n", dev);
        sync();
        reboot(RB_AUTOBOOT);
    }
    if (rc & 4) root_fail("root filesystem has errors e2fsck -p could not fix", dev);
    fprintf(stderr, "[init] warning: e2fsck exited %d on %s; continuing\n", rc, dev);
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
    dev_links();
    safe_mkdir("/proc", 0755);
    mount("proc", "/proc", "proc", MS_NOSUID | MS_NOEXEC | MS_NODEV, NULL);
    safe_mkdir("/sys", 0755);
    mount("sysfs", "/sys", "sysfs", MS_NOSUID | MS_NOEXEC | MS_NODEV, NULL);

    // 2. Discover hardware and load kernel modules (virtio_scsi, virtio_blk, sd_mod, ahci, nvme)
    init_devices();

    // 3. Inspect kernel command line
    char root_spec[256] = {0};
    read_cmdline();
    int live_requested = cmdline_has("ziro.live");
    size_t rlen = 0;
    const char *rval = cmdline_find("root=", &rlen);
    if (rval && rlen < sizeof(root_spec)) {
        memcpy(root_spec, rval, rlen);
        root_spec[rlen] = '\0';
    }

    // 4. Persistent root requested (e.g. root=LABEL=ZIRO_ROOT): wait for it, check it, switch to it.
    //    Fail closed: a missing or broken disk never falls back to the live image.
    if (!live_requested && root_spec[0] != '\0') {
        char val[32] = "";
        cmdline_copy("rootwait=", val, sizeof(val));
        long wait_s = val[0] ? strtol(val, NULL, 10) : 90;
        if (wait_s <= 0 || wait_s > 3600) wait_s = 90;
        char fstype[32] = "ext4";
        cmdline_copy("rootfstype=", fstype, sizeof(fstype));
        printf("[init] root device requested: %s (%s, rootwait=%lds)\n", root_spec, fstype, wait_s);

        char root_dev[256] = {0};
        struct timespec t0, now;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        useconds_t delay = 50000;
        long last_note = 0;
        for (;;) {
            resolve_root_device(root_spec, root_dev, sizeof(root_dev));
            if (root_dev[0] != '\0' && access(root_dev, F_OK) == 0) break;
            clock_gettime(CLOCK_MONOTONIC, &now);
            long waited = (long)(now.tv_sec - t0.tv_sec);
            if (waited >= wait_s) root_fail("root device not found", root_spec);
            if (waited >= last_note + 10) {
                last_note = waited;
                if (waited > 0) printf("[init] still waiting for %s (%lds/%lds)...\n", root_spec, waited, wait_s);
                init_devices();   /* late controllers (USB, slow cloud volume attach) */
            }
            usleep(delay);
            if (delay < 1000000) delay *= 2;
        }
        printf("[init] resolved root device: %s\n", root_dev);

        check_root_fs(root_dev, fstype);
        safe_mkdir("/sysroot", 0755);
        if (mount(root_dev, "/sysroot", fstype, MS_RELATIME, NULL) != 0)
            root_fail(strerror(errno), root_dev);
        printf("[init] mounted %s on /sysroot (%s)\n", root_dev, fstype);
        if (access("/sysroot/sbin/init", X_OK) != 0 && access("/sysroot/init", X_OK) != 0)
            root_fail("no /sbin/init on the root filesystem", root_dev);

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
        mknod("/sysroot/dev/urandom", S_IFCHR | 0666, makedev(1, 9));

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
        root_fail("switch_root failed", root_dev);
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
            "for d in bin boot sbin etc home lib lib64 opt root usr var; do "
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
    /* LSM state (lockdown, landlock, bpf) and pinned eBPF objects (Cilium, Tetragon, Falco) */
    mount_essential("securityfs", "/sys/kernel/security", "securityfs", MS_NOSUID | MS_NOEXEC | MS_NODEV, NULL);
    mount_essential("bpf", "/sys/fs/bpf", "bpf", MS_NOSUID | MS_NOEXEC | MS_NODEV, "mode=0700");
    mount_essential("devtmpfs", "/dev", "devtmpfs", MS_NOSUID, "mode=0755");
    dev_links();
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
        // Container & Virtual Networking / Netfilter
        "bridge", "br_netfilter", "veth", "tap", "tun", "wireguard",
        "nf_tables", "nfnetlink", "nft_nat", "nft_compat",
        "nft_chain_nat", "nft_masq", "xt_nat", "xt_conntrack",
        "xt_MASQUERADE", "xt_addrtype", "iptable_filter", "iptable_nat",
        NULL
    };

    // One modprobe for the whole list (was a fork+exec per module).
    char cmd[2048] = "modprobe -qa";
    for (int i = 0; modules[i] != NULL; i++) {
        strncat(cmd, " ", sizeof(cmd) - strlen(cmd) - 1);
        strncat(cmd, modules[i], sizeof(cmd) - strlen(cmd) - 1);
    }
    strncat(cmd, " 2>/dev/null", sizeof(cmd) - strlen(cmd) - 1);
    if (system(cmd) != 0) {}

    // Extra modules from /etc/modules, then hardware coldplug: every device modalias,
    // de-duplicated, in a single modprobe (was a shell loop running modprobe per device).
    if (system("[ -f /etc/modules ] && sed 's/#.*//' /etc/modules | xargs -r modprobe -qa 2>/dev/null; "
               "find /sys/devices -name modalias 2>/dev/null | xargs -r cat 2>/dev/null | sort -u | "
               "xargs -r modprobe -qa 2>/dev/null") != 0) {}

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

    // 5. Ensure all partition devices in /proc/partitions exist in /dev
    FILE *pf_devs = fopen("/proc/partitions", "r");
    if (pf_devs) {
        char pline[256];
        while (fgets(pline, sizeof(pline), pf_devs)) {
            int maj = 0, min = 0;
            long long blocks = 0;
            char pname[128];
            if (sscanf(pline, "%d %d %lld %127s", &maj, &min, &blocks, pname) == 4) {
                if (pname[0] == '\0' || strcmp(pname, "name") == 0) continue;
                char devpath[256];
                snprintf(devpath, sizeof(devpath), "/dev/%s", pname);
                struct stat st;
                if (stat(devpath, &st) != 0) {
                    mknod(devpath, S_IFBLK | 0660, makedev(maj, min));
                }
                char last = pname[strlen(pname) - 1];
                if (last >= '0' && last <= '9' && strncmp(pname, "loop", 4) != 0 && strncmp(pname, "ram", 3) != 0) {
                    printf("[init] partition detected: /dev/%s\n", pname);
                }
            }
        }
        fclose(pf_devs);
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

    // 3. Apply container bridge networking and routing sysctl parameters
    system("sysctl -q -w net.bridge.bridge-nf-call-iptables=1 2>/dev/null || true");
    system("sysctl -q -w net.bridge.bridge-nf-call-ip6tables=1 2>/dev/null || true");
    system("sysctl -q -w net.bridge.bridge-nf-call-arptables=1 2>/dev/null || true");
    system("sysctl -q -w net.ipv4.ip_forward=1 2>/dev/null || true");
    system("sysctl -q -w net.ipv6.conf.all.forwarding=1 2>/dev/null || true");
    system("sysctl -p /etc/sysctl.d/99-ziro.conf 2>/dev/null || true");
    system("sysctl -p /etc/sysctl.conf 2>/dev/null || true");
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
        containerd_started = time(NULL);
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
    // deepcode ignore MissingAuthorization: PID 1 must make sshd privilege-separation dir root-owned (sshd refuses otherwise)
    if (chown("/var/empty", 0, 0) != 0) {
        // ignore if not running as root
    }
    safe_mkdir("/run/sshd", 0755);
    safe_mkdir("/etc/ssh", 0755);
    safe_mkdir("/root/.ssh", 0700);
    chmod("/root/.ssh", 0700);
    // deepcode ignore MissingAuthorization: PID 1 must keep root's .ssh root-owned (sshd StrictModes)
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
        sshd_started = time(NULL);
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
            /* A plain device name from the kernel (e.g. ttyS0): never a path. */
            if (last_word && strlen(last_word) > 0 && strlen(last_word) < 32 &&
                strspn(last_word, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") == strlen(last_word)) {
                snprintf(dev_path, max_len, "/dev/%s", last_word);
            }
        }
        fclose(f);
    }
}

static int is_installed_system(void) {
    if (access("/etc/ziro-installed", F_OK) == 0) {
        return 1;
    }
    struct statfs s;
    if (statfs("/", &s) == 0) {
        if (s.f_type != RAMFS_MAGIC && s.f_type != TMPFS_MAGIC) {
            return 1;
        }
    }
    return 0;
}

/*
 * Console session: installed systems ALWAYS require login (a locked or empty
 * root password simply means no console login). A bare root shell is only
 * offered on the live ISO. Break-glass access is the exact 'ziro.recovery'
 * kernel argument, which already requires bootloader access.
 */
static void exec_console_session(void) {
    setenv("TERM", "linux", 1);
    setenv("PATH", "/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin:/opt/cni/bin", 1);
    setenv("HOME", "/root", 1);
    setenv("USER", "root", 1);
    if (chdir("/root") != 0) {}

    if (is_installed_system()) {
        char *largv[] = {"login", NULL};
        execv("/bin/login", largv);
        char *bargv[] = {"busybox", "login", NULL};
        execv("/bin/busybox", bargv);
        _exit(1); /* never fall back to an unauthenticated shell */
    }

    char *argv[] = {"-sh", NULL};
    execv("/bin/sh", argv);
    char *bargv[] = {"busybox", "sh", "-l", NULL};
    execv("/bin/busybox", bargv);
    _exit(1);
}

static void print_host_ips(void) {
    DIR *d = opendir("/sys/class/net");
    if (!d) return;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.' || strcmp(ent->d_name, "lo") == 0) continue;
        char cmd[512];
        snprintf(cmd, sizeof(cmd), "ip -4 addr show %s 2>/dev/null | awk '/inet /{print $2}'", ent->d_name);
        FILE *p = popen(cmd, "r");
        char ip[64] = {0};
        if (p) {
            if (fgets(ip, sizeof(ip), p)) {
                ip[strcspn(ip, "\r\n")] = '\0';
            }
            pclose(p);
        }
        if (strlen(ip) > 0) {
            printf("  * IPv4 (%s):    %s\n", ent->d_name, ip);
        } else {
            printf("  * IPv4 (%s):    configuring (DHCP auto-assign)...\n", ent->d_name);
        }
    }
    closedir(d);
}

static void setup_controlling_tty(void) {
    setsid();

    char dev_path[64];
    get_active_console(dev_path, sizeof(dev_path));

    // deepcode ignore PT: dev_path is /dev/<name>, name restricted to [A-Za-z0-9] in get_active_console
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

        exec_console_session();
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
        exec_console_session();
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

static time_t schedule_backoff(int fails) {
    return fails >= 6 ? 60 : (time_t)1 << fails;
}

static void restart_due_daemons(void) {
    time_t now = time(NULL);
    if (containerd_restart_at && now >= containerd_restart_at) {
        containerd_restart_at = 0;
        start_containerd();
    }
    if (sshd_restart_at && now >= sshd_restart_at) {
        sshd_restart_at = 0;
        start_sshd();
    }
}

/*
 * Supervision for /etc/ziro/services/<name>.conf with restart=always|on-failure (containerd and
 * sshd have their own supervisors above). Services started by 'ziroctl service start' are
 * reparented to PID 1; when one exits and its pidfile still names it (ziroctl stop removes the
 * pidfile first), it is restarted with the same crash-loop backoff.
 */
#define MAX_SUPERVISED 32
static struct {
    char name[64];
    int fails;
    time_t started, restart_at;
} supervised[MAX_SUPERVISED];

/* Service definitions steer what PID 1 restarts and which pidfile it deletes: only trust a
 * regular file owned by root and not writable by group or others. */
static int conf_trusted(FILE *f) {
    struct stat st;
    return fstat(fileno(f), &st) == 0 && S_ISREG(st.st_mode) && st.st_uid == 0 && (st.st_mode & 022) == 0;
}

/* Pidfiles live under /run: never follow a definition elsewhere (PID 1 unlinks them). */
static int pidfile_ok(const char *p) {
    return strncmp(p, "/run/", 5) == 0 && strstr(p, "..") == NULL && strlen(p) < 128;
}

static int conf_get(const char *path, const char *key, char *out, size_t max) {
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    if (!conf_trusted(f)) {
        fclose(f);
        return 0;
    }
    char line[256];
    size_t klen = strlen(key);
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, key, klen) == 0 && line[klen] == '=') {
            // deepcode ignore IntegerOverflow: line starts with key (strncmp) and line[klen] == '=', so both offsets are in bounds
            snprintf(out, max, "%s", line + klen + 1);
            out[strcspn(out, "\r\n")] = '\0';
            found = 1;
            break;
        }
    }
    fclose(f);
    return found;
}

static void supervise_service_exit(pid_t pid, int status) {
    DIR *d = opendir("/etc/ziro/services");
    if (!d) return;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        size_t n = strlen(e->d_name);
        if (n < 6 || n > 60 || strcmp(e->d_name + n - 5, ".conf") != 0) continue;
        char conf[320], restart[32] = "", pidfile[200] = "", pidbuf[32] = "", state[16] = "";
        snprintf(conf, sizeof(conf), "/etc/ziro/services/%s", e->d_name);
        if (!conf_get(conf, "restart", restart, sizeof(restart))) continue;
        int always = strcmp(restart, "always") == 0;
        if (!always && !(strcmp(restart, "on-failure") == 0 && !(WIFEXITED(status) && WEXITSTATUS(status) == 0))) continue;
        if (!conf_get(conf, "pidfile", pidfile, sizeof(pidfile)) || !pidfile_ok(pidfile)) continue;
        // deepcode ignore PT: pidfile comes from a root-owned, non-group/world-writable definition (conf_trusted) and pidfile_ok limits it to /run/ without ..
        FILE *pf = fopen(pidfile, "r");
        if (!pf) continue;
        if (!fgets(pidbuf, sizeof(pidbuf), pf)) pidbuf[0] = '\0';
        fclose(pf);
        if (atoi(pidbuf) != pid) continue;

        char name[64];
        snprintf(name, sizeof(name), "%.*s", (int)(n - 5), e->d_name);
        char enabled[320];
        snprintf(enabled, sizeof(enabled), "/etc/ziro/services/enabled/%s", name);
        FILE *ef = fopen(enabled, "r");
        if (ef) {
            if (!fgets(state, sizeof(state), ef)) state[0] = '\0';
            fclose(ef);
        }
        // deepcode ignore PT: same pidfile as above: trusted definition, confined to /run/ by pidfile_ok
        unlink(pidfile);
        if (strncmp(state, "disabled", 8) == 0) break;

        time_t now = time(NULL);
        int slot = -1;
        for (int i = 0; i < MAX_SUPERVISED; i++) {
            if (strcmp(supervised[i].name, name) == 0) { slot = i; break; }
            if (slot < 0 && supervised[i].name[0] == '\0') slot = i;
        }
        if (slot < 0) break;
        snprintf(supervised[slot].name, sizeof(supervised[slot].name), "%s", name);
        supervised[slot].fails = (now - supervised[slot].started < 10) ? supervised[slot].fails + 1 : 0;
        supervised[slot].restart_at = now + schedule_backoff(supervised[slot].fails);
        printf("[init] service %s (PID %d) exited with status %d; restarting in %lds\n",
               name, pid, status, (long)(supervised[slot].restart_at - now));
        break;
    }
    closedir(d);
}

static void restart_due_services(void) {
    time_t now = time(NULL);
    for (int i = 0; i < MAX_SUPERVISED; i++) {
        if (!supervised[i].restart_at || now < supervised[i].restart_at) continue;
        supervised[i].restart_at = 0;
        supervised[i].started = now;
        pid_t p = fork();
        if (p == 0) {
            char *argv[] = {"ziroctl", "service", "start", supervised[i].name, NULL};
            execv("/usr/bin/ziroctl", argv);
            _exit(1);
        } else if (p > 0) {
            waitpid(p, NULL, 0);
        }
    }
}

/* Apply the host firewall synchronously so sshd and containerd never listen unfiltered.
 * 'ziroctl service boot' applies it again later (idempotent). Skipped only when disabled. */
static void apply_firewall_early(void) {
    if (access("/usr/bin/ziroctl", X_OK) != 0) return;
    char state[16] = "";
    FILE *f = fopen("/etc/ziro/services/enabled/firewall", "r");
    if (f) {
        if (!fgets(state, sizeof(state), f)) state[0] = '\0';
        fclose(f);
    }
    if (strncmp(state, "disabled", 8) == 0) return;
    printf("[init] applying host firewall before network daemons...\n");
    pid_t pid = fork();
    if (pid == 0) {
        int log_fd = open("/var/log/firewall.log", O_WRONLY | O_CREAT | O_APPEND, 0600);
        if (log_fd >= 0) {
            dup2(log_fd, STDOUT_FILENO);
            dup2(log_fd, STDERR_FILENO);
            close(log_fd);
        }
        char *argv[] = {"ziroctl", "firewall", "apply", NULL};
        execv("/usr/bin/ziroctl", argv);
        _exit(1);
    } else if (pid > 0) {
        int st;
        waitpid(pid, &st, 0);
    }
}

/* Start everything enabled in /etc/ziro/services (firewall, sentinel, cloud-init, ...). */
static void start_enabled_services(void) {
    if (access("/usr/bin/ziroctl", X_OK) != 0) return;
    printf("[init] starting enabled Ziro services...\n");
    pid_t pid = fork();
    if (pid == 0) {
        char *argv[] = {"ziroctl", "service", "boot", NULL};
        execv("/usr/bin/ziroctl", argv);
        _exit(1);
    } else if (pid > 0) {
        int st;
        waitpid(pid, &st, 0);
    }
}

static void handle_child_exit(pid_t pid, int status) {
    time_t now = time(NULL);

    if (pid == containerd_pid) {
        containerd_pid = 0;
        containerd_fails = (now - containerd_started < 10) ? containerd_fails + 1 : 0;
        containerd_restart_at = now + schedule_backoff(containerd_fails);
        printf("[init] containerd (PID %d) exited with status %d; restarting in %lds\n",
               pid, status, (long)(containerd_restart_at - now));
        return;
    }
    if (pid == sshd_pid) {
        sshd_pid = 0;
        sshd_fails = (now - sshd_started < 10) ? sshd_fails + 1 : 0;
        sshd_restart_at = now + schedule_backoff(sshd_fails);
        printf("[init] sshd (PID %d) exited with status %d; restarting in %lds\n",
               pid, status, (long)(sshd_restart_at - now));
        return;
    }
    if (pid == console_fallback_pid) {
        console_fallback_pid = 0;
        return;
    }
    int is_term = 0;
    for (size_t i = 0; i < NUM_TERM_SESSIONS; i++) is_term |= term_sessions[i].pid == pid;
    if (!is_term) {
        supervise_service_exit(pid, status);
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
        /* Give containerd up to 10s to stop tasks and flush snapshots. */
        for (int i = 0; i < 100 && waitpid(containerd_pid, NULL, WNOHANG) == 0; i++) {
            usleep(100000);
        }
    }

    printf("[init] sending SIGTERM to all processes...\n");
    kill(-1, SIGTERM);
    sync();
    sleep(3);

    printf("[init] sending SIGKILL to remaining processes...\n");
    kill(-1, SIGKILL);
    while (waitpid(-1, NULL, WNOHANG) > 0) {}
    sync();

    printf("[init] unmounting filesystems...\n");
    pid_t upid = fork();
    if (upid == 0) {
        char *uargv[] = {"umount", "-a", "-r", NULL};
        execv("/bin/umount", uargv);
        char *bargv[] = {"busybox", "umount", "-a", "-r", NULL};
        execv("/bin/busybox", bargv);
        _exit(1);
    } else if (upid > 0) {
        waitpid(upid, NULL, 0);
    }
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

    // Inspect kernel command line for recovery or autoinstall
    read_cmdline();
    int recovery_requested = cmdline_has("ziro.recovery");
    int autoinstall_requested = cmdline_has("ziro.autoinstall");

    // Initialization phases
    init_filesystems();
    init_devices();

    if (recovery_requested) {
        printf("\n============================================================\n");
        printf("  Ziro-OS Emergency Maintenance / Recovery Shell\n");
        printf("  Filesystems mounted in /dev, /proc, /sys. Type 'exit' to reboot.\n");
        printf("============================================================\n\n");

        setup_controlling_tty();
        pid_t rpid = fork();
        if (rpid == 0) {
            setenv("TERM", "linux", 1);
            setenv("PATH", "/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin:/opt/cni/bin", 1);
            setenv("HOME", "/root", 1);
            setenv("USER", "root", 1);
            if (chdir("/root") != 0) {}
            char *rargs[] = {"-sh", NULL};
            execv("/bin/sh", rargs);
            execv("/bin/busybox", rargs);
            _exit(1);
        } else if (rpid > 0) {
            int st;
            waitpid(rpid, &st, 0);
        }

        printf("\n[recovery] Exiting recovery mode. Syncing and rebooting...\n");
        perform_shutdown(1);
        return 0;
    }

    if (is_installed_system()) {
        printf("\n================================================================================\n");
        printf("  Ziro-OS Enterprise Container Host (x86_64)\n");
        printf("  Minimal by design. Born for the cloud.\n");
        printf("================================================================================\n");
    } else {
        printf(BANNER);
        printf("[init] starting Ziro-OS Live & Installer Init...\n");
    }

    init_cgroups();
    init_hostname();
    init_network();
    apply_firewall_early();
    start_containerd();
    start_sshd();
    start_enabled_services();

    if (is_installed_system()) {
        char hname[64] = "ziro-os";
        gethostname(hname, sizeof(hname));
        printf("\n================================================================================\n");
        printf("  Ziro-OS Enterprise Container Host Status:\n");
        printf("  * Hostname:       %s\n", hname);
        print_host_ips();
        printf("  * Container:      containerd (active)\n");
        printf("  * OCI Runtime:    runc / crun\n");
        printf("  * Storage:        LABEL=ZIRO_ROOT (ext4)\n");
        printf("  * Management:     ziroctl (container, network, cluster, image)\n");
        printf("================================================================================\n\n");
    } else {
        printf("\n[init] Ziro-OS Live initialization complete!\n");
        printf("[init] Type 'ziro-install' to install Ziro-OS to physical or virtual disk.\n");
        printf("[init] Type 'ziroctl help' for container OS commands.\n\n");
    }

    if (autoinstall_requested) {
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

    // Interactive supervisor loop (concurrent multi-terminal on tty1, ttyS0, ttyAMA0)
    while (!shutdown_requested && !reboot_requested) {
        supervise_terminals();
        restart_due_daemons();
        restart_due_services();

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
