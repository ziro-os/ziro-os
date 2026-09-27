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
    mount_essential("var", "/var", "tmpfs", MS_NODEV, "mode=0755");
    safe_mkdir("/var/log", 0755);
    safe_mkdir("/var/lib", 0755);
    safe_mkdir("/var/lib/containerd", 0755);
    safe_mkdir("/var/lib/containers", 0755);
    safe_mkdir("/var/empty", 0700);
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
                    write(fd_subtree, enable_cmd, strlen(enable_cmd));
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
    sethostname(hostname, strlen(hostname));
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
    chown("/var/empty", 0, 0);
    safe_mkdir("/run/sshd", 0755);
    safe_mkdir("/etc/ssh", 0755);
    safe_mkdir("/root/.ssh", 0700);
    chmod("/root/.ssh", 0700);
    chown("/root/.ssh", 0, 0);

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
        case SIGINT:
        case SIGTERM:
        case SIGPWR:
            shutdown_requested = 1;
            break;
        case SIGCHLD:
            // Handled in main loop
            break;
    }
}

static void reap_children(void) {
    int status;
    pid_t pid;
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        if (pid == containerd_pid) {
            printf("[init] containerd (PID %d) exited with status %d\n", pid, status);
            containerd_pid = 0;
        } else if (pid == sshd_pid) {
            printf("[init] sshd (PID %d) exited with status %d\n", pid, status);
            sshd_pid = 0;
        }
    }
}

static void spawn_shell(void) {
    pid_t pid = fork();
    if (pid == 0) {
        setsid();

        // Detect active console device if available in sysfs
        char dev_path[64] = "/dev/console";
        FILE *f = fopen("/sys/class/tty/console/active", "r");
        if (f) {
            char active_tty[32];
            if (fgets(active_tty, sizeof(active_tty), f)) {
                char *p = active_tty;
                while (*p && *p != ' ' && *p != '\n' && *p != '\r') p++;
                *p = '\0';
                if (strlen(active_tty) > 0) {
                    snprintf(dev_path, sizeof(dev_path), "/dev/%s", active_tty);
                }
            }
            fclose(f);
        }

        int fd = open(dev_path, O_RDWR);
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

        setenv("TERM", "linux", 1);
        setenv("PATH", "/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin:/opt/cni/bin", 1);
        setenv("HOME", "/root", 1);
        setenv("USER", "root", 1);
        chdir("/root");

        if (access("/bin/sh", X_OK) == 0) {
            char *argv[] = {"sh", NULL};
            execv("/bin/sh", argv);
        }
        if (access("/bin/busybox", X_OK) == 0) {
            char *argv[] = {"busybox", "sh", NULL};
            execv("/bin/busybox", argv);
        }
        fprintf(stderr, "[init] exec shell failed: %s\n", strerror(errno));
        _exit(1);
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
    }
}

static void perform_shutdown(int is_reboot) {
    printf("\n[init] sending SIGTERM to all processes...\n");
    kill(-1, SIGTERM);
    sync();
    sleep(1);

    printf("[init] sending SIGKILL to remaining processes...\n");
    kill(-1, SIGKILL);
    sync();

    printf("[init] unmounting filesystems...\n");
    mount(NULL, "/", NULL, MS_REMOUNT | MS_RDONLY, NULL);

    if (is_reboot) {
        printf("[init] rebooting system...\n");
        reboot(RB_AUTOBOOT);
    } else {
        printf("[init] powering off system...\n");
        reboot(RB_POWER_OFF);
    }
}

int main(int argc, char *argv[]) {
    if (getpid() != 1) {
        fprintf(stderr, "ziro-init: must be run as PID 1\n");
        return 1;
    }

    printf(BANNER);
    printf("[init] starting Ziro-OS PID 1 init...\n");

    // Standard system environment
    setenv("PATH", "/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin:/opt/cni/bin", 1);
    setenv("HOME", "/root", 1);
    setenv("USER", "root", 1);

    // Signal setup
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sig_handler;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGPWR, &sa, NULL);
    signal(SIGCHLD, SIG_DFL);

    // Initialization phases
    init_filesystems();
    init_cgroups();
    init_hostname();
    init_network();
    start_containerd();
    start_sshd();

    printf("\n[init] Ziro-OS initialization complete!\n");
    printf("[init] Type 'ziroctl help' for container OS commands.\n\n");

    // Interactive supervisor loop
    while (!shutdown_requested && !reboot_requested) {
        spawn_shell();
        reap_children();
        usleep(500000); // 500ms debounce before respawn
    }

    perform_shutdown(reboot_requested);
    return 0;
}
