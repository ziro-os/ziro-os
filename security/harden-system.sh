#!/bin/bash
# Security hardening script for Ziro-OS

set -e

echo "=== Ziro-OS Security Hardening ==="

# Create security directories
mkdir -p /etc/security
mkdir -p /etc/seccomp
mkdir -p /etc/apparmor.d

echo "1. Configuring seccomp profiles..."

# Default seccomp profile for containers
cat > /etc/seccomp/default.json << 'EOF'
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": [
    "SCMP_ARCH_X86_64",
    "SCMP_ARCH_X86",
    "SCMP_ARCH_X32"
  ],
  "syscalls": [
    {
      "names": [
        "accept",
        "accept4",
        "access",
        "adjtimex",
        "alarm",
        "bind",
        "brk",
        "capget",
        "capset",
        "chdir",
        "chmod",
        "chown",
        "chown32",
        "clock_adjtime",
        "clock_getres",
        "clock_gettime",
        "clock_nanosleep",
        "close",
        "connect",
        "copy_file_range",
        "creat",
        "dup",
        "dup2",
        "dup3",
        "epoll_create",
        "epoll_create1",
        "epoll_ctl",
        "epoll_ctl_old",
        "epoll_pwait",
        "epoll_wait",
        "epoll_wait_old",
        "eventfd",
        "eventfd2",
        "execve",
        "execveat",
        "exit",
        "exit_group",
        "faccessat",
        "fadvise64",
        "fadvise64_64",
        "fallocate",
        "fanotify_mark",
        "fchdir",
        "fchmod",
        "fchmodat",
        "fchown",
        "fchown32",
        "fchownat",
        "fcntl",
        "fcntl64",
        "fdatasync",
        "fgetxattr",
        "flistxattr",
        "flock",
        "fork",
        "fremovexattr",
        "fsetxattr",
        "fstat",
        "fstat64",
        "fstatat64",
        "fstatfs",
        "fstatfs64",
        "fsync",
        "ftruncate",
        "ftruncate64",
        "futex",
        "futimesat",
        "getcpu",
        "getcwd",
        "getdents",
        "getdents64",
        "getegid",
        "getegid32",
        "geteuid",
        "geteuid32",
        "getgid",
        "getgid32",
        "getgroups",
        "getgroups32",
        "getitimer",
        "getpeername",
        "getpgid",
        "getpgrp",
        "getpid",
        "getppid",
        "getpriority",
        "getrandom",
        "getresgid",
        "getresgid32",
        "getresuid",
        "getresuid32",
        "getrlimit",
        "get_robust_list",
        "getrusage",
        "getsid",
        "getsockname",
        "getsockopt",
        "get_thread_area",
        "gettid",
        "gettimeofday",
        "getuid",
        "getuid32",
        "getxattr",
        "inotify_add_watch",
        "inotify_init",
        "inotify_init1",
        "inotify_rm_watch",
        "io_cancel",
        "ioctl",
        "io_destroy",
        "io_getevents",
        "ioprio_get",
        "ioprio_set",
        "io_setup",
        "io_submit",
        "ipc",
        "kill",
        "lchown",
        "lchown32",
        "lgetxattr",
        "link",
        "linkat",
        "listen",
        "listxattr",
        "llistxattr",
        "lremovexattr",
        "lseek",
        "lsetxattr",
        "lstat",
        "lstat64",
        "madvise",
        "memfd_create",
        "mincore",
        "mkdir",
        "mkdirat",
        "mknod",
        "mknodat",
        "mlock",
        "mlock2",
        "mlockall",
        "mmap",
        "mmap2",
        "mprotect",
        "mq_getsetattr",
        "mq_notify",
        "mq_open",
        "mq_timedreceive",
        "mq_timedsend",
        "mq_unlink",
        "mremap",
        "msgctl",
        "msgget",
        "msgrcv",
        "msgsnd",
        "msync",
        "munlock",
        "munlockall",
        "munmap",
        "nanosleep",
        "newfstatat",
        "_newselect",
        "open",
        "openat",
        "pause",
        "pipe",
        "pipe2",
        "poll",
        "ppoll",
        "prctl",
        "pread64",
        "preadv",
        "prlimit64",
        "pselect6",
        "ptrace",
        "pwrite64",
        "pwritev",
        "read",
        "readahead",
        "readlink",
        "readlinkat",
        "readv",
        "recv",
        "recvfrom",
        "recvmmsg",
        "recvmsg",
        "remap_file_pages",
        "removexattr",
        "rename",
        "renameat",
        "renameat2",
        "restart_syscall",
        "rmdir",
        "rt_sigaction",
        "rt_sigpending",
        "rt_sigprocmask",
        "rt_sigqueueinfo",
        "rt_sigreturn",
        "rt_sigsuspend",
        "rt_sigtimedwait",
        "rt_tgsigqueueinfo",
        "sched_getaffinity",
        "sched_getattr",
        "sched_getparam",
        "sched_get_priority_max",
        "sched_get_priority_min",
        "sched_getscheduler",
        "sched_rr_get_interval",
        "sched_setaffinity",
        "sched_setattr",
        "sched_setparam",
        "sched_setscheduler",
        "sched_yield",
        "seccomp",
        "select",
        "semctl",
        "semget",
        "semop",
        "semtimedop",
        "send",
        "sendfile",
        "sendfile64",
        "sendmmsg",
        "sendmsg",
        "sendto",
        "setfsgid",
        "setfsgid32",
        "setfsuid",
        "setfsuid32",
        "setgid",
        "setgid32",
        "setgroups",
        "setgroups32",
        "setitimer",
        "setpgid",
        "setpriority",
        "setregid",
        "setregid32",
        "setresgid",
        "setresgid32",
        "setresuid",
        "setresuid32",
        "setreuid",
        "setreuid32",
        "setrlimit",
        "set_robust_list",
        "setsid",
        "setsockopt",
        "set_thread_area",
        "set_tid_address",
        "setuid",
        "setuid32",
        "setxattr",
        "shmat",
        "shmctl",
        "shmdt",
        "shmget",
        "shutdown",
        "sigaltstack",
        "signalfd",
        "signalfd4",
        "sigreturn",
        "socket",
        "socketcall",
        "socketpair",
        "splice",
        "stat",
        "stat64",
        "statfs",
        "statfs64",
        "statx",
        "symlink",
        "symlinkat",
        "sync",
        "sync_file_range",
        "syncfs",
        "sysinfo",
        "tee",
        "tgkill",
        "time",
        "timer_create",
        "timer_delete",
        "timerfd_create",
        "timerfd_gettime",
        "timerfd_settime",
        "timer_getoverrun",
        "timer_gettime",
        "timer_settime",
        "times",
        "tkill",
        "truncate",
        "truncate64",
        "ugetrlimit",
        "umask",
        "uname",
        "unlink",
        "unlinkat",
        "utime",
        "utimensat",
        "utimes",
        "vfork",
        "vmsplice",
        "wait4",
        "waitid",
        "waitpid",
        "write",
        "writev"
      ],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}
EOF

echo "2. Configuring AppArmor profiles..."

# AppArmor profile for containerd
cat > /etc/apparmor.d/containerd << 'EOF'
#include <tunables/global>

/usr/bin/containerd {
  #include <abstractions/base>
  #include <abstractions/nameservice>

  capability dac_override,
  capability setuid,
  capability setgid,
  capability sys_admin,
  capability sys_chroot,
  capability sys_ptrace,
  capability kill,
  capability net_admin,
  capability net_raw,

  network inet stream,
  network inet dgram,
  network unix stream,
  network unix dgram,

  /usr/bin/containerd mr,
  /usr/bin/runc Px,
  
  /etc/containerd/** r,
  /var/lib/containerd/** rw,
  /run/containerd/** rw,
  
  /proc/sys/net/** r,
  /sys/fs/cgroup/** rw,
  
  owner /tmp/** rw,
  
  # Allow access to container filesystems
  /var/lib/containers/** rw,
  /opt/cni/bin/* Px,
  
  # Deny dangerous capabilities
  deny capability sys_module,
  deny capability sys_rawio,
  deny capability sys_boot,
}
EOF

# AppArmor profile for containers
cat > /etc/apparmor.d/ziro-container << 'EOF'
#include <tunables/global>

profile ziro-container flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>

  network,
  capability,
  file,
  umount,

  deny @{PROC}/* w,   # deny write for all files directly in /proc (not in a subdir)
  deny @{PROC}/{[^1-9],[^1-9][^0-9],[^1-9s][^0-9y][^0-9s],[^1-9][^0-9][^0-9][^0-9]*}/** w,
  deny @{PROC}/sys/[^k]** w,  # deny /proc/sys except /proc/sys/k* (effectively /proc/sys/kernel)
  deny @{PROC}/sys/kernel/{?,??,[^s][^h][^m]**} w,  # deny everything except shm* in /proc/sys/kernel/
  deny @{PROC}/sysrq-trigger rwklx,
  deny @{PROC}/mem rwklx,
  deny @{PROC}/kmem rwklx,
  deny @{PROC}/kcore rwklx,

  deny mount,

  deny /sys/[^f]*/** wklx,
  deny /sys/f[^s]*/** wklx,
  deny /sys/fs/[^c]*/** wklx,
  deny /sys/fs/c[^g]*/** wklx,
  deny /sys/fs/cg[^r]*/** wklx,
  deny /sys/firmware/** rwklx,
  deny /sys/kernel/security/** rwklx,
}
EOF

echo "3. Configuring system limits..."

# Security limits
cat > /etc/security/limits.d/ziro-os.conf << 'EOF'
# Ziro-OS security limits

# Prevent fork bombs
* soft nproc 4096
* hard nproc 8192

# Limit core dumps
* soft core 0
* hard core 0

# Limit memory usage
* soft memlock 64
* hard memlock 64

# File descriptor limits
* soft nofile 65536
* hard nofile 65536
EOF

echo "4. Configuring kernel parameters..."

# Kernel security parameters
cat > /etc/sysctl.d/99-ziro-security.conf << 'EOF'
# Ziro-OS security kernel parameters

# Network security
net.ipv4.ip_forward = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1

# IPv6 security
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Kernel security
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 1
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2

# File system security
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.suid_dumpable = 0

# Container security
user.max_user_namespaces = 15000
EOF

echo "5. Setting up audit logging..."

# Basic audit rules
cat > /etc/audit/rules.d/ziro-os.rules << 'EOF'
# Ziro-OS audit rules

# Monitor container runtime
-w /usr/bin/containerd -p x -k container-runtime
-w /usr/bin/runc -p x -k container-runtime
-w /usr/bin/ctr -p x -k container-runtime

# Monitor configuration changes
-w /etc/containerd/ -p wa -k container-config
-w /etc/cni/ -p wa -k network-config
-w /etc/kubernetes/ -p wa -k k8s-config

# Monitor privilege escalation
-a always,exit -F arch=b64 -S setuid -S setgid -S setreuid -S setregid -k privilege-escalation
-a always,exit -F arch=b32 -S setuid -S setgid -S setreuid -S setregid -k privilege-escalation

# Monitor network changes
-a always,exit -F arch=b64 -S socket -F a0=10 -k network-changes
-a always,exit -F arch=b32 -S socket -F a0=10 -k network-changes
EOF

echo "6. Configuring container security..."

# Update containerd config for security
cat >> /etc/containerd/config.toml << 'EOF'

# Security configuration
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc.options]
  SystemdCgroup = true
  
[plugins."io.containerd.grpc.v1.cri".containerd.default_runtime]
  runtime_type = "io.containerd.runc.v2"
  
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc-seccomp]
  runtime_type = "io.containerd.runc.v2"
  [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc-seccomp.options]
    BinaryName = "/usr/bin/runc"
    SystemdCgroup = true
    SeccompProfile = "/etc/seccomp/default.json"
EOF

echo ""
echo "✅ Security hardening complete!"
echo ""
echo "Applied security measures:"
echo "  - Seccomp profiles for containers"
echo "  - AppArmor profiles for containerd and containers"
echo "  - System resource limits"
echo "  - Kernel security parameters"
echo "  - Audit logging rules"
echo "  - Container runtime security"
echo ""
echo "To enable AppArmor profiles:"
echo "  apparmor_parser -r /etc/apparmor.d/containerd"
echo "  apparmor_parser -r /etc/apparmor.d/ziro-container"
echo ""
echo "To apply sysctl settings:"
echo "  sysctl --system"