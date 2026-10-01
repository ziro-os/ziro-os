// SPDX-License-Identifier: GPL-2.0
// CO-RE eBPF example: counts exec() calls per user. Build: ziroctl dev bpf build sdk/examples/bpf/execcount.bpf.c
// Load with any libbpf loader (bpftool prog loadall execcount.bpf.o /sys/fs/bpf/execcount autoattach),
// then read the map: bpftool map dump name exec_by_uid
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u32);
	__type(value, u64);
} exec_by_uid SEC(".maps");

SEC("tp_btf/sched_process_exec")
int BPF_PROG(on_exec, struct task_struct *p)
{
	u32 uid = BPF_CORE_READ(p, cred, uid.val); // CO-RE: field offsets relocated at load time
	u64 one = 1, *n = bpf_map_lookup_elem(&exec_by_uid, &uid);

	if (n)
		__sync_fetch_and_add(n, 1);
	else
		bpf_map_update_elem(&exec_by_uid, &uid, &one, BPF_NOEXIST);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
