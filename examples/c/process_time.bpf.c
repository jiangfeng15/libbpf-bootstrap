#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <linux/bpf>
#include <linux/types.h>

struct procEntry{
	u64 cpuTime;
	char comm[TASK_COMM_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key,pid_t);
	__type(value, u64);

}cpu_time SEC(".maps");

SEC("kprobe/sys_enter")

int capture_cpu_time(struct pt_regs *ctx){
	struct task_struct *task = bpf_get_current_task();
	u32 pid_key = task->pid;
	u64 *value = bpf_map_lookup_elem(&cpu_time, &pid_key);

	u64 cpuTime = bpf_ktime_get_ns() -task->sched_info.last_arrival;

	if(value){
		__sync_fetch_and_add(value, cpuTime);
	}
	else{
		struct procEntry entry = {};
		bpf_probe_read_kernel(entry.comm, TASK_COMM_LEN, task->comm);
		entry.cpuTime = cpuTime;
		bpf_map_update_elem(&my_map,&pid_key, &entry, BPF_AMY);
	}
	task->sched_info.last_arrival = bpf_ktime_get_ns();
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
