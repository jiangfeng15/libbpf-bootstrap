#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
//int count=0;
typedef unsigned long u64;

struct {
	__uint(type,BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, u64);
	__type(value, u64);
}global_value SEC(".maps");

SEC("xdp")
int hello(void *ctx)
{
	u64 key = 100;
	u64 *value = NULL;
	value = bpf_map_lookup_elem(&global_value, &key);
	if(value==NULL){
		unsigned long tmp = 0;
		value = &tmp;
		bpf_map_update_elem(&global_value, &key, value, BPF_ANY);
	}
	else{
		(*value)++;
		bpf_map_update_elem(&global_value, &key, value,BPF_ANY);
	}

	char fmt[]="hello world %d.\n";
	bpf_trace_printk(fmt,sizeof(fmt), *value);

	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
