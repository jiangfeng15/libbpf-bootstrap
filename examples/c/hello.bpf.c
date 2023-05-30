#define BPF_NO_PRESERVE_ACCESS_INDEX
#include "vmlinux.h"
#include <bpf/bpf_helpers.h> 
//#include "simple.h"

//SEC("kprobe/__x64_sys_write")
//SEC("kprobe/__x64_sys_fchmodat")
SEC("kprobe/do_unlinkat")
int kprobe_write(void *ctx) {
	char msg[]="HELLO WORLD.\n";
	bpf_trace_printk(msg,sizeof(msg));
	return 0;
}

char _license[] SEC("license")="GPL";
