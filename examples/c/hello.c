#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "hello.skel.h"

#define DEBUGFS "/sys/kernel/debug/tracing/"
void read_trace_pipe(void){
	int trace_fd;
	trace_fd = open(DEBUGFS "trace_pipe", O_RDONLY, 0);
	if(trace_fd < 0){
		printf("open pipe failed.");
		return ;
	}
	while(1){
		static char buff[4096]={0x00};
		ssize_t sz;
		sz = read(trace_fd, buff, sizeof(buff)-1);
		if(sz > 0){
			buff[sz]=0;
			puts(buff);
		}
	}



}
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}


int main(int argc, char **argv)
{
	struct hello_bpf *skel;
	int err;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);
	struct bpf_object_open_opts openopts = {};
	openopts.sz = sizeof(struct bpf_object_open_opts);
	openopts.btf_custom_path = "/home/admin/a.btf";
	/* Open BPF application */
	//skel = hello_bpf__open_opts(&openopts);
	skel = hello_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}
	/* ensure BPF program only handles write() syscalls from our process */
	//skel->bss->my_pid = getpid();
	/* Load & verify BPF programs */
	err = hello_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}
	/* Attach tracepoint handler */
	err = hello_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}
	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF programs.\n");
	
	/*
	for (;;) {
	// trigger our BPF program 
		fprintf(stderr, ".");
		sleep(1);
	}*/
	read_trace_pipe();

cleanup:
	hello_bpf__destroy(skel);
	return -err;
}

