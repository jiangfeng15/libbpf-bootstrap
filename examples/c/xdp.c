#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include "xdp.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args){
	return vfprintf(stderr, format, args);
}

static volatile sig_atomic_t stop;

static void sig_int(int signo){

	stop = 1;
}
int main(int argc, char **argv){
	struct xdp_bpf * skel;

	libbpf_set_print(libbpf_print_fn);

	skel = xdp_bpf__open_and_load();
	if(!skel){
		fprintf(stderr, "failed to open and load bpf skeleton\n");
		return 1;
	}
	int err = xdp_bpf__attach(skel);
	if(err){
		fprintf(stderr, "failed to attach bpf skeleton\n");
		return 2;
	}
	if(signal(SIGINT, sig_int) == SIG_ERR){
		fprintf(stderr, "can not signal handler\n");
		goto cleanup;
	}
	printf("successfully started! please run 'sudo cat /sys/kernel/debug/tracing/trace_pipe to see output of bpf programs.\n'");
	while(!stop)
	{
		fprintf(stderr, ".");
		unsigned long key=100;
		unsigned long value;
		int err = bpf_map__lookup_elem(skel->maps.global_value, &key,sizeof(key), &value, sizeof(value),BPF_ANY);
		if(err==0){
			fprintf(stderr, "count is %ld\n", value);
		}
		sleep(1);
	}
cleanup:
	xdp_bpf__destroy(skel);
	return 0;
}
