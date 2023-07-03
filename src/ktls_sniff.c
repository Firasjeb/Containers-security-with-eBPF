#include <stdio.h>
#include <signal.h>
#include <unistd.h>
//#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "ktls_sniff.skel.h"


static volatile bool exiting = false;


void handle_data(void *ctx,int cpu,void *data, __u32 size)
{

    
    

}

void lost_data(void *ctx, int cpu , __u64 size)
{

    

}



int print_libbpf_log(enum libbpf_print_level level,const char* fmt, va_list args)
{
    if(level >= LIBBPF_DEBUG){
        return 0;
    }
    return vfprintf(stderr,fmt,args);
}


int main(int argc, char *argv[]){

    libbpf_set_print(print_libbpf_log);
    
    int err;
    struct perf_buffer* perf;
    int fd_map_traced;
    int fd_perf_buffer;
    int pid_trace;
    struct ktls_sniff_bpf* skel_ktls;
    int exiting = 0;
    int zero = 0;


    skel_ktls = ktls_sniff_bpf__open();
    if(skel_ktls== NULL){
        fprintf(stderr,"Could not find BPF file\n");
        return -1;
    }

    err = ktls_sniff_bpf__load(skel_ktls);
    if(err){
        fprintf(stderr,"Could not load BPF program in memory\n");
        return -1;
    }

    err = ktls_sniff_bpf__attach(skel_ktls);
    if(err){
        fprintf(stderr,"Failed to attach BPF program\n");
        goto cleanup;
        
    }


    //fd_prog_ktls = bpf_program__fd(skel_ktls->progs.trace_event_setsockopt);
    fd_map_traced = bpf_map__fd(skel_ktls -> maps.traced_pids);
    printf("Choose the PID to trace \n");
    scanf("%d",&pid_trace);
    printf("Started tracing the proces %d \n",pid_trace);
    err = bpf_map_update_elem(fd_map_traced,&zero,&pid_trace,BPF_ANY);
    if(err){
        fprintf(stderr,"Failed to update map \n");
        goto cleanup;

    }

    fd_perf_buffer = bpf_map__fd(skel_ktls-> maps.messages);
    if(fd_perf_buffer < 0){
        fprintf(stderr,"Failed to find perf buffer");
    }

    perf = perf_buffer__new(fd_perf_buffer,2,handle_data,lost_data,
                            NULL,NULL);
    err = libbpf_get_error(perf);

    if(perf == NULL){
        fprintf(stderr,"Failed to open perf buffer");
        goto cleanup;

    }

    
    while(!exiting){
        perf_buffer__poll(perf,100);
        }
    
    
    cleanup:
    
    ktls_sniff_bpf__destroy(skel_ktls);
    ktls_sniff_bpf__detach(skel_ktls);    
    return err < 0 ? -err : 0 ;




    

}