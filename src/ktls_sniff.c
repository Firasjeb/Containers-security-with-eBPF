#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include "ktls_sniff.h"
//#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "ktls_sniff.skel.h"
#include <stdio.h>
#include <stdlib.h>

static volatile bool exiting = false;


int handle_data(void *ctx,void *data, size_t size)
{
    struct data *my_data = (struct data*) data;
    FILE* file;
    
    if(my_data -> len > 100){
        file = fopen("output.txt","a+");
        if(file == NULL){
            printf("Failed to open file\n");
            exit(1);
        }
        //fwrite(&my_data->len,sizeof(my_data->len),1,file);
        fwrite(my_data->message,my_data->len,1,file);
        fclose(file);
    }
    
    return 0;
}



int print_libbpf_log(enum libbpf_print_level level,const char* fmt, va_list args)
{
    if(level >= LIBBPF_DEBUG){
        return 0;
    }
    return vfprintf(stderr,fmt,args);
}


int main(int argc, char *argv[]){
    
    int err;
    struct ring_buffer* ring;
    int fd_map_traced;
    int fd_perf_buffer;
    int pid_trace;
    struct ktls_sniff_bpf* skel_ktls;
    int exiting = 0;

    libbpf_set_print(print_libbpf_log);

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


    fd_map_traced = bpf_map__fd(skel_ktls -> maps.traced_pids);
    
    
    printf("Choose the PID  of process to trace \n");
    scanf("%d",&pid_trace);
    err = bpf_map_update_elem(fd_map_traced,&pid_trace,&pid_trace,BPF_ANY);
    if(err){
        fprintf(stderr,"Failed to update map \n");
        goto cleanup;

    }

    fd_perf_buffer = bpf_map__fd(skel_ktls-> maps.data_tls);
    if(fd_perf_buffer < 0){
        fprintf(stderr,"Failed to find ringbuffer");
    }

    ring = ring_buffer__new(fd_perf_buffer,handle_data,NULL,NULL);
   

    if(!ring){
        fprintf(stderr,"Failed to open perf buffer\n");
        goto cleanup;

    }

    while(!exiting){
        err  = ring_buffer__poll(ring,100);
        if(err == -EINTR){
            err = 0;
            break;
        }

        if(err < 0 ){
            printf("error during polling\n");
            break;
        }
        }
        
    cleanup:
    
    ktls_sniff_bpf__destroy(skel_ktls);
    ktls_sniff_bpf__detach(skel_ktls);    
    return err < 0 ? -err : 0 ;




    

}