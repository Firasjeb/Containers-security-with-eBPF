#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "ktls_sniff.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";



//Array qui stocke les process que l'on veut trace

struct {
    __uint(type,BPF_MAP_TYPE_ARRAY);
    __uint(max_entries,MAX_PROC);
    __uint(key_size,sizeof(int));
    __uint(value_size,sizeof(int));
} traced_pids SEC(".maps");



//Perfbuffer pour stocker les process qui utilisent KTLS

/*
struct{
    __uint(type,BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size,sizeof(int));
    __uint(value_size,sizeof(int));
} ktls_process SEC(".maps");
*/


// Pour dechiffrer
struct{
    __uint(type,BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size,sizeof(__u32));
    __uint(value_size,sizeof(__u32));
} messages SEC(".maps");


SEC("tp/syscalls/sys_enter_setsockopt")
int trace_event_setsockopt(struct trace_event_raw_sys_enter *ctx){
    
    int *ret;
    int optname;
    int level ;
    int socket_fd;
    int current_pid = bpf_get_current_pid_tgid() << 32;
    ret = bpf_map_lookup_elem(&traced_pids,&current_pid);
    if(ret == NULL)
        return 0;

    if(ctx!= NULL){
        socket_fd = (int) BPF_CORE_READ(ctx,args[0]);
        level = BPF_CORE_READ(ctx,args[1]);
        optname = BPF_CORE_READ(ctx,args[2]);
        if(level && optname){
            if(optname != TLS_RX){
                bpf_map_delete_elem(&traced_pids,&current_pid);
            } 
            if( level == SOL_TLS  && optname == TLS_RX){
                bpf_printk("Socket %d is using KTLS \n",);
                //bpf_perf_event_output(ctx,&ktls_process,BPF_F_CURRENT_CPU,&current_pid,sizeof(int));
            }
        }
  
    }  
    return 0; 
} 

SEC("tp/syscalls/sys_enter_recvmsg")
int trace_event_recvmsg(struct trace_event_raw_sys_enter* ctx){

    int *err;
    struct user_msghdr* msg;
    struct iovec* msg_iov;
    struct data* data;
    int current_pid = bpf_get_current_pid_tgid() << 32;
    err = bpf_map_lookup_elem(&traced_pids,&current_pid);
    if(err == NULL){
        bpf_printk("This process is not using KTLS \n");
        return 0;
    }

    msg = (struct user_msghdr*) BPF_CORE_READ(ctx, args[1]);
    msg_iov = (struct iovec* ) BPF_CORE_READ(msg,msg_iov);
    if(!msg_iov)
        bpf_printk("Message Empty \n");
    return 0;
    

}
 






 
