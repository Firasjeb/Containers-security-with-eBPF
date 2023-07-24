#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "ktls_sniff.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";



//Array qui stocke les process que l'on veut trace

struct {
    __uint(type,BPF_MAP_TYPE_HASH);
    __uint(max_entries,2);
    __uint(key_size,sizeof(int));
    __uint(value_size,sizeof(int));
} traced_pids SEC(".maps");



//Perfbuffer pour stocker les process qui utilisent KTLS

struct {
    __uint(type,BPF_MAP_TYPE_HASH);
    __uint(max_entries,3);
    __uint(key_size,sizeof(int));
    __uint(value_size,sizeof(int));
} traced_sockets SEC(".maps");

// Pour dechiffrer

struct{
    __uint(type,BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size,sizeof(__u32));
    __uint(value_size,sizeof(__u32));
} data_tls SEC(".maps");




struct{
    __uint(type,BPF_MAP_TYPE_HASH);
    __uint(max_entries,2);
    __uint(key_size,sizeof(int));
    __uint(value_size,sizeof(char *));
}  messages SEC(".maps");



//Heap car on peut pas allouer des variables > 512 Octets sur la stack
struct {
    __uint(type,BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries,1);
    __type(key,int);
    __type(value,struct data);
}heap SEC(".maps");



SEC("tp/syscalls/sys_enter_setsockopt")
int trace_event_setsockopt(struct trace_event_raw_sys_enter *ctx){
    
    int optname;
    int level ;
    int socket_fd;
    int *traced_pid;
    int zero = 1;
    int current_pid = bpf_get_current_pid_tgid() >> 32;
    traced_pid = bpf_map_lookup_elem(&traced_pids,&current_pid);

    if(traced_pid == NULL)
        return 0;
    
    if(*traced_pid != current_pid)
        return 0;
    
    
    if(ctx!= NULL){
        socket_fd = (int) BPF_CORE_READ(ctx,args[0]);
        level = BPF_CORE_READ(ctx,args[1]);
        optname = BPF_CORE_READ(ctx,args[2]);
        if(level && optname){
            if( level == SOL_TLS  && optname == TLS_RX){
                bpf_map_update_elem(&traced_sockets,&current_pid,&socket_fd,BPF_ANY);
            }
        }
  
    }  
    return 0; 
} 



SEC("tp/syscalls/sys_enter_recvmsg")
int trace_event_recvmsg(struct trace_event_raw_sys_enter* ctx){

    int *socket;
    struct user_msghdr *msg ;
    struct iovec * my_iovec;
    const char *buffer;

    int current_pid = bpf_get_current_pid_tgid() >> 32;
    socket = bpf_map_lookup_elem(&traced_sockets,&current_pid);

    if(socket == NULL)
        return 0;

    msg = (struct user_msghdr*) BPF_CORE_READ(ctx,args[1]) ;  
    
    if(msg){
        bpf_core_read_user(&my_iovec,sizeof(my_iovec),&msg->msg_iov);
        bpf_core_read_user(&buffer,sizeof(buffer),&my_iovec->iov_base);
        //bpf_printk("Adress buffer : %p\n",(char*) buffer);
        bpf_map_update_elem(&messages,&current_pid,&buffer,BPF_ANY);
    }
    
    return 0;
}
        
    

    SEC("tp/syscalls/sys_exit_recvmsg")
    int trace_event_exit_recvmsg(struct trace_event_raw_sys_exit* ctx){
        char **buffer;
        const char* p;
        unsigned int len;
        int res;
        int key = 0;
        struct data *data; 
        int current_pid = bpf_get_current_pid_tgid() >> 32;
        len =  (int) BPF_CORE_READ(ctx,ret);
        buffer = bpf_map_lookup_elem(&messages,&current_pid);

        data = bpf_map_lookup_elem(&heap,&key);

        if(data == NULL){
            bpf_printk("Failed to find data in the heap \n");
            return 0;
        }
                      
        if(buffer != NULL && len >0){
            bpf_probe_read(&p,sizeof(p),buffer); 
            data->len = (len < 0 ) ? (len && 0xFFFFFFFF) : MAX_DATA_SIZE;

            if(data ->len <0)
                return 0;

            if(data-> len > MAX_DATA_SIZE)
                return 0;
    
            bpf_probe_read_str(data->message,data->len,p);
            res  = bpf_perf_event_output(ctx,&data_tls,BPF_F_CURRENT_CPU,data,sizeof(*data));
            if(res)
                bpf_printk("Failed to send data to buffer, res :%d \n",res);

        }

        return 0;
    }
    







 
