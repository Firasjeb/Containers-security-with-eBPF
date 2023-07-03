
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "my_prog.bpf.h"
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define BPF_NOEXIST 1

struct {
        __uint(type, BPF_MAP_TYPE_SOCKMAP);
        __uint(max_entries,1);
        __uint(key_size, sizeof(int));
        __uint(value_size, sizeof(int));
} socketmap SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size,sizeof(__u32));
    __uint(value_size,sizeof(__u32));

} perfbuf SEC(".maps");

//Programme pour retrouver la socket de nginx


SEC("sockops")
int prog_sockops(struct bpf_sock_ops *sock_ops){
    int key = 0;
    bpf_printk("Map updated \n");
    if(sock_ops->op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB || sock_ops -> op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB ){
        int ret = bpf_sock_map_update(sock_ops,&socketmap,&key,BPF_NOEXIST);
        if(ret < 0){
            bpf_printk("Failed to update the map \n");
        }
        return 0;
    }
    return 0;
}

SEC("sk_msg")
int handle_ktls(struct sk_msg_md *msg)
{
    // Use bpf_msg_pull_data to extract the data sent by the socket.
    struct data my_data;
    void *data = (void *)(long)msg->data;
    void *data_end = (void*)(long)msg->data_end;
    u32 len = msg->size;
    if(bpf_msg_pull_data(msg,0,len,0)==0){
        void *data = (void *)(long)msg->data;
        void *data_end=(void*)(long) msg->data_end;
        if(data)
            bpf_printk("%s \n",(char*)data);
        return SK_PASS;
    }else{        
        bpf_printk("Data not  pulled \n");
        return SK_DROP;
    }
}













