
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>


char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("tp/kvm/kvm_hypercall")
int trace_kvm_hypercall(struct trace_event_raw_sys_enter *ctx)
{
    int nr;
    int a0;
    int a1;

    nr = ctx->args[0];
	
  bpf_printk("KVM HYPERCALL : %d \n",nr);

    return 0 ;


}


SEC("kprobe/kvm_emulate_hypercall")
int trace_kvm_emulate_hypercall(struct pt_regs* ctx)
{	
	bpf_printk("EMULATE HYPERCALL\n");
	return 0;

}
SEC("tp/kvm/kvm_exit")
int trace_kvm_exit(struct trace_event_raw_sys_enter* ctx)
{
    unsigned int exit_reason = ctx->args[0];
    //bpf_printk("KVM EXIT, REASON : %d  \n",exit_reason);

    return 0;
}

