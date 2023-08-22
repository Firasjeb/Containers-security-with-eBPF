

#include <signal.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include "kvm_sniff.skel.h"


int print_libbpf_log(enum libbpf_print_level level, const char* fmt,va_list args)
{

      if(level >= LIBBPF_DEBUG){
        return 0;
    }
    return vfprintf(stderr,fmt,args);
}
int main(int argc,char *argv[]){

    int err;
    struct kvm_sniff_bpf* skel_kvm;
    libbpf_set_print(print_libbpf_log);

    skel_kvm = kvm_sniff_bpf__open();
    if(skel_kvm == NULL){
        fprintf(stderr,"Failed to open kvm sniff");
        return -1;
    }

    err = kvm_sniff_bpf__load(skel_kvm);
    if(err){
        fprintf(stderr,"Could not load BPF program in memory \n");
        return -1;
    }

    err = kvm_sniff_bpf__attach(skel_kvm);
    if(err){
        fprintf(stderr,"Failed to attach BPF program");
        goto cleanup;
    }


    while(1){};

    cleanup:
    kvm_sniff_bpf__destroy(skel_kvm);
    return err;




}
