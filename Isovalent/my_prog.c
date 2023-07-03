
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <signal.h>
#include <bpf/bpf.h>
#include <arpa/inet.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <bpf/libbpf.h>
#include <linux/socket.h>
#include "my_prog.skel.h"
#include <fcntl.h>
#include "my_prog.bpf.h"
#include <sys/sendfile.h>

#ifndef TCP_ULP
# define TCP_ULP 31
#endif
#ifndef SOL_TLS
# define SOL_TLS 282
#endif

#define BPF_CGROUP_SOCK_OPS  3

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void handle_data(void * ctx,int cpu,void *data, __u32 size)
{
    printf("Data handled \n");
}

static void lost_data(void* ctx,int cpu, __u64 cnt)
{
    fprintf(stderr,"Lost data \n");
}



static void sig_handler(int sing)
{
    exiting = true;
}


int main(int argc,char ** argv){

    struct my_prog_bpf* skel;
    int err;
    int fd_map;
    int fd_prog_skmsg;
    int fd_prog_sockops;
    int perfbuf_fd;
    struct perf_buffer* perfbuf;
    struct bpf_map* sock_map;
    struct bpf_program* my_prog;

    libbpf_set_print(libbpf_print_fn);

    skel = my_prog_bpf__open();
    if(!skel){
        fprintf(stderr,"Failed to open \n");
        return 1;
    }

    //Set attach type
    if(bpf_program__set_expected_attach_type(skel->progs.prog_sockops,BPF_CGROUP_SOCK_OPS)){
        fprintf(stderr,"Failed to set attach type \n");
        return -1;
    }

    //Charger le programme en mémoire
    err = my_prog_bpf__load(skel);
    if(err ){
        fprintf(stderr,"Failed to load \n");
        return 1;
    }

    my_prog = skel-> progs.prog_sockops;
    sock_map = skel -> maps.socketmap;
    fd_map = bpf_map__fd(sock_map);
    fd_prog_skmsg = bpf_program__fd(skel->progs.handle_ktls);
    fd_prog_sockops = bpf_program__fd(skel->progs.prog_sockops);
    perfbuf_fd = bpf_map__fd(skel->maps.perfbuf);    


    signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);
    
    //Attacher le programme en mémoire
    err = my_prog_bpf__attach(skel);
    if(err){
        fprintf(stderr,"Failed to attach BPF skeleton");
        goto cleanup;
    }

    int cgroup_fd;
    cgroup_fd = open("/sys/fs/cgroup/unified/my_cgroup",O_RDONLY);
    if(cgroup_fd == -1){
        fprintf(stderr,"Enable to open cgroup 1");
        return -1;
    }


    /*
    int cgroup_fd_docker;
    cgroup_fd_docker = open("/sys/fs/cgroup/unified/docker/759d78f781f9c233ef04dfc38c9170eb69e0222a34cfc91357e8f6377d42fd8b",O_RDONLY);
    if(cgroup_fd_docker == -1){
        fprintf(stderr,"Enable to open cgroup");
        return -1;
    }*/


    //Attacher le programme BPF à la map
    err = bpf_prog_attach(fd_prog_skmsg,fd_map,BPF_SK_MSG_VERDICT,0);
    if(err){
        fprintf(stderr,"Failed to attach program to socketmap \n");
        goto cleanup;

    }

    //Recuperer ringbuffer 
    perfbuf = perf_buffer__new(perfbuf_fd,1,handle_data,
                                            lost_data,NULL,NULL);
    if(perfbuf == NULL){
        err = -1;
        fprintf(stderr,"Could not create perf buffer \n");
        goto cleanup;
    }

    //Attacher le programme à un cgroup
    err = bpf_prog_attach(fd_prog_sockops,cgroup_fd,
                                BPF_CGROUP_SOCK_OPS,0);

    if(err){
        fprintf(stderr,"Failed to attach program to CGROUP: %d (%s)\n",err,strerror(errno));
        goto cleanup;
    }  
    
    //err = bpf_prog_attach(fd_prog_sockops,cgroup_fd_docker,
                                //BPF_CGROUP_SOCK_OPS,0);


    if(err){
        fprintf(stderr,"Failed to attach program to CGROUP DOCKER: %d (%s)\n",err,strerror(errno));
        goto cleanup;
    }  
        
    //Poller le buffer
    while(!exiting){
        err = perf_buffer__poll(perfbuf,10);
        if(err == -EINTR){
            err = 0;
            break;
        }

    }


    cleanup:
    bpf_prog_detach(fd_prog_sockops,BPF_CGROUP_SOCK_OPS);
    bpf_prog_detach(fd_map,BPF_SK_MSG_VERDICT);
    my_prog_bpf__destroy(skel);
    perf_buffer__free(perfbuf);
    
    return err < 0 ? -err : 0;
    
}