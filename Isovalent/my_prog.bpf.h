#ifndef __MYPROGBPF__
#define __MYPROGBPF__


#define TASK_COMM_LEN 16
struct data {
    char msg[300];
    int remote_ip4;
};


#endif