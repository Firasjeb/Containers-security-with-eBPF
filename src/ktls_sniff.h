
#define SOL_TLS 282
#define TLS_RX 2
#define TLS_TX 1
#define MAX_PROC 20
#define SIZE_MESSAGE 600 
#define TASK_COMM_LEN 16

#define BPF_F_CURRENT_CPU 0xffffffffULL

struct data{
    int pid;
    int socket;
    char message[SIZE_MESSAGE];
};

struct socket_info{
    int level_protocol;
    int optname;
};