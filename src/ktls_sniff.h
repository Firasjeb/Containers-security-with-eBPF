
#define SOL_TLS 282
#define TLS_RX 2
#define TLS_TX 1
#define MAX_PROC 20
#define MAX_DATA_SIZE 20000
#define TASK_COMM_LEN 16


struct data{
    int len;
    char message[MAX_DATA_SIZE];
};

struct socket_info{
    int level_protocol;
    int optname;
};