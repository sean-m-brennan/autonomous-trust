#ifndef MESSAGE_H
#define MESSAGE_H

#include <sys/msg.h>
#include <stdbool.h>

typedef enum {
    SIGNAL,
    GROUP,
    PEERS,
    CAPABILITIES,
    PEER_CAPABILITIES,
} msg_types_t;

typedef key_t msgq_key_t;

typedef int queue_id_t;

typedef struct {
    char *process;
    char *function;
    //obj;  // FIXME
    char *to_whom;
    char *from_whom;
    bool encrypt;
    char *return_to;
} message_t;

size_t message_size(message_t msg);

typedef struct {
    long mtype;
    message_t info;
} msgq_buf_t;

typedef struct {
    long mtype;
    struct sig_s {
        char signal[32];
        int sig;
    } info;
} signal_buf_t;

#define msgq_create(id) msgget(id, 0666 | IPC_CREAT)

#endif // MESSAGE_H
