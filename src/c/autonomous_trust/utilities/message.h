#ifndef MESSAGE_H
#define MESSAGE_H

#include <sys/msg.h>
#include <stdbool.h>

#include "structures/map.h"

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

/**
 * @brief Get a message queue key
 * 
 * @param subdir A subdirectory of the AT config dir
 * @param filename An optional filename (otherwise "")
 * @param id An optional number (otherwise chosen at random)
 * @return msgq_key_t 
 */
msgq_key_t get_msgq_key(const char *subdir, const char *filename, const int id);

/**
 * @brief 
 * 
 * @param map 
 * @param key 
 * @return queue_id_t 
 */
queue_id_t fetch_msgq(map_t *map, const char *key);

#endif  // MESSAGE_H
