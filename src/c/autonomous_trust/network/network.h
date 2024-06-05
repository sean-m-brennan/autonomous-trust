#ifndef NETWORK_H
#define NETWORK_H

typedef struct
{
    /* data from json */
    int port;
    char *address;
    char *multicast_address;
    char *broadcast_address;
} network_config_t;


#endif // NETWORK_H
