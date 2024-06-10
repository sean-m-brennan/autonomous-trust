#include <stdbool.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>



#include "processes/processes.h"
#include "utilities/message.h"
#include "utilities/exception.h"
#include "network.h"


const bool use_mcast = false;

typedef struct {
    int domain;
    int type;
    int protocol;
} socket_t;

typedef struct {
    int level;
    int optname;
    const void *optval;
    socklen_t optlen;
} sock_opts_t;

typedef struct {
    int recv_ptp;
    int recv_grp;
    int recv_cast;
} recvrs_t;


int _send(socket_t *cfg, char *msg, char *host, int port)
{
    //int sock = socket(cfg->domain, cfg->type, cfg->protocol);
    // encode
    // connect
    // send all
    return 0;
}

void network_shutdown(recvrs_t *socks)
{
    if (socks->recv_cast > 0)
        close(socks->recv_cast);
    if (socks->recv_grp > 0)
        close(socks->recv_grp);
    if (socks->recv_ptp > 0)
        close(socks->recv_ptp);
}

int network_run(socket_t *cfg, const process_t *proc, map_t *queues, msgq_key_t signal)
{
    recvrs_t socks = {0};
    int backlog = 5;
    network_config_t *net_cfg = (network_config_t *)proc->conf.data_struct;
    int one = 1;

    char *address = net_cfg->address;
    struct addrinfo *res;
    struct addrinfo hints = {0};
    hints.ai_family = cfg->domain;
    hints.ai_socktype = cfg->type;
    if (address == NULL)
        hints.ai_flags = AI_PASSIVE;

    char port_str[32];
    snprintf(port_str, 31, "%d", net_cfg->port);
    char grp_port_str[32];
    snprintf(grp_port_str, 31, "%d", net_cfg->port + 1);

    int err = getaddrinfo(address, port_str, &hints, &res);
    if (err != 0) {
        if (err == EAI_SYSTEM)
            return SYS_EXCEPTION();
        return EXCEPTION(err);
    }
    socks.recv_ptp = socket(cfg->domain, cfg->type, cfg->protocol);
    if (socks.recv_ptp == -1)
        return SYS_EXCEPTION();
    err = setsockopt(socks.recv_ptp, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(int));
    if (err != 0) {
        network_shutdown(&socks);
        return SYS_EXCEPTION();
    }
    err = bind(socks.recv_ptp, res->ai_addr, res->ai_addrlen);
    if (err != 0) {
        network_shutdown(&socks);
        return SYS_EXCEPTION();
    }
    err = listen(socks.recv_ptp, backlog);
    if (err != 0) {
        network_shutdown(&socks);
        return SYS_EXCEPTION();
    }
    freeaddrinfo(res);

    err = getaddrinfo(address, grp_port_str, &hints, &res);
    if (err != 0) {
        network_shutdown(&socks);
        if (err == EAI_SYSTEM)
            return SYS_EXCEPTION();
        return EXCEPTION(err);
    }
    socks.recv_grp = socket(cfg->domain, cfg->type, cfg->protocol);
    if (socks.recv_grp == -1) {
        network_shutdown(&socks);
        return SYS_EXCEPTION();
    }
    err = setsockopt(socks.recv_grp, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(int));
    if (err != 0) {
        network_shutdown(&socks);
        return SYS_EXCEPTION();
    }
    err = bind(socks.recv_grp, res->ai_addr, res->ai_addrlen);
    if (err != 0) {
        network_shutdown(&socks);
        return SYS_EXCEPTION();
    }
    err = listen(socks.recv_grp, backlog);
    if (err != 0) {
        network_shutdown(&socks);
        return SYS_EXCEPTION();
    }
    freeaddrinfo(res);

    if (use_mcast) {
        char *mcast_address = net_cfg->multicast_address;
        err = getaddrinfo(mcast_address, port_str, &hints, &res);
        if (err != 0) {
            network_shutdown(&socks);
            if (err == EAI_SYSTEM)
                return SYS_EXCEPTION();
            return EXCEPTION(err);
        }
        //size_t packet_size = 65527;
        //int mcast_ttl = 2;
        //sock_opts_t send_opts = { .level = IPPROTO_IP, .optname = IP_MULTICAST_TTL, .optval = &mcast_ttl, .optlen = sizeof(int) };
        socks.recv_cast = socket(cfg->domain, SOCK_DGRAM, IPPROTO_UDP);
        if (socks.recv_cast == -1) {
            network_shutdown(&socks);
            return SYS_EXCEPTION();
        }
        err = setsockopt(socks.recv_cast, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(int));
        if (err != 0) {
            network_shutdown(&socks);
            return SYS_EXCEPTION();
        }
        err = bind(socks.recv_cast, res->ai_addr, res->ai_addrlen);
        if (err != 0) {
            network_shutdown(&socks);
            return SYS_EXCEPTION();
        }
        //setsockopt(IPPROTO_IP, IP_ADD_MEMBERSHIP, req);
        freeaddrinfo(res);
    } else {
        char *bcast_address = net_cfg->broadcast_address;
        err = getaddrinfo(bcast_address, port_str, &hints, &res);
        if (err != 0) {
            network_shutdown(&socks);
            if (err == EAI_SYSTEM)
                return SYS_EXCEPTION();
            return -1; // FIXME EXCEPTION(err);
        }
        //size_t packet_size = 65507;
        //sock_opts_t send_opts = { .level = SOL_SOCKET, .optname = SO_BROADCAST, .optval = &one, .optlen = sizeof(int) };
        socks.recv_cast = socket(cfg->domain, SOCK_DGRAM, IPPROTO_UDP);
        if (socks.recv_cast == -1) {
            network_shutdown(&socks);
            return SYS_EXCEPTION();
        }
        err = setsockopt(socks.recv_cast, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(int));
        if (err != 0) {
            network_shutdown(&socks);
            return SYS_EXCEPTION();
        }
        err = bind(socks.recv_cast, res->ai_addr, res->ai_addrlen);
        if (err != 0) {
            network_shutdown(&socks);
            return SYS_EXCEPTION();
        }
        freeaddrinfo(res);
    }

    // register handlers for intern msgs
    return process_run(proc, queues, signal);
}


/**********/

int network_udp_ip4_run(const process_t *proc, map_t *queues, msgq_key_t signal)
{
    socket_t cfg = { .domain = AF_INET, .type = SOCK_DGRAM, .protocol = IPPROTO_UDP };
    return network_run(&cfg, proc, queues, signal);
}
DECLARE_PROCESS(network, udp_net_4, network_udp_ip4_run);

int network_udp_ip6_run(const process_t *proc, map_t *queues, msgq_key_t signal)
{
    socket_t cfg = { .domain = AF_INET6, .type = SOCK_DGRAM, .protocol = IPPROTO_UDP };
    return network_run(&cfg, proc, queues, signal);
}
DECLARE_PROCESS(network, udp_net_6, network_udp_ip6_run);

int network_tcp_ip4_run(const process_t *proc, map_t *queues, msgq_key_t signal)
{
    socket_t cfg = { .domain = AF_INET, .type = SOCK_STREAM, .protocol = 0 };
    return network_run(&cfg, proc, queues, signal);
}
DECLARE_PROCESS(network, tcp_net_4, network_tcp_ip4_run);

int network_tcp_ip6_run(const process_t *proc, map_t *queues, msgq_key_t signal)
{
    socket_t cfg = { .domain = AF_INET6, .type = SOCK_STREAM, .protocol = 0 };
    return network_run(&cfg, proc, queues, signal);
}
DECLARE_PROCESS(network, tcp_net_6, network_tcp_ip6_run);
