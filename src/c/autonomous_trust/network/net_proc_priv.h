#ifndef NET_PROC_H
#define NET_PROC_H

#include "processes/processes.h"

int network_udp_ip4_run(const process_t *proc, map_t *queues, msgq_key_t signal);

int network_udp_ip6_run(const process_t *proc, map_t *queues, msgq_key_t signal);

int network_tcp_ip4_run(const process_t *proc, map_t *queues, msgq_key_t signal);

int network_tcp_ip6_run(const process_t *proc, map_t *queues, msgq_key_t signal);

#endif // NET_PROC_H