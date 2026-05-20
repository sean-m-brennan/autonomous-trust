#ifndef __FC_NETINET_UDP_H
#define __FC_NETINET_UDP_H

#include <stdint.h>

struct udphdr {
    uint16_t uh_sport;
    uint16_t uh_dport;
    uint16_t uh_ulen;
    uint16_t uh_sum;
};

#ifndef SOL_UDP
#define SOL_UDP 17
#endif

#endif
