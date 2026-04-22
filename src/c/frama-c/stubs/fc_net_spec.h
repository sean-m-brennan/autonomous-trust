#ifndef __FC_NET_SPEC_H
#define __FC_NET_SPEC_H

#ifdef __FRAMAC__
#include <netinet/in.h>

#ifndef __FC_IP_MREQ_DEFINED
#define __FC_IP_MREQ_DEFINED
struct ip_mreq {
    struct in_addr imr_multiaddr;
    struct in_addr imr_interface;
};
#endif
#endif

#endif
