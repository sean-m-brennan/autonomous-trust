/********************
 *  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *******************/

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
