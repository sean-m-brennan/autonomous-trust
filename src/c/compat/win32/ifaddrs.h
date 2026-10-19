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

/* Windows stand-in for <ifaddrs.h>: getifaddrs over GetAdaptersAddresses. */
#ifndef AT_COMPAT_IFADDRS_H
#define AT_COMPAT_IFADDRS_H

#include <at_win32.h>
#include <net/if.h>

/* getifaddrs over GetAdaptersAddresses (ifaddrs.c): an entry per unicast
 * address of each adapter that is up, plus one AF_LINK entry carrying its MAC.
 * ifa_name is the adapter's name (a GUID), which is what an interface name is
 * on Windows. */
struct ifaddrs
{
    struct ifaddrs  *ifa_next;
    char            *ifa_name;
    unsigned int     ifa_flags;
    struct sockaddr *ifa_addr;
    struct sockaddr *ifa_netmask;
    struct sockaddr *ifa_broadaddr;
    void            *ifa_data;
};

int  getifaddrs(struct ifaddrs **ifap);
void freeifaddrs(struct ifaddrs *ifa);

#endif /* AT_COMPAT_IFADDRS_H */
