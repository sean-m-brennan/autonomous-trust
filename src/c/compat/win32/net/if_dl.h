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

/* Windows stand-in for <net/if_dl.h>: the AF_LINK entries of getifaddrs. */
#ifndef AT_COMPAT_NET_IF_DL_H
#define AT_COMPAT_NET_IF_DL_H

#include <at_win32.h>

/* The BSD link-layer address getifaddrs reports for each interface: how AT
 * reads a MAC where there is no SIOCGIFHWADDR (config/generate.c). Windows has
 * no AF_LINK; this one is ours, a value no Winsock family uses. */
#ifndef AF_LINK
#define AF_LINK 0xAF18
#endif

struct sockaddr_dl
{
    unsigned short sdl_family;   /* AF_LINK */
    unsigned char  sdl_alen;     /* address length */
    unsigned char  sdl_data[MAX_ADAPTER_ADDRESS_LENGTH];
};

#define LLADDR(s) ((caddr_t)((s)->sdl_data))
typedef char *caddr_t;

#endif /* AT_COMPAT_NET_IF_DL_H */
