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

/* Windows stand-in for <net/if.h>: the interface flags getifaddrs (ifaddrs.h) reports. */
#ifndef AT_COMPAT_NET_IF_H
#define AT_COMPAT_NET_IF_H

#include <at_win32.h>

#ifndef IFNAMSIZ
#define IFNAMSIZ IF_NAMESIZE
#endif
#ifndef IFF_UP
#define IFF_UP        0x1
#define IFF_BROADCAST 0x2
#define IFF_LOOPBACK  0x8
#define IFF_MULTICAST 0x1000
#endif

#endif /* AT_COMPAT_NET_IF_H */
