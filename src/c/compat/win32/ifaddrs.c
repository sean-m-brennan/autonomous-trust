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

/* getifaddrs / freeifaddrs over GetAdaptersAddresses (ifaddrs.h). */

#include <ifaddrs.h>
#include <net/if_dl.h>
#include <stdlib.h>
#include <string.h>

/* One allocation per entry: the entry, then its name and addresses. */
typedef struct
{
    struct ifaddrs ifa;
    char name[MAX_ADAPTER_NAME_LENGTH + 4];
    struct sockaddr_storage addr, mask, bcast;
    struct sockaddr_dl link;
} entry_t;

static entry_t *_entry(const IP_ADAPTER_ADDRESSES *ad, unsigned flags)
{
    entry_t *e = calloc(1, sizeof(*e));
    if (e == NULL)
        return NULL;
    snprintf(e->name, sizeof(e->name), "%s", ad->AdapterName);
    e->ifa.ifa_name = e->name;
    e->ifa.ifa_flags = flags;
    return e;
}

static void _prefix_mask(struct sockaddr_storage *out, int family, unsigned bits)
{
    memset(out, 0, sizeof(*out));
    if (family == AF_INET)
    {
        struct sockaddr_in *m = (struct sockaddr_in *)out;
        m->sin_family = AF_INET;
        m->sin_addr.s_addr = bits == 0 ? 0 : htonl(0xFFFFFFFFu << (32 - (bits > 32 ? 32 : bits)));
    }
    else
    {
        struct sockaddr_in6 *m = (struct sockaddr_in6 *)out;
        m->sin6_family = AF_INET6;
        for (unsigned i = 0; i < 16 && bits > 0; i++)
        {
            unsigned take = bits >= 8 ? 8 : bits;
            m->sin6_addr.s6_addr[i] = (unsigned char)(0xFF << (8 - take));
            bits -= take;
        }
    }
}

int getifaddrs(struct ifaddrs **ifap)
{
    if (ifap == NULL)
    {
        errno = EINVAL;
        return -1;
    }
    *ifap = NULL;
    ULONG size = 16 * 1024;
    IP_ADAPTER_ADDRESSES *list = NULL;
    ULONG rc = ERROR_BUFFER_OVERFLOW;
    for (int tries = 0; tries < 4 && rc == ERROR_BUFFER_OVERFLOW; tries++)
    {
        free(list);
        list = malloc(size);
        if (list == NULL)
        {
            errno = ENOMEM;
            return -1;
        }
        rc = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST
                                  | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
                                  NULL, list, &size);
    }
    if (rc != NO_ERROR)
    {
        free(list);
        errno = EIO;
        return -1;
    }

    struct ifaddrs *head = NULL, **tail = &head;
    for (IP_ADAPTER_ADDRESSES *ad = list; ad != NULL; ad = ad->Next)
    {
        if (ad->OperStatus != IfOperStatusUp)
            continue;
        unsigned flags = IFF_UP | IFF_MULTICAST;
        if (ad->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
            flags |= IFF_LOOPBACK;
        else
            flags |= IFF_BROADCAST;
        for (IP_ADAPTER_UNICAST_ADDRESS *ua = ad->FirstUnicastAddress; ua != NULL; ua = ua->Next)
        {
            int family = ua->Address.lpSockaddr->sa_family;
            if (family != AF_INET && family != AF_INET6)
                continue;
            entry_t *e = _entry(ad, flags);
            if (e == NULL)
                break;
            memcpy(&e->addr, ua->Address.lpSockaddr, (size_t)ua->Address.iSockaddrLength);
            e->ifa.ifa_addr = (struct sockaddr *)&e->addr;
            _prefix_mask(&e->mask, family, ua->OnLinkPrefixLength);
            e->ifa.ifa_netmask = (struct sockaddr *)&e->mask;
            if (family == AF_INET)
            {
                struct sockaddr_in *a = (struct sockaddr_in *)&e->addr;
                struct sockaddr_in *m = (struct sockaddr_in *)&e->mask;
                struct sockaddr_in *b = (struct sockaddr_in *)&e->bcast;
                b->sin_family = AF_INET;
                b->sin_addr.s_addr = a->sin_addr.s_addr | ~m->sin_addr.s_addr;
                e->ifa.ifa_broadaddr = (struct sockaddr *)&e->bcast;
            }
            *tail = &e->ifa;
            tail = &e->ifa.ifa_next;
        }
        if (ad->PhysicalAddressLength > 0)
        {
            entry_t *e = _entry(ad, flags);
            if (e != NULL)
            {
                e->link.sdl_family = AF_LINK;
                e->link.sdl_alen = (unsigned char)ad->PhysicalAddressLength;
                memcpy(e->link.sdl_data, ad->PhysicalAddress, ad->PhysicalAddressLength);
                e->ifa.ifa_addr = (struct sockaddr *)&e->link;
                *tail = &e->ifa;
                tail = &e->ifa.ifa_next;
            }
        }
    }
    free(list);
    *ifap = head;
    return 0;
}

void freeifaddrs(struct ifaddrs *ifa)
{
    while (ifa != NULL)
    {
        struct ifaddrs *next = ifa->ifa_next;
        free(ifa);   /* the ifaddrs is the first member of its entry_t */
        ifa = next;
    }
}
