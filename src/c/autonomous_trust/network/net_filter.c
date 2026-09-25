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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "network/net_filter.h"

/* Sorted by order (ties keep install order). Filled at network start before
 * the receiver threads run, then read-only, so unlocked -- as the other
 * registries. */
static const net_filter_t *chain[NET_FILTER_MAX];
static size_t chain_len = 0;

int net_filter_install(const net_filter_t *f)
{
    if (f == NULL || f->name == NULL || f->name[0] == '\0') {
        fprintf(stderr, "net_filter_install: refusing an unnamed filter\n");
        return -1;
    }
    if (net_filter_installed(f->name)) {
        fprintf(stderr, "net_filter_install: refusing %s: already installed\n", f->name);
        return -1;
    }
    if (chain_len >= NET_FILTER_MAX) {
        fprintf(stderr, "net_filter_install: refusing %s: chain full (%d)\n",
                f->name, NET_FILTER_MAX);
        return -1;
    }
    size_t at = chain_len;
    while (at > 0 && chain[at - 1]->order > f->order) {
        chain[at] = chain[at - 1];
        at--;
    }
    chain[at] = f;
    chain_len++;
    return 0;
}

bool net_filter_installed(const char *name)
{
    if (name == NULL)
        return false;
    for (size_t i = 0; i < chain_len; i++)
        if (strcmp(chain[i]->name, name) == 0)
            return true;
    return false;
}

void net_filters_reset(void)
{
    chain_len = 0;
}

net_filter_verdict_t net_filters_inbound(const net_thread_ctx_t *ctx, net_channel_t ch,
                                         uint8_t *buf, size_t nbytes,
                                         const char *from_addr, net_inbound_meta_t *meta)
{
    memset(meta, 0, sizeof(*meta));
    meta->inner = buf;
    meta->inner_len = nbytes;
    for (size_t i = 0; i < chain_len; i++) {
        const net_filter_t *f = chain[i];
        /* The slice is the thread's buffer: the core's const view of it is a
         * narrowing, not a promise the bytes are read-only. */
        uint8_t *frame = (uint8_t *)meta->inner;
        size_t len = meta->inner_len;
        meta->seen[i].frame = frame;
        meta->seen[i].len = len;
        meta->n_seen = i + 1;
        if (f->inbound == NULL)
            continue;
        net_filter_verdict_t v = f->inbound(ctx, ch, frame, len, from_addr, meta);
        if (v != NET_FILTER_CONTINUE)
            return v;
    }
    return NET_FILTER_CONTINUE;
}

int net_filters_outbound(const net_send_info_t *info, const uint8_t *in, size_t in_len,
                         uint8_t **out, size_t *out_len)
{
    const uint8_t *cur = in;
    size_t cur_len = in_len;
    for (size_t i = chain_len; i-- > 0;) {
        const net_filter_t *f = chain[i];
        if (f->outbound == NULL)
            continue;
        uint8_t *next = NULL;
        size_t next_len = 0;
        if (f->outbound(info, cur, cur_len, &next, &next_len) != 0 || next == NULL) {
            if (cur != in)
                free((void *)cur);
            return -1;
        }
        if (next != cur && cur != in)
            free((void *)cur);
        cur = next;
        cur_len = next_len;
    }
    *out = (uint8_t *)cur;
    *out_len = cur_len;
    return 0;
}

void net_filters_after_deliver(const net_thread_ctx_t *ctx, net_channel_t ch,
                               const net_inbound_meta_t *meta)
{
    for (size_t i = 0; i < meta->n_seen && i < chain_len; i++)
        if (chain[i]->after_deliver != NULL)
            chain[i]->after_deliver(ctx, ch, meta->seen[i].frame, meta->seen[i].len, meta);
}

int net_filters_check_config(const network_config_t *cfg, logger_t *logger)
{
    if (cfg == NULL)
        return 0;
    if ((cfg->group_forward || cfg->cross_cluster) && !cfg->envelope) {
        log_error(logger, "Network: %s needs \"envelope\": true in the network config;"
                          " refusing to start\n",
                  cfg->group_forward ? "group_forward" : "cross_cluster");
        return -1;
    }
    if (cfg->envelope && !net_filter_installed(NET_FILTER_ENVELOPE)) {
        log_error(logger, "Network: the network config asks for the routing envelope,"
                          " but libat_gateway is not loaded; refusing to start rather"
                          " than speak a wire format the cohort does not\n");
        return -1;
    }
    return 0;
}
