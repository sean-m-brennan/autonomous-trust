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

/** @file DTN adapter (kind: scenario, protocol: dtn).
 *
 *  Twin of the Python DtnAdapter (conformance/harness/python/adapters/dtn.py).
 *  Reads fixtures.dtn.op, runs the DTN transport's addressing
 *  (extensions/dtn/dtn_eid.h) or the hybrid transport's routing
 *  (network/net_transport_hybrid.h), and asserts expected_state.host. Every op
 *  is a pure function; both adapters must assert the same values.
 */

#include "dtn_adapter.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <jansson.h>
#include <uuid/uuid.h>

#include "extensions/dtn/dtn_eid.h"
#include "network/net_transport.h"
#include "network/net_transport_hybrid.h"

#define FAILF(...)                                                        \
    do {                                                                  \
        char _d[320];                                                     \
        snprintf(_d, sizeof(_d), __VA_ARGS__);                            \
        at_case_result_set_fail(out, 0, "AssertionError", _d);            \
        return;                                                           \
    } while (0)

static const char *_sfield(json_t *o, const char *k)
{
    return json_string_value(json_object_get(o, k));
}

static bool _want_error(json_t *exp)
{
    return json_is_true(json_object_get(exp, "error"));
}

/* A uuid field: 1 parsed into @p out, 0 null or absent, -1 malformed. */
static int _uuid_field(json_t *o, const char *k, uuid_t out)
{
    json_t *v = json_object_get(o, k);
    if (v == NULL || json_is_null(v))
        return 0;
    const char *s = json_string_value(v);
    if (s == NULL || uuid_parse(s, out) != 0)
        return -1;
    return 1;
}

/* Compare a formed EID (rc = its length, or -1 for a refusal) with the
 * scenario's eid / error expectation. */
static void _check_eid(const char *what, int rc, const char *got, json_t *exp,
                       at_case_result_t *out)
{
    if (rc < 0) {
        if (!_want_error(exp))
            FAILF("%s: refused, but the scenario expects a value", what);
        at_case_result_set_pass(out, 0);
        return;
    }
    if (_want_error(exp))
        FAILF("%s: expected a refusal, got %s", what, got);
    const char *want = _sfield(exp, "eid");
    if (want == NULL || strcmp(got, want) != 0)
        FAILF("%s: %s, want %s", what, got, want ? want : "(none)");
    at_case_result_set_pass(out, 0);
}

static void _op_node_eid(json_t *fx, json_t *exp, at_case_result_t *out)
{
    uuid_t u;
    if (_uuid_field(fx, "uuid", u) != 1)
        FAILF("node_eid: bad uuid");
    char eid[DTN_EID_MAX + 1] = {0};
    _check_eid("node eid", dtn_eid_from_uuid(u, eid, sizeof(eid)), eid, exp, out);
}

static int _hex_byte(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static void _op_group_eid(json_t *fx, json_t *exp, at_case_result_t *out)
{
    const char *hex = _sfield(fx, "group_hash_hex");
    size_t n = hex ? strlen(hex) : 0;
    unsigned char hash[64];
    if (hex == NULL || n % 2 != 0 || n / 2 > sizeof(hash))
        FAILF("group_eid: bad group_hash_hex");
    for (size_t i = 0; i < n / 2; i++) {
        int hi = _hex_byte(hex[2 * i]), lo = _hex_byte(hex[2 * i + 1]);
        if (hi < 0 || lo < 0)
            FAILF("group_eid: bad group_hash_hex");
        hash[i] = (unsigned char)(hi << 4 | lo);
    }
    char eid[DTN_EID_MAX + 1] = {0};
    _check_eid("group eid", dtn_eid_for_group(hash, n / 2, eid, sizeof(eid)), eid, exp, out);
}

static void _op_endpoints(json_t *fx, json_t *exp, at_case_result_t *out)
{
    uuid_t node, group;
    int have_node = _uuid_field(fx, "node_uuid", node);
    int have_group = _uuid_field(fx, "group_uuid", group);
    if (have_node < 0 || have_group < 0)
        FAILF("endpoints: bad uuid");
    char eids[3][DTN_EID_MAX + 1];
    int joined = dtn_endpoints(have_node ? node : NULL, have_group ? group : NULL, eids);
    if (joined < 0)
        FAILF("endpoints: an EID did not fit");
    json_t *want = json_object_get(exp, "endpoints");
    if (!json_is_array(want) || json_array_size(want) != 3)
        FAILF("endpoints: expected_state.host.endpoints must list three");
    for (size_t i = 0; i < 3; i++) {
        json_t *pair = json_array_get(want, i);
        const char *weid = json_string_value(json_array_get(pair, 0));
        const char *wsvc = json_string_value(json_array_get(pair, 1));
        const char *svc = dtn_channel_suffix((int)i);
        if (weid == NULL || wsvc == NULL || strcmp(eids[i], weid) != 0 ||
            svc == NULL || strcmp(svc, wsvc) != 0)
            FAILF("endpoints[%zu]: %s %s, want %s %s", i, eids[i], svc ? svc : "(none)",
                  weid ? weid : "(none)", wsvc ? wsvc : "(none)");
    }
    json_t *wj = json_object_get(exp, "group_joined");
    if (!json_is_boolean(wj) || (joined == 1) != json_is_true(wj))
        FAILF("endpoints: group_joined %d", joined);
    at_case_result_set_pass(out, 0);
}

static int _channel(const char *name)
{
    if (name == NULL) return -1;
    if (strcmp(name, "peer") == 0) return NET_CHAN_PEER;
    if (strcmp(name, "broadcast") == 0) return NET_CHAN_BROADCAST;
    if (strcmp(name, "group") == 0) return NET_CHAN_GROUP;
    return -1;
}

static void _op_broadcast_eid(json_t *fx, json_t *exp, at_case_result_t *out)
{
    int ch = _channel(_sfield(fx, "channel"));
    uuid_t group;
    int have_group = _uuid_field(fx, "group_uuid", group);
    if (ch < 0 || have_group < 0)
        FAILF("broadcast_eid: bad channel or group_uuid");
    char eid[DTN_EID_MAX + 1] = {0};
    _check_eid("broadcast eid",
               dtn_broadcast_eid(ch, have_group ? group : NULL, eid, sizeof(eid)),
               eid, exp, out);
}

static void _op_demux(json_t *fx, json_t *exp, at_case_result_t *out)
{
    const char *service = _sfield(fx, "service");
    int ch = dtn_service_to_channel(service);
    const char *got = ch == NET_CHAN_PEER ? "peer"
                    : ch == NET_CHAN_BROADCAST ? "broadcast"
                    : ch == NET_CHAN_GROUP ? "group" : "none";
    const char *want = _sfield(exp, "channel");
    if (want == NULL || strcmp(got, want) != 0)
        FAILF("demux: %s -> %s, want %s", service ? service : "(null)", got,
              want ? want : "(none)");
    if (ch < NET_CHAN__COUNT) {
        const char *suffix = dtn_channel_suffix(ch);
        if (suffix == NULL || strcmp(suffix, service) != 0)
            FAILF("demux: channel %s does not map back to %s", got, service);
    }
    at_case_result_set_pass(out, 0);
}

static void _op_peer_eid(json_t *fx, json_t *exp, at_case_result_t *out)
{
    const char *target = _sfield(fx, "target");
    if (target == NULL)
        FAILF("peer_eid: missing target");
    /* The transport's lookup: exact address match, first listed wins. */
    uuid_t matched;
    bool found = false;
    json_t *peers = json_object_get(fx, "peers");
    size_t i;
    json_t *peer;
    json_array_foreach(peers, i, peer) {
        const char *addr = _sfield(peer, "address");
        if (addr != NULL && strcmp(addr, target) == 0) {
            if (_uuid_field(peer, "uuid", matched) != 1)
                FAILF("peer_eid: peers[%zu] has a bad uuid", i);
            found = true;
            break;
        }
    }
    /* The transport skips the lookup for an EID target; dtn_peer_eid uses an
     * EID verbatim either way. */
    char eid[DTN_EID_MAX + 1] = {0};
    _check_eid("peer eid", dtn_peer_eid(target, found ? matched : NULL, eid, sizeof(eid)),
               eid, exp, out);
}

static void _op_route(json_t *fx, json_t *exp, at_case_result_t *out)
{
    json_t *inners = json_object_get(fx, "inners");
    const char *target = _sfield(fx, "target");
    if (!json_is_array(inners) || json_array_size(inners) > HYBRID_MAX_INNERS || target == NULL)
        FAILF("route: bad inners or target");
    hybrid_config_t *cfg = calloc(1, sizeof(*cfg));
    if (cfg == NULL)
        FAILF("route: out of memory");
    size_t i;
    json_t *jin;
    json_array_foreach(inners, i, jin) {
        hybrid_inner_t *in = &cfg->inners[i];
        const char *kind = _sfield(jin, "kind");
        const char *cidr = _sfield(jin, "match_cidr");
        snprintf(in->kind, sizeof(in->kind), "%s", kind ? kind : "");
        if (cidr != NULL)
            snprintf(in->match_cidr, sizeof(in->match_cidr), "%s", cidr);
        in->match_eid = json_is_true(json_object_get(jin, "match_eid"));
        in->is_default = json_is_true(json_object_get(jin, "is_default"));
    }
    cfg->n_inners = json_array_size(inners);
    int got = hybrid_route(cfg, target, NULL);
    free(cfg);
    json_t *want = json_object_get(exp, "leg");
    if (!json_is_integer(want) || got != (int)json_integer_value(want))
        FAILF("route: %s -> %d, want %lld", target, got,
              json_is_integer(want) ? (long long)json_integer_value(want) : -99LL);
    at_case_result_set_pass(out, 0);
}

void at_dtn_conf_run(const at_case_t *c, at_case_result_t *out)
{
    if (strcmp(c->kind, "scenario") != 0) {
        char detail[160];
        snprintf(detail, sizeof(detail),
                 "C dtn adapter only handles kind:scenario (got %s)", c->kind);
        at_case_result_set_skip(out, detail);
        return;
    }
    json_t *fixtures = json_object_get(c->data, "fixtures");
    json_t *fx = json_is_object(fixtures) ? json_object_get(fixtures, "dtn") : NULL;
    if (!json_is_object(fx)) {
        at_case_result_set_fail(out, 0, "AssertionError", "missing fixtures.dtn");
        return;
    }
    json_t *state = json_object_get(c->data, "expected_state");
    json_t *exp = json_is_object(state) ? json_object_get(state, "host") : NULL;
    if (!json_is_object(exp)) {
        at_case_result_set_fail(out, 0, "AssertionError", "missing expected_state.host");
        return;
    }
    const char *op = _sfield(fx, "op");
    if (op == NULL)
        at_case_result_set_fail(out, 0, "AssertionError", "missing fixtures.dtn.op");
    else if (strcmp(op, "node_eid") == 0)
        _op_node_eid(fx, exp, out);
    else if (strcmp(op, "group_eid") == 0)
        _op_group_eid(fx, exp, out);
    else if (strcmp(op, "endpoints") == 0)
        _op_endpoints(fx, exp, out);
    else if (strcmp(op, "broadcast_eid") == 0)
        _op_broadcast_eid(fx, exp, out);
    else if (strcmp(op, "demux") == 0)
        _op_demux(fx, exp, out);
    else if (strcmp(op, "peer_eid") == 0)
        _op_peer_eid(fx, exp, out);
    else if (strcmp(op, "route") == 0)
        _op_route(fx, exp, out);
    else {
        char detail[160];
        snprintf(detail, sizeof(detail), "unknown dtn op %s", op);
        at_case_result_set_fail(out, 0, "AssertionError", detail);
    }
}
