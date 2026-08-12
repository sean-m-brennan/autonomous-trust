/* ******************
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
 * ****************** */
/**
 * @file trust_ladder.c
 * @brief Trust-ladder loader (C twin of core/_python/trust_ladder.py).
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <jansson.h>

#include "config/trust_ladder.h"
#include "utilities/at_jansson.h"
#include "utilities/exception.h"
#include "utilities/logger.h"
#include "utilities/util.h"

void trust_ladder_defaults(trust_ladder_t *out)
{
    if (out == NULL)
        return;
    memset(out, 0, sizeof(*out));
    out->num_capabilities = 0;
    out->bootstrap.enabled = true;
    out->bootstrap.duration_sec = TRUST_LADDER_DEFAULT_BOOTSTRAP_DURATION_SEC;
    out->bootstrap.pairs = TRUST_LADDER_DEFAULT_BOOTSTRAP_PAIRS;
    out->tier_demotion_epsilon = TRUST_LADDER_DEFAULT_TIER_DEMOTION_EPSILON;
}

/** An optional integer field: absent → @p dflt, present-but-not-an-integer →
 *  reported, because a typo in a ladder should not silently become a default.
 *  Mirrors Python's int(...) raising ValueError inside the loader. */
static int _opt_int(const json_t *obj, const char *key, int dflt, bool *bad)
{
    json_t *val = json_object_get((json_t *)obj, key);
    if (val == NULL || json_is_null(val))
        return dflt;
    if (!json_is_integer(val))
    {
        /* A real (2.0) is accepted the way Python's int() accepts a float;
         * anything else is malformed. */
        if (json_is_real(val))
            return (int)json_real_value(val);
        *bad = true;
        return dflt;
    }
    return (int)json_integer_value(val);
}

static double _opt_double(const json_t *obj, const char *key, double dflt,
                          bool *bad)
{
    json_t *val = json_object_get((json_t *)obj, key);
    if (val == NULL || json_is_null(val))
        return dflt;
    if (json_is_real(val))
        return json_real_value(val);
    if (json_is_integer(val))
        return (double)json_integer_value(val);
    *bad = true;
    return dflt;
}

static bool _opt_bool(const json_t *obj, const char *key, bool dflt, bool *bad)
{
    json_t *val = json_object_get((json_t *)obj, key);
    if (val == NULL || json_is_null(val))
        return dflt;
    if (json_is_boolean(val))
        return json_is_true(val);
    *bad = true;
    return dflt;
}

static int _parse_capabilities(const json_t *caps, trust_ladder_t *out)
{
    if (caps == NULL || json_is_null(caps))
        return 0;
    if (!json_is_object(caps))
    {
        log_error(NULL, "trust_ladder: `capabilities` must be an object\n");
        return -1;
    }
    const char *name;
    json_t *entry;
    json_object_foreach((json_t *)caps, name, entry)
    {
        if (out->num_capabilities >= TRUST_LADDER_MAX_CAPABILITIES)
        {
            /* Refused rather than truncated: a silently dropped tail would
             * leave some capabilities at the defaults with nothing to say so,
             * which reads as "the ladder does not cover them". */
            log_error(NULL, "trust_ladder: more than %d capabilities\n",
                      TRUST_LADDER_MAX_CAPABILITIES);
            return -1;
        }
        if (entry != NULL && !json_is_object(entry) && !json_is_null(entry))
        {
            log_error(NULL, "trust_ladder: malformed entry for '%s'\n", name);
            return -1;
        }
        ladder_capability_t *slot = &out->capabilities[out->num_capabilities];
        if (strlen(name) > CAP_NAMELEN)
        {
            log_error(NULL, "trust_ladder: capability name too long: '%s'\n",
                      name);
            return -1;
        }
        at_strlcpy(slot->name, name, sizeof(slot->name));
        bool bad = false;
        slot->required_tier = _opt_int(entry, "required_tier",
                                       TRUST_LADDER_DEFAULT_REQUIRED_TIER, &bad);
        slot->transaction_weight =
            _opt_int(entry, "transaction_weight",
                     TRUST_LADDER_DEFAULT_TRANSACTION_WEIGHT, &bad);
        if (bad)
        {
            log_error(NULL, "trust_ladder: malformed entry for '%s'\n", name);
            return -1;
        }
        out->num_capabilities++;
    }
    return 0;
}

int trust_ladder_load(const char *path, trust_ladder_t *out)
{
    if (out == NULL || path == NULL)
        return EXCEPTION(EINVAL);
    trust_ladder_defaults(out);

    json_error_t err;
    json_t *root = json_load_file(path, 0, &err);
    if (root == NULL)
    {
        /* An explicit path that does not parse -- or does not exist -- is an
         * error, matching Python's FileNotFoundError / ValueError for the same
         * call. The env-driven entry point below is the forgiving one. */
        log_error(NULL, "trust_ladder: %s: %s (line %d)\n", path, err.text,
                  err.line);
        return EXCEPTION(EINVAL);
    }
    if (!json_is_object(root))
    {
        log_error(NULL, "trust_ladder: %s: top level must be an object\n", path);
        json_decref(root);
        return EXCEPTION(EINVAL);
    }

    bool bad = false;
    json_t *boot = json_object_get(root, "bootstrap");
    if (boot != NULL && !json_is_null(boot) && !json_is_object(boot))
    {
        log_error(NULL, "trust_ladder: %s: `bootstrap` must be an object\n",
                  path);
        json_decref(root);
        trust_ladder_defaults(out);
        return EXCEPTION(EINVAL);
    }
    out->bootstrap.enabled = _opt_bool(boot, "enabled", true, &bad);
    out->bootstrap.duration_sec =
        _opt_int(boot, "duration_sec",
                 TRUST_LADDER_DEFAULT_BOOTSTRAP_DURATION_SEC, &bad);
    out->bootstrap.pairs =
        _opt_int(boot, "pairs", TRUST_LADDER_DEFAULT_BOOTSTRAP_PAIRS, &bad);
    out->tier_demotion_epsilon =
        _opt_double(root, "tier_demotion_epsilon",
                    TRUST_LADDER_DEFAULT_TIER_DEMOTION_EPSILON, &bad);
    if (bad)
    {
        log_error(NULL, "trust_ladder: %s: malformed bootstrap/epsilon\n", path);
        json_decref(root);
        trust_ladder_defaults(out);
        return EXCEPTION(EINVAL);
    }

    if (_parse_capabilities(json_object_get(root, "capabilities"), out) != 0)
    {
        json_decref(root);
        trust_ladder_defaults(out);
        return EXCEPTION(EINVAL);
    }
    json_decref(root);
    return 0;
}

int trust_ladder_load_env(trust_ladder_t *out)
{
    if (out == NULL)
        return EXCEPTION(EINVAL);
    trust_ladder_defaults(out);
    const char *path = getenv(TRUST_LADDER_ENV);
    if (path == NULL || path[0] == '\0')
        return 0;
    if (access(path, R_OK) != 0)
    {
        /* Missing env-pointed file degrades to the defaults with a warning, as
         * Python does: a misconfigured deployment should still start. Named
         * out loud, because a silently empty ladder looks exactly like a
         * scenario that declared none. */
        log_warn(NULL, "trust_ladder: %s=%s not found; using defaults\n",
                 TRUST_LADDER_ENV, path);
        return 0;
    }
    return trust_ladder_load(path, out);
}

const ladder_capability_t *trust_ladder_find(const trust_ladder_t *ladder,
                                             const char *name)
{
    if (ladder == NULL || name == NULL)
        return NULL;
    for (size_t i = 0; i < ladder->num_capabilities; i++)
    {
        if (strncmp(ladder->capabilities[i].name, name, CAP_NAMELEN) == 0)
            return &ladder->capabilities[i];
    }
    return NULL;
}

int trust_ladder_apply(const trust_ladder_t *ladder, capability_t *caps,
                       size_t num_caps)
{
    if (ladder == NULL || (caps == NULL && num_caps > 0))
        return -1;
    int updated = 0;
    for (size_t i = 0; i < num_caps; i++)
    {
        const ladder_capability_t *meta = trust_ladder_find(ladder,
                                                            caps[i].name);
        if (meta == NULL)
            continue;   /* not in the ladder: keep the code-declared metadata */
        caps[i].required_tier = meta->required_tier;
        caps[i].transaction_weight = meta->transaction_weight;
        updated++;
    }
    return updated;
}
