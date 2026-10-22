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

#ifndef AT_SELECTION_H
#define AT_SELECTION_H

/** @defgroup internal_selection Selective assignment (R+D.md §12.7)
 *
 * The C twin of Python `autonomous_trust.oracle.selection`
 * (RD_12.7_SELECTIVE_ASSIGNMENT_PLAN.md): the `selection.json` declaration,
 * the draw and its exact inclusion probabilities, the committed seed chain
 * that makes a draw auditable, the requestor's decision log, the peer's audit
 * of it, and the doubly robust estimator over the log. Every rule here is
 * pinned against Python by the `selection` conformance protocol, so each sum
 * runs left to right in the order Python's does.
 * @{
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <jansson.h>

#include "certificates/rng.h"

/** Capability-name buffer, matching the other oracle layers. */
#define AT_SEL_NAME_LEN 63
/** Upper bound on per-capability policies. */
#define AT_SEL_MAX_CAPS 64
/** The floor for a policy that names none. */
#define AT_SEL_DEFAULT_FLOOR 0.05
/** The decision log's default bound, and the largest a declaration may ask. */
#define AT_SEL_DEFAULT_LOG_RECORDS 4096
#define AT_SEL_MAX_LOG_RECORDS (1 << 20)
/** The largest k a declaration may ask for. */
#define AT_SEL_MAX_K 1024

/** Links per seed chain, checkpoint spacing and link size. */
#define AT_SEL_CHAIN_LENGTH (1 << 16)
#define AT_SEL_CHAIN_CHECKPOINT 256
#define AT_SEL_LINK_BYTES 32
#define AT_SEL_HEX_LEN (AT_SEL_LINK_BYTES * 2)

/** Pseudo-observations behind each peer in the estimator's reward model, and
 *  the model's value with no probe at all. */
#define AT_SEL_PRIOR_STRENGTH 2.0
#define AT_SEL_NEUTRAL 0.5

/* ---- the declaration ---------------------------------------------------- */

/** How one capability is assigned: @c k 0 fans out to everyone (JSON null). */
typedef struct {
    int    k;
    double floor;
} at_sel_policy_t;

typedef struct {
    char            name[AT_SEL_NAME_LEN + 1];
    at_sel_policy_t policy;
} at_sel_cap_t;

typedef struct {
    bool            declared;   /* false only for the empty model */
    at_sel_policy_t def;
    bool            has_probe;
    double          probe_floor;
    at_sel_cap_t    caps[AT_SEL_MAX_CAPS];
    size_t          num_caps;
    int             log_records;
} at_selection_model_t;

/** Validate a decoded declaration into @p out. NULL @p doc gives the empty
 *  model. @return false with @p err set on a malformed one. */
bool at_selection_parse(const json_t *doc, at_selection_model_t *out,
                        char *err, size_t errlen);

/** Parse @p text, as Python's json.loads would. */
bool at_selection_parse_text(const char *text, at_selection_model_t *out,
                             char *err, size_t errlen);

/** The declaration named by $AT_SELECTION, or the empty model. */
bool at_selection_load_env(at_selection_model_t *out, char *err, size_t errlen);

/** @p cap's own policy, or the default. */
const at_sel_policy_t *at_selection_policy_for(const at_selection_model_t *m,
                                               const char *cap);

/** True when @p cap is drawn from rather than fanned out. */
bool at_selection_selects(const at_selection_model_t *m, const char *cap);

/* ---- the draw ------------------------------------------------------------ */

typedef enum { AT_SEL_ALL = 0, AT_SEL_CATEGORICAL, AT_SEL_BERNOULLI } at_sel_kind_t;

/** One draw in [0, 1): the high 53 bits of the next output. */
double at_sel_unit(at_splitmix64_t *rng);

/** The seed a link stands for: its first eight bytes, big-endian. */
uint64_t at_sel_seed_of(const unsigned char *link);

/** The categorical distribution over @p w with every entry at least
 *  @p floor, into @p p. @return true when the floor was unsatisfiable and
 *  the result is uniform. */
bool at_sel_propensities(const double *w, size_t n, double floor, double *p);

/** The index whose cumulative interval holds @p u. */
size_t at_sel_pick(const double *p, size_t n, double u);

/** The decision for one task: categorical for @p k 1, Bernoulli above, every
 *  peer for @p k 0 or at least @p n. Writes @p selected and @p inclusion
 *  (both length @p n). @return 0, or -1 out of memory. */
int at_sel_draw(const double *w, size_t n, int k, double floor, uint64_t seed,
                bool *selected, double *inclusion, at_sel_kind_t *kind,
                bool *degraded, bool *fallback);

/* ---- the seed chain ------------------------------------------------------- */

typedef struct {
    unsigned char root[AT_SEL_LINK_BYTES];
    unsigned char head[AT_SEL_LINK_BYTES];
    /* checkpoints[j] = H^(j*CHECKPOINT)(root) */
    unsigned char checkpoints[AT_SEL_CHAIN_LENGTH / AT_SEL_CHAIN_CHECKPOINT + 1]
                             [AT_SEL_LINK_BYTES];
} at_sel_chain_t;

/** Build the chain of @p root. */
void at_sel_chain_init(at_sel_chain_t *c, const unsigned char *root);

/** The seed for draw @p index (1 .. LENGTH). @return 0, -1 out of range. */
int at_sel_chain_link(const at_sel_chain_t *c, long index, unsigned char *out);

/** True when @p link is draw @p index of the chain committed to by @p head;
 *  with @p known_index > 0, checked forward from that already-checked link. */
bool at_sel_verify_link(const unsigned char *head, long index,
                        const unsigned char *link, long known_index,
                        const unsigned char *known_link);

/** True when @p old_root closes the chain committed to by @p old_head. */
bool at_sel_verify_rotation(const unsigned char *old_head,
                            const unsigned char *old_root);

/** Lowercase hex of @p n bytes into @p out (2n+1). */
void at_sel_hex(const unsigned char *in, size_t n, char *out);
/** Parse exactly @p n bytes of hex. @return 0, -1 malformed. */
int at_sel_unhex(const char *hex, unsigned char *out, size_t n);

/* ---- the decision log ------------------------------------------------------ */

typedef enum { AT_SEL_OUT_NONE = 0, AT_SEL_OUT_SCORE, AT_SEL_OUT_DECLINED } at_sel_out_t;

typedef struct {
    char         peer[37];
    double       propensity;
    double       weight;
    bool         selected;
    at_sel_out_t outcome;
    double       score;
} at_sel_row_t;

typedef struct {
    long          index;
    char          head[AT_SEL_HEX_LEN + 1];
    char          link[AT_SEL_HEX_LEN + 1];
    char          task[37];
    char          capability[AT_SEL_NAME_LEN + 1];
    bool          probe;        /* purpose: "probe", else "task" */
    at_sel_kind_t kind;
    bool          degraded;
    bool          fallback;
    int           k;            /* 0 = null */
    double        floor;
    long          redraw_of;    /* 0 = none */
    size_t        n;
    at_sel_row_t *rows;
} at_sel_record_t;

/** The requestor: chain, probe counts and bounded log. */
typedef struct {
    at_selection_model_t model;
    at_sel_chain_t      *chain;
    long                 next_index;
    bool                 has_prev_root;
    unsigned char        prev_root[AT_SEL_LINK_BYTES];
    /* probe counts, per peer */
    char               (*probe_peer)[37];
    long                *probe_count;
    size_t               probe_n, probe_cap;
    long                 probe_total;
    /* the log, oldest first */
    at_sel_record_t    **records;
    size_t               rec_n;
    char                 chain_path[512];
    char                 log_path[512];
    bool                 dirty;
    double               last_flush;
} at_sel_requestor_t;

/** Open the requestor of process @p proc_name with @p model: its files live
 *  in @p cfg_dir; a fresh chain is seeded from @p root (32 bytes), or from
 *  the system's entropy when NULL, unless the chain file exists.
 *  @return 0, -1 out of memory. */
int at_sel_requestor_open(at_sel_requestor_t *r, const at_selection_model_t *model,
                          const char *proc_name, const char *cfg_dir,
                          const unsigned char *root);
void at_sel_requestor_close(at_sel_requestor_t *r);

/** Draw over @p n peers (uuid strings in canonical order) with @p weights.
 *  Writes @p selected and the invitation's draw JSON. @return 0, -1. */
int at_sel_decide(at_sel_requestor_t *r, const char *task, const char *capability,
                  char (*peers)[37], const double *weights, size_t n, int k,
                  double floor, bool probe, long redraw_of, bool *selected,
                  char *draw_json, size_t draw_len);

/** Mark @p peer declined in @p task's latest decision that selected it.
 *  @return that record, or NULL. */
at_sel_record_t *at_sel_record_decline(at_sel_requestor_t *r, const char *task,
                                       const char *peer);

/** Join a scored result into the decision that selected @p peer. */
bool at_sel_record_outcome(at_sel_requestor_t *r, const char *task,
                           const char *peer, double score);

/** True when some decision for @p task selected @p peer. */
bool at_sel_asked(const at_sel_requestor_t *r, const char *task, const char *peer);

/** The record for draw @p index, or NULL. */
const at_sel_record_t *at_sel_record_at(const at_sel_requestor_t *r, long index);

/** The audit answer for draw @p index asked by @p asker (new reference). */
json_t *at_sel_audit_answer(const at_sel_requestor_t *r, long index, const char *asker);

/** The asker's audit row for @p rec at @p pos (new reference). */
json_t *at_sel_audit_row(const at_sel_record_t *rec, size_t pos);

/** Write the log if it changed and @p force or the timer allows. */
void at_sel_requestor_flush(at_sel_requestor_t *r, bool force);

/** The UCB1 bonus the prober computes. */
double at_sel_ucb_bonus(long count, long total);

/** The probe count of @p peer. */
long at_sel_probe_count(const at_sel_requestor_t *r, const char *peer);

/* ---- the peer's audit -------------------------------------------------------- */

#define AT_SEL_AUDIT_MAX_PER_GAP 8

/** What a peer holds about one requestor's chain. */
typedef struct {
    char          requestor[37];
    unsigned char head[AT_SEL_LINK_BYTES];
    long          known_index;      /* 0 = none */
    unsigned char known_link[AT_SEL_LINK_BYTES];
    long         *indices;          /* every index checked */
    size_t        n_indices, cap_indices;
} at_sel_seen_t;

typedef struct {
    at_sel_seen_t *seen;
    size_t         n, cap;
} at_sel_peer_t;

void at_sel_peer_free(at_sel_peer_t *p);

/** Check one invitation's coin. @return the finding or NULL; the gap indices
 *  to audit go to @p gap (at most AT_SEL_AUDIT_MAX_PER_GAP). */
const char *at_sel_check_draw(at_sel_peer_t *p, const char *requestor,
                              const json_t *draw, long *gap, size_t *n_gap);

/** Check an audit answer. @return the finding or NULL. */
const char *at_sel_check_answer(const at_sel_peer_t *p, const char *requestor,
                                const json_t *answer);

/* ---- the estimator ------------------------------------------------------------- */

/** The doubly robust estimate over @p n records (index order), as Python's
 *  estimate(): {capability: {decisions, observed, value, regret}} (new
 *  reference). */
json_t *at_sel_estimate(at_sel_record_t *const *records, size_t n);

/** Serialize @p rec as Python's log record (new reference), and parse one
 *  back (NULL on malformed). */
json_t *at_sel_record_to_json(const at_sel_record_t *rec);
at_sel_record_t *at_sel_record_from_json(const json_t *j);
void at_sel_record_free(at_sel_record_t *rec);

/** @} */
#endif /* AT_SELECTION_H */
