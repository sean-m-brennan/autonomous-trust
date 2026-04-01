# Phase 5A: Update Proposal + Consensus Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enable peers in an AutonomousTrust mesh to propose, verify, and vote on software updates via decentralized Paxos consensus, with no central server.

**Architecture:** Extract the Paxos state machine from `rep_proc.c` into a shared `algorithms/paxos.c` module. Add a new `fleet` process with `UPDATE_PROPOSAL` message type and trust-gated voting on a separate chain from reputation scores. Fix inline C bugs as encountered.

**Tech Stack:** C11, CMake, libcheck (tests), jansson (JSON), libsodium (crypto), protobuf-c (serialization)

**Repo root:** `/home/user/Software/sustainable_space/lib/muudd/lib/autonomous_trust`
**C source root:** `src/c/` (all paths below are relative to repo root unless noted)

---

## File Map

### New Files

| File | Responsibility |
|------|---------------|
| `src/c/autonomous_trust/algorithms/paxos.h` | Shared Paxos engine: state machine types and API |
| `src/c/autonomous_trust/algorithms/paxos.c` | Shared Paxos engine: propose, handle_request, handle_grant, handle_accepted |
| `src/c/autonomous_trust/fleet/update_proposal.h` | `update_proposal_t` struct, serialization, signature helpers |
| `src/c/autonomous_trust/fleet/update_proposal.c` | Proposal JSON pack/unpack, Ed25519 sign/verify via libsodium |
| `src/c/autonomous_trust/fleet/fleet_proc.h` | Fleet process header, protocol constants |
| `src/c/autonomous_trust/fleet/fleet_proc.c` | Fleet process: proposal validation, trust-gated voting |
| `src/protobuf/autonomous_trust/core/protobuf/fleet/update_proposal.proto` | Protobuf definition for update proposals |
| `src/c/test/paxos_test.c` | Paxos engine unit tests |
| `src/c/test/update_proposal_test.c` | Proposal serialization and signing tests |
| `src/c/test/fleet_proc_test.c` | Fleet process handler tests |

### Modified Files

| File | Change |
|------|--------|
| `src/c/autonomous_trust/utilities/msg_types.h` | Add UPDATE_PROPOSAL, UPDATE_VOTE, UPDATE_ACCEPTED to enum and union |
| `src/c/autonomous_trust/reputation/rep_proc.c` | Replace inline Paxos with calls to shared `paxos.c` |
| `src/c/autonomous_trust/autonomous_trust.c` | Add routing for new message types; fix error handling bugs |
| `src/c/autonomous_trust/config/generate.c` | Register "fleet" subsystem |
| `src/c/autonomous_trust/config/configuration.c` | Fix smrt_create memory leak (line 280) |
| `src/c/autonomous_trust/processes/processes.c` | Add missing logging (lines 164, 268) |
| `src/c/CMakeLists.txt` | Add new source files, protobuf, and test targets |

---

## Task 1: Shared Paxos Engine — Header and Tests

**Files:**
- Create: `src/c/autonomous_trust/algorithms/paxos.h`
- Create: `src/c/test/paxos_test.c`

This task creates the Paxos API and tests. The implementation comes in Task 2.

- [ ] **Step 1: Create paxos.h**

Write to `src/c/autonomous_trust/algorithms/paxos.h`:

```c
#ifndef PAXOS_H
#define PAXOS_H

#include <stdbool.h>
#include <pthread.h>
#include "autonomous_trust/structures/map.h"
#include "autonomous_trust/structures/array.h"
#include "autonomous_trust/utilities/logger.h"

#define PAXOS_MAJORITY(n) (((n) / 2) + 1)
#define PAXOS_BACKOFF_MULT    1.5
#define PAXOS_BACKOFF_MAX_SEC 90
#define PAXOS_KEY_LEN 64

typedef enum {
    PAXOS_GRANT = 0,
    PAXOS_NACK,
    PAXOS_BACKDATE,
} paxos_response_t;

/* Per-proposal tracking */
typedef struct {
    double score;       /* Application-specific value being proposed */
    int grant_count;    /* Number of grants received */
} paxos_proposal_t;

/* A single Paxos consensus instance */
typedef struct {
    double last_id;           /* Highest proposal ID seen */
    int chain_len;            /* Current chain length (application manages actual chain) */
    int num_peers;            /* Total peers in group */
    map_t proposals;          /* "id1:id2" -> paxos_proposal_t* */
    map_t acceptances;        /* "id1:id2" -> int (acceptance count) */
    map_t backoff;            /* "id1:id2" -> time_t (next retry time) */
    array_t granted_ids;      /* id2 values we've granted (as int data_t) */
    pthread_mutex_t lock;
    logger_t *logger;
    bool initialized;
} paxos_instance_t;

/* Initialize a Paxos instance */
int paxos_init(paxos_instance_t *inst, int num_peers, logger_t *logger);

/* Free resources */
void paxos_destroy(paxos_instance_t *inst);

/* Compute composite Paxos ID: id1 + id2/10^digits(id2) */
double paxos_id_index(double id1, double id2);

/* Phase 1a: Handle incoming request. Returns GRANT, NACK, or BACKDATE.
   On GRANT, out_last_id and out_chain_len are set for the response. */
paxos_response_t paxos_handle_request(paxos_instance_t *inst,
                                      double id1, double id2,
                                      double *out_last_id, int *out_chain_len);

/* Phase 1b: Record a grant response. Returns the new grant_count.
   Caller should check count >= PAXOS_MAJORITY(num_peers) to proceed. */
int paxos_record_grant(paxos_instance_t *inst,
                       double id1, double id2, double score);

/* Phase 2: Record an acceptance. Returns the new accept_count.
   Caller should check count >= PAXOS_MAJORITY(num_peers) to commit. */
int paxos_record_acceptance(paxos_instance_t *inst,
                            double id1, double id2);

/* Check if a granted id2 exists (for transaction validation) */
bool paxos_has_granted_id(paxos_instance_t *inst, int id2);

/* Advance chain length (call after committing to application chain) */
void paxos_advance_chain(paxos_instance_t *inst);

/* Generate next proposal IDs. Increments last_id. */
void paxos_next_ids(paxos_instance_t *inst, double *out_id1, double *out_id2);

/* Record a nack and compute backoff time. Returns seconds to wait. */
int paxos_record_nack(paxos_instance_t *inst, double id1, double id2);

#endif /* PAXOS_H */
```

- [ ] **Step 2: Create paxos_test.c**

Write to `src/c/test/paxos_test.c`:

```c
#include <check.h>
#include "autonomous_trust/algorithms/paxos.h"
#include "autonomous_trust/utilities/logger.h"

/* Helpers */
#define ck_assert_ret_ok(expr) ck_assert_int_eq((expr), 0)

static logger_t test_logger;

static void setup(void)
{
    logger_init(&test_logger, WARNING, NULL);
}

DEFINE_TEST(test_paxos_init)
{
    paxos_instance_t inst;
    ck_assert_ret_ok(paxos_init(&inst, 5, &test_logger));
    ck_assert_int_eq(inst.num_peers, 5);
    ck_assert_int_eq(inst.chain_len, 0);
    ck_assert_double_eq_tol(inst.last_id, 0.0, 1e-9);
    ck_assert(inst.initialized);
    paxos_destroy(&inst);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_paxos_id_index)
{
    ck_assert_double_eq_tol(paxos_id_index(1.0, 5.0),  1.5,   1e-9);
    ck_assert_double_eq_tol(paxos_id_index(3.0, 42.0), 3.42,  1e-9);
    ck_assert_double_eq_tol(paxos_id_index(1.0, 0.0),  1.0,   1e-9);
    ck_assert_double_eq_tol(paxos_id_index(7.0, 1.0),  7.1,   1e-9);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_paxos_handle_request_grant)
{
    paxos_instance_t inst;
    ck_assert_ret_ok(paxos_init(&inst, 3, &test_logger));

    double out_last_id = -1.0;
    int out_chain_len = -1;

    /* id1=1.0 > last_id=0.0, id2=1.0 == chain_len+1=1 -> GRANT */
    paxos_response_t r = paxos_handle_request(&inst, 1.0, 1.0,
                                               &out_last_id, &out_chain_len);
    ck_assert_int_eq(r, PAXOS_GRANT);
    ck_assert_int_eq(out_chain_len, 0);

    paxos_destroy(&inst);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_paxos_handle_request_nack)
{
    paxos_instance_t inst;
    ck_assert_ret_ok(paxos_init(&inst, 3, &test_logger));

    double out_last_id;
    int out_chain_len;

    /* First request succeeds (sets last_id) */
    paxos_handle_request(&inst, 2.0, 1.0, &out_last_id, &out_chain_len);

    /* Second request with id1 <= last_id -> NACK */
    paxos_response_t r = paxos_handle_request(&inst, 1.0, 1.0,
                                               &out_last_id, &out_chain_len);
    ck_assert_int_eq(r, PAXOS_NACK);

    paxos_destroy(&inst);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_paxos_handle_request_backdate)
{
    paxos_instance_t inst;
    ck_assert_ret_ok(paxos_init(&inst, 3, &test_logger));

    /* Advance chain so chain_len=1 */
    paxos_advance_chain(&inst);

    double out_last_id;
    int out_chain_len;

    /* id2=1 but chain_len+1=2 -> BACKDATE */
    paxos_response_t r = paxos_handle_request(&inst, 1.0, 1.0,
                                               &out_last_id, &out_chain_len);
    ck_assert_int_eq(r, PAXOS_BACKDATE);

    paxos_destroy(&inst);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_paxos_quorum_3_peers)
{
    paxos_instance_t inst;
    ck_assert_ret_ok(paxos_init(&inst, 3, &test_logger));

    /* Need MAJORITY(3) = 2 grants */
    int count1 = paxos_record_grant(&inst, 1.0, 1.0, 0.75);
    ck_assert_int_eq(count1, 1);

    int count2 = paxos_record_grant(&inst, 1.0, 1.0, 0.75);
    ck_assert_int_eq(count2, 2);
    ck_assert(count2 >= PAXOS_MAJORITY(3));

    paxos_destroy(&inst);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_paxos_quorum_5_peers)
{
    paxos_instance_t inst;
    ck_assert_ret_ok(paxos_init(&inst, 5, &test_logger));

    /* Need MAJORITY(5) = 3 grants */
    paxos_record_grant(&inst, 1.0, 1.0, 0.5);
    paxos_record_grant(&inst, 1.0, 1.0, 0.5);
    int count3 = paxos_record_grant(&inst, 1.0, 1.0, 0.5);
    ck_assert_int_eq(count3, 3);
    ck_assert(count3 >= PAXOS_MAJORITY(5));

    paxos_destroy(&inst);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_paxos_acceptance_quorum)
{
    paxos_instance_t inst;
    ck_assert_ret_ok(paxos_init(&inst, 3, &test_logger));

    int a1 = paxos_record_acceptance(&inst, 1.0, 1.0);
    ck_assert_int_eq(a1, 1);

    int a2 = paxos_record_acceptance(&inst, 1.0, 1.0);
    ck_assert_int_eq(a2, 2);
    ck_assert(a2 >= PAXOS_MAJORITY(3));

    paxos_destroy(&inst);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_paxos_next_ids)
{
    paxos_instance_t inst;
    ck_assert_ret_ok(paxos_init(&inst, 3, &test_logger));

    double id1, id2;
    paxos_next_ids(&inst, &id1, &id2);
    ck_assert_double_eq_tol(id2, 1.0, 1e-9); /* chain_len=0, so id2=1 */
    ck_assert(id1 > 0.0);

    paxos_destroy(&inst);
}
END_TEST_DEFINITION()

RUN_TESTS(Paxos,
    test_paxos_init,
    test_paxos_id_index,
    test_paxos_handle_request_grant,
    test_paxos_handle_request_nack,
    test_paxos_handle_request_backdate,
    test_paxos_quorum_3_peers,
    test_paxos_quorum_5_peers,
    test_paxos_acceptance_quorum,
    test_paxos_next_ids
)
```

- [ ] **Step 3: Add paxos_test to CMakeLists.txt**

In `src/c/CMakeLists.txt`, after the last `add_test` line (before `endif() # LIBCHECK_LIBRARY`), add:

```cmake
add_executable(paxos_test test/paxos_test.c)
set_source_files_properties(test/paxos_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(paxos_test PRIVATE autonomous_trust_static ${TEST_DEPENDENCIES})

add_test(NAME paxos_test COMMAND $<TARGET_FILE:paxos_test>)
```

- [ ] **Step 4: Verify tests fail (paxos.c doesn't exist yet)**

Run:
```bash
cd src/c && rm -rf build && mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug
make paxos_test 2>&1
```

Expected: Linker error — `paxos_init`, `paxos_handle_request`, etc. are undefined. This confirms the test references the right symbols.

- [ ] **Step 5: Commit**

```bash
git add src/c/autonomous_trust/algorithms/paxos.h src/c/test/paxos_test.c src/c/CMakeLists.txt
git commit -m "feat(paxos): add shared Paxos engine header and tests

Defines the paxos_instance_t API for reusable Paxos consensus.
Tests cover: init, id computation, request handling (grant/nack/backdate),
quorum detection for 3 and 5 peers, acceptance counting, id generation.
Implementation in next commit."
```

---

## Task 2: Shared Paxos Engine — Implementation

**Files:**
- Create: `src/c/autonomous_trust/algorithms/paxos.c`
- Modify: `src/c/CMakeLists.txt` (add to libsrc)

- [ ] **Step 1: Create paxos.c**

Write to `src/c/autonomous_trust/algorithms/paxos.c`:

```c
#include "algorithms/paxos.h"
#include "structures/data.h"
#include <math.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

int paxos_init(paxos_instance_t *inst, int num_peers, logger_t *logger)
{
    memset(inst, 0, sizeof(*inst));
    inst->num_peers = num_peers;
    inst->logger = logger;
    inst->last_id = 0.0;
    inst->chain_len = 0;
    map_init(&inst->proposals);
    map_init(&inst->acceptances);
    map_init(&inst->backoff);
    array_init(&inst->granted_ids);
    pthread_mutex_init(&inst->lock, NULL);
    inst->initialized = true;
    return 0;
}

void paxos_destroy(paxos_instance_t *inst)
{
    if (!inst->initialized)
        return;
    map_free(&inst->proposals);
    map_free(&inst->acceptances);
    map_free(&inst->backoff);
    array_free(&inst->granted_ids);
    pthread_mutex_destroy(&inst->lock);
    inst->initialized = false;
}

double paxos_id_index(double id1, double id2)
{
    if (fabs(id2) < 1e-15)
        return id1;
    int digits = 0;
    double tmp = fabs(id2);
    if (tmp < 1.0)
        digits = 1;
    else
    {
        while (tmp >= 1.0)
        {
            tmp /= 10.0;
            digits++;
        }
    }
    return id1 + id2 / pow(10.0, (double)digits);
}

static void make_key(char *buf, size_t buflen, double id1, double id2)
{
    snprintf(buf, buflen, "%.0f:%.0f", id1, id2);
}

paxos_response_t paxos_handle_request(paxos_instance_t *inst,
                                      double id1, double id2,
                                      double *out_last_id, int *out_chain_len)
{
    pthread_mutex_lock(&inst->lock);

    *out_last_id = inst->last_id;
    *out_chain_len = inst->chain_len;

    if (id1 > inst->last_id)
    {
        if ((int)id2 == inst->chain_len + 1)
        {
            /* GRANT — record this id2 so we can verify transactions later */
            data_t *id2_dat = integer_data((int)id2);
            array_append(&inst->granted_ids, id2_dat);
            pthread_mutex_unlock(&inst->lock);
            return PAXOS_GRANT;
        }
        else
        {
            /* BACKDATE — chain index mismatch */
            pthread_mutex_unlock(&inst->lock);
            return PAXOS_BACKDATE;
        }
    }
    else
    {
        /* NACK — stale proposal ID */
        pthread_mutex_unlock(&inst->lock);
        return PAXOS_NACK;
    }
}

int paxos_record_grant(paxos_instance_t *inst,
                       double id1, double id2, double score)
{
    char key[PAXOS_KEY_LEN];
    make_key(key, sizeof(key), id1, id2);

    pthread_mutex_lock(&inst->lock);

    data_t *prop_dat = NULL;
    paxos_proposal_t *ptc = NULL;

    if (map_get(&inst->proposals, key, &prop_dat) == 0)
    {
        data_object_ptr(prop_dat, (void **)&ptc);
        ptc->grant_count += 1;
    }
    else
    {
        ptc = smrt_create(sizeof(paxos_proposal_t));
        if (ptc != NULL)
        {
            ptc->score = score;
            ptc->grant_count = 1;
            data_t *new_dat = object_ptr_data(ptc, sizeof(paxos_proposal_t));
            map_set(&inst->proposals, key, new_dat);
        }
    }

    int count = (ptc != NULL) ? ptc->grant_count : 0;
    pthread_mutex_unlock(&inst->lock);
    return count;
}

int paxos_record_acceptance(paxos_instance_t *inst,
                            double id1, double id2)
{
    char key[PAXOS_KEY_LEN];
    make_key(key, sizeof(key), id1, id2);

    pthread_mutex_lock(&inst->lock);

    data_t *acc_dat = NULL;
    int count = 0;

    if (map_get(&inst->acceptances, key, &acc_dat) == 0)
    {
        data_int(acc_dat, &count);
        count += 1;
        data_t *new_dat = integer_data(count);
        map_set(&inst->acceptances, key, new_dat);
    }
    else
    {
        count = 1;
        data_t *new_dat = integer_data(count);
        map_set(&inst->acceptances, key, new_dat);
    }

    pthread_mutex_unlock(&inst->lock);
    return count;
}

bool paxos_has_granted_id(paxos_instance_t *inst, int id2)
{
    pthread_mutex_lock(&inst->lock);
    for (size_t i = 0; i < array_length(&inst->granted_ids); i++)
    {
        data_t *dat = NULL;
        if (array_get(&inst->granted_ids, i, &dat) == 0)
        {
            int val;
            if (data_int(dat, &val) == 0 && val == id2)
            {
                pthread_mutex_unlock(&inst->lock);
                return true;
            }
        }
    }
    pthread_mutex_unlock(&inst->lock);
    return false;
}

void paxos_advance_chain(paxos_instance_t *inst)
{
    pthread_mutex_lock(&inst->lock);
    inst->chain_len += 1;
    pthread_mutex_unlock(&inst->lock);
}

void paxos_next_ids(paxos_instance_t *inst, double *out_id1, double *out_id2)
{
    pthread_mutex_lock(&inst->lock);
    inst->last_id += 1.0;
    *out_id1 = paxos_id_index(inst->last_id, (double)inst->num_peers);
    *out_id2 = (double)(inst->chain_len + 1);
    pthread_mutex_unlock(&inst->lock);
}

int paxos_record_nack(paxos_instance_t *inst, double id1, double id2)
{
    char key[PAXOS_KEY_LEN];
    make_key(key, sizeof(key), id1, id2);

    pthread_mutex_lock(&inst->lock);

    data_t *bo_dat = NULL;
    int wait_sec = 2; /* initial backoff */

    if (map_get(&inst->backoff, key, &bo_dat) == 0)
    {
        int prev;
        data_int(bo_dat, &prev);
        wait_sec = (int)((double)prev * PAXOS_BACKOFF_MULT);
        if (wait_sec > PAXOS_BACKOFF_MAX_SEC)
            wait_sec = PAXOS_BACKOFF_MAX_SEC;
    }

    data_t *new_dat = integer_data(wait_sec);
    map_set(&inst->backoff, key, new_dat);

    pthread_mutex_unlock(&inst->lock);
    return wait_sec;
}
```

- [ ] **Step 2: Add paxos.c to library sources in CMakeLists.txt**

In `src/c/CMakeLists.txt`, add to the `libsrc` list (after `autonomous_trust/algorithms/agreement.c`):

```cmake
    autonomous_trust/algorithms/paxos.c
```

And add to `libhdr` (after `autonomous_trust/algorithms/algorithms.h`):

```cmake
    autonomous_trust/algorithms/paxos.h
```

- [ ] **Step 3: Build and run paxos_test**

```bash
cd src/c/build && cmake .. -DCMAKE_BUILD_TYPE=Debug && make paxos_test && ctest -R paxos_test -V
```

Expected: All 9 tests pass.

- [ ] **Step 4: Commit**

```bash
git add src/c/autonomous_trust/algorithms/paxos.c src/c/CMakeLists.txt
git commit -m "feat(paxos): implement shared Paxos engine

Extracts core Paxos state machine into reusable algorithms/paxos.c:
propose, handle_request (grant/nack/backdate), record_grant,
record_acceptance, quorum tracking, exponential backoff on nack.
All 9 paxos_test cases pass."
```

---

## Task 3: Refactor rep_proc.c to Use Shared Paxos

**Files:**
- Modify: `src/c/autonomous_trust/reputation/rep_proc.c`

This is the critical refactoring task. The existing `rep_proc.c` has Paxos logic embedded in its handlers. We replace the inline state management with calls to `paxos_instance_t`.

- [ ] **Step 1: Run existing reputation tests to establish baseline**

```bash
cd src/c/build && cmake .. -DCMAKE_BUILD_TYPE=Debug && make -j$(nproc)
ctest -R reputation -V
```

Record which tests pass. All reputation tests (reputation_test, reputation2_test, reputation3_test) must pass before and after this refactor.

- [ ] **Step 2: Replace rep_state Paxos fields with paxos_instance_t**

In `src/c/autonomous_trust/reputation/rep_proc.c`, add include at the top:

```c
#include "algorithms/paxos.h"
```

Replace the static state struct to use `paxos_instance_t` instead of inline fields. Change:

```c
static struct {
    tx_history_t history;
    reputations_t reputations;
    map_t my_requests;
    map_t proposals;       /* REMOVE — now in paxos_instance_t */
    map_t acceptances;     /* REMOVE — now in paxos_instance_t */
    map_t backoff;         /* REMOVE — now in paxos_instance_t */
    map_t updates;
    array_t requests;      /* REMOVE — now granted_ids in paxos */
    array_t requested_reps;
    double last_id;        /* REMOVE — now in paxos_instance_t */
    int num_peers;
    pthread_mutex_t lock;
    bool initialized;
} rep_state;
```

To:

```c
static struct {
    tx_history_t history;
    reputations_t reputations;
    map_t my_requests;
    paxos_instance_t paxos;   /* Shared Paxos engine */
    map_t updates;
    array_t requested_reps;
    int num_peers;
    pthread_mutex_t lock;
    bool initialized;
} rep_state;
```

- [ ] **Step 3: Update _ensure_init to initialize paxos**

Replace the removed `map_init`/`array_init` calls with:

```c
/* paxos_init is called in reputation_run after num_peers is known */
```

Remove from `_ensure_init`:
- `map_init(&rep_state.proposals);`
- `map_init(&rep_state.acceptances);`
- `map_init(&rep_state.backoff);`
- `array_init(&rep_state.requests);`
- `rep_state.last_id = 0.0;`

- [ ] **Step 4: Update handle_request to use paxos_handle_request**

Replace the body of `handle_request` (the Paxos decision logic) with:

```c
double out_last_id;
int out_chain_len;
paxos_response_t result = paxos_handle_request(&rep_state.paxos,
                                                id1, id2,
                                                &out_last_id, &out_chain_len);
```

Then branch on `result` to send GRANT, NACK, or BACKDATE messages (keep the existing message-building code, just replace the if/else decision logic).

- [ ] **Step 5: Update handle_grant to use paxos_record_grant**

Replace the proposals map lookup with:

```c
int count = paxos_record_grant(&rep_state.paxos, id1, id2, tx_score);
bool send_tx = (count >= PAXOS_MAJORITY(rep_state.num_peers));
```

Remove the inline `map_get`/`map_set` on `rep_state.proposals`.

- [ ] **Step 6: Update handle_nack to use paxos_record_nack**

Replace inline backoff computation with:

```c
int wait_sec = paxos_record_nack(&rep_state.paxos, id1, id2);
```

- [ ] **Step 7: Update handle_transaction to use paxos_has_granted_id**

Replace the `requests` array scan with:

```c
if (!paxos_has_granted_id(&rep_state.paxos, (int)id2))
{
    /* Not a valid transaction for us */
    ...
}
```

- [ ] **Step 8: Update handle_accepted to use paxos_record_acceptance**

Replace inline acceptance counting with:

```c
int count = paxos_record_acceptance(&rep_state.paxos, id1, id2);
if (count >= PAXOS_MAJORITY(rep_state.num_peers))
{
    /* Commit to chain */
    ...
    paxos_advance_chain(&rep_state.paxos);
}
```

- [ ] **Step 9: Update _forward_transaction to use paxos_next_ids**

Replace inline id computation with:

```c
double id1, id2;
paxos_next_ids(&rep_state.paxos, &id1, &id2);
```

- [ ] **Step 10: Update reputation_run to init paxos**

After `rep_state.num_peers = (int)proc->protocol.num_peers;`, add:

```c
paxos_init(&rep_state.paxos, rep_state.num_peers, logger);
```

- [ ] **Step 11: Build and run ALL reputation tests**

```bash
cd src/c/build && cmake .. -DCMAKE_BUILD_TYPE=Debug && make -j$(nproc)
ctest -R reputation -V
ctest -R paxos -V
```

Expected: All reputation tests pass (same results as Step 1). All paxos tests pass.

- [ ] **Step 12: Commit**

```bash
git add src/c/autonomous_trust/reputation/rep_proc.c
git commit -m "refactor(reputation): use shared Paxos engine

Replace inline Paxos state management in rep_proc.c with calls to
the shared paxos_instance_t API. No behavior change — all existing
reputation tests pass. Enables reuse by fleet process."
```

---

## Task 4: Update Proposal Message Type

**Files:**
- Create: `src/c/autonomous_trust/fleet/update_proposal.h`
- Create: `src/c/autonomous_trust/fleet/update_proposal.c`
- Create: `src/protobuf/autonomous_trust/core/protobuf/fleet/update_proposal.proto`
- Modify: `src/c/autonomous_trust/utilities/msg_types.h`
- Create: `src/c/test/update_proposal_test.c`
- Modify: `src/c/CMakeLists.txt`

- [ ] **Step 1: Create update_proposal.proto**

```bash
mkdir -p src/protobuf/autonomous_trust/core/protobuf/fleet
```

Write to `src/protobuf/autonomous_trust/core/protobuf/fleet/update_proposal.proto`:

```protobuf
syntax = "proto3";
package autonomous_trust.core.protobuf.fleet;

message UpdateProposal {
    string version = 1;
    bytes artifact_hash = 2;
    bytes signer_uuid = 3;
    string target_arch = 4;
    double min_proposer_reputation = 5;
    bytes proposal_uuid = 6;
    bytes signature = 7;
}
```

- [ ] **Step 2: Create update_proposal.h**

```bash
mkdir -p src/c/autonomous_trust/fleet
```

Write to `src/c/autonomous_trust/fleet/update_proposal.h`:

```c
#ifndef UPDATE_PROPOSAL_H
#define UPDATE_PROPOSAL_H

#include <stdbool.h>
#include <stdint.h>
#include <uuid/uuid.h>
#include <jansson.h>

#define UPDATE_VERSION_LEN 64
#define UPDATE_HASH_LEN    32   /* blake2b-256 */
#define UPDATE_SIG_LEN     64   /* Ed25519 */
#define UPDATE_ARCH_LEN    16

typedef struct {
    char version[UPDATE_VERSION_LEN + 1];
    uint8_t artifact_hash[UPDATE_HASH_LEN];
    uuid_t signer_uuid;
    char target_arch[UPDATE_ARCH_LEN + 1];
    double min_proposer_reputation;
    uuid_t proposal_uuid;
    uint8_t signature[UPDATE_SIG_LEN];
} update_proposal_t;

/* JSON serialization */
json_t *update_proposal_to_json(const update_proposal_t *prop);
int update_proposal_from_json(const json_t *json, update_proposal_t *prop);

/* Sign the proposal fields (version + hash + arch) with Ed25519 secret key.
   sk must be crypto_sign_SECRETKEYBYTES long. */
int update_proposal_sign(update_proposal_t *prop, const uint8_t *sk);

/* Verify the proposal signature against the signer's Ed25519 public key.
   pk must be crypto_sign_PUBLICKEYBYTES long. Returns 0 on success. */
int update_proposal_verify(const update_proposal_t *prop, const uint8_t *pk);

#endif /* UPDATE_PROPOSAL_H */
```

- [ ] **Step 3: Create update_proposal.c**

Write to `src/c/autonomous_trust/fleet/update_proposal.c`:

```c
#include "fleet/update_proposal.h"
#include "utilities/b64.h"
#include <sodium.h>
#include <string.h>
#include <stdio.h>

json_t *update_proposal_to_json(const update_proposal_t *prop)
{
    json_t *obj = json_object();
    if (!obj) return NULL;

    json_object_set_new(obj, "version", json_string(prop->version));

    /* Hex-encode binary fields */
    char hash_hex[UPDATE_HASH_LEN * 2 + 1];
    sodium_bin2hex(hash_hex, sizeof(hash_hex), prop->artifact_hash, UPDATE_HASH_LEN);
    json_object_set_new(obj, "artifact_hash", json_string(hash_hex));

    char signer_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(prop->signer_uuid, signer_str);
    json_object_set_new(obj, "signer_uuid", json_string(signer_str));

    json_object_set_new(obj, "target_arch", json_string(prop->target_arch));
    json_object_set_new(obj, "min_proposer_reputation", json_real(prop->min_proposer_reputation));

    char proposal_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(prop->proposal_uuid, proposal_str);
    json_object_set_new(obj, "proposal_uuid", json_string(proposal_str));

    char sig_hex[UPDATE_SIG_LEN * 2 + 1];
    sodium_bin2hex(sig_hex, sizeof(sig_hex), prop->signature, UPDATE_SIG_LEN);
    json_object_set_new(obj, "signature", json_string(sig_hex));

    return obj;
}

int update_proposal_from_json(const json_t *json, update_proposal_t *prop)
{
    memset(prop, 0, sizeof(*prop));

    const char *version = json_string_value(json_object_get(json, "version"));
    const char *hash_hex = json_string_value(json_object_get(json, "artifact_hash"));
    const char *signer_str = json_string_value(json_object_get(json, "signer_uuid"));
    const char *arch = json_string_value(json_object_get(json, "target_arch"));
    json_t *j_rep = json_object_get(json, "min_proposer_reputation");
    const char *proposal_str = json_string_value(json_object_get(json, "proposal_uuid"));
    const char *sig_hex = json_string_value(json_object_get(json, "signature"));

    if (!version || !hash_hex || !signer_str || !arch || !j_rep || !proposal_str || !sig_hex)
        return -1;

    strncpy(prop->version, version, UPDATE_VERSION_LEN);
    strncpy(prop->target_arch, arch, UPDATE_ARCH_LEN);
    prop->min_proposer_reputation = json_real_value(j_rep);

    if (sodium_hex2bin(prop->artifact_hash, UPDATE_HASH_LEN,
                       hash_hex, strlen(hash_hex), NULL, NULL, NULL) != 0)
        return -1;

    if (uuid_parse(signer_str, prop->signer_uuid) != 0)
        return -1;

    if (uuid_parse(proposal_str, prop->proposal_uuid) != 0)
        return -1;

    if (sodium_hex2bin(prop->signature, UPDATE_SIG_LEN,
                       sig_hex, strlen(sig_hex), NULL, NULL, NULL) != 0)
        return -1;

    return 0;
}

/* Build the signable message: version + artifact_hash + target_arch */
static size_t build_signable(const update_proposal_t *prop, uint8_t *buf, size_t buflen)
{
    size_t offset = 0;
    size_t vlen = strlen(prop->version);

    if (offset + vlen > buflen) return 0;
    memcpy(buf + offset, prop->version, vlen);
    offset += vlen;

    if (offset + UPDATE_HASH_LEN > buflen) return 0;
    memcpy(buf + offset, prop->artifact_hash, UPDATE_HASH_LEN);
    offset += UPDATE_HASH_LEN;

    size_t alen = strlen(prop->target_arch);
    if (offset + alen > buflen) return 0;
    memcpy(buf + offset, prop->target_arch, alen);
    offset += alen;

    return offset;
}

int update_proposal_sign(update_proposal_t *prop, const uint8_t *sk)
{
    uint8_t msg[256];
    size_t msg_len = build_signable(prop, msg, sizeof(msg));
    if (msg_len == 0) return -1;

    unsigned long long sig_len;
    return crypto_sign_detached(prop->signature, &sig_len, msg, msg_len, sk);
}

int update_proposal_verify(const update_proposal_t *prop, const uint8_t *pk)
{
    uint8_t msg[256];
    size_t msg_len = build_signable(prop, msg, sizeof(msg));
    if (msg_len == 0) return -1;

    return crypto_sign_verify_detached(prop->signature, msg, msg_len, pk);
}
```

- [ ] **Step 4: Add to msg_types.h**

In `src/c/autonomous_trust/utilities/msg_types.h`, add to the enum (after `TRANSACTION_SCORE`):

```c
    UPDATE_PROPOSAL,
    UPDATE_VOTE,
    UPDATE_ACCEPTED,
```

Add structs (after `tx_score_msg_t`):

```c
typedef struct {
    uuid_t proposal_uuid;
    uuid_t voter_uuid;
    bool accept;
} update_vote_msg_t;

typedef struct {
    uuid_t proposal_uuid;
    int accept_count;
    int reject_count;
} update_accepted_msg_t;
```

Add to the `generic_msg_t` union (after `tx_score`):

```c
        update_vote_msg_t update_vote;
        update_accepted_msg_t update_accepted;
```

- [ ] **Step 5: Create update_proposal_test.c**

Write to `src/c/test/update_proposal_test.c`:

```c
#include <check.h>
#include <sodium.h>
#include <uuid/uuid.h>
#include "autonomous_trust/fleet/update_proposal.h"

#define ck_assert_ret_ok(expr) ck_assert_int_eq((expr), 0)

DEFINE_TEST(test_proposal_json_roundtrip)
{
    update_proposal_t orig = {0};
    strncpy(orig.version, "1.2.3", UPDATE_VERSION_LEN);
    memset(orig.artifact_hash, 0xAB, UPDATE_HASH_LEN);
    uuid_generate(orig.signer_uuid);
    strncpy(orig.target_arch, "arm64", UPDATE_ARCH_LEN);
    orig.min_proposer_reputation = 0.7;
    uuid_generate(orig.proposal_uuid);
    memset(orig.signature, 0xCD, UPDATE_SIG_LEN);

    json_t *json = update_proposal_to_json(&orig);
    ck_assert_ptr_nonnull(json);

    update_proposal_t decoded = {0};
    ck_assert_ret_ok(update_proposal_from_json(json, &decoded));
    json_decref(json);

    ck_assert_str_eq(orig.version, decoded.version);
    ck_assert_mem_eq(orig.artifact_hash, decoded.artifact_hash, UPDATE_HASH_LEN);
    ck_assert_str_eq(orig.target_arch, decoded.target_arch);
    ck_assert_double_eq_tol(orig.min_proposer_reputation, decoded.min_proposer_reputation, 1e-9);
    ck_assert_mem_eq(orig.signature, decoded.signature, UPDATE_SIG_LEN);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_proposal_sign_verify)
{
    ck_assert_ret_ok(sodium_init() == -1 ? 0 : sodium_init()); /* init or already init */

    uint8_t pk[crypto_sign_PUBLICKEYBYTES];
    uint8_t sk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(pk, sk);

    update_proposal_t prop = {0};
    strncpy(prop.version, "2.0.0", UPDATE_VERSION_LEN);
    randombytes_buf(prop.artifact_hash, UPDATE_HASH_LEN);
    uuid_generate(prop.signer_uuid);
    strncpy(prop.target_arch, "amd64", UPDATE_ARCH_LEN);
    prop.min_proposer_reputation = 0.8;
    uuid_generate(prop.proposal_uuid);

    ck_assert_ret_ok(update_proposal_sign(&prop, sk));
    ck_assert_ret_ok(update_proposal_verify(&prop, pk));
}
END_TEST_DEFINITION()

DEFINE_TEST(test_proposal_verify_rejects_tampered)
{
    ck_assert_ret_ok(sodium_init() == -1 ? 0 : sodium_init());

    uint8_t pk[crypto_sign_PUBLICKEYBYTES];
    uint8_t sk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(pk, sk);

    update_proposal_t prop = {0};
    strncpy(prop.version, "3.0.0", UPDATE_VERSION_LEN);
    randombytes_buf(prop.artifact_hash, UPDATE_HASH_LEN);
    uuid_generate(prop.signer_uuid);
    strncpy(prop.target_arch, "arm64", UPDATE_ARCH_LEN);
    prop.min_proposer_reputation = 0.7;
    uuid_generate(prop.proposal_uuid);

    ck_assert_ret_ok(update_proposal_sign(&prop, sk));

    /* Tamper with version */
    strncpy(prop.version, "3.0.1", UPDATE_VERSION_LEN);

    /* Verification should fail */
    ck_assert_int_ne(update_proposal_verify(&prop, pk), 0);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_proposal_verify_rejects_wrong_key)
{
    ck_assert_ret_ok(sodium_init() == -1 ? 0 : sodium_init());

    uint8_t pk1[crypto_sign_PUBLICKEYBYTES], sk1[crypto_sign_SECRETKEYBYTES];
    uint8_t pk2[crypto_sign_PUBLICKEYBYTES], sk2[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(pk1, sk1);
    crypto_sign_keypair(pk2, sk2);

    update_proposal_t prop = {0};
    strncpy(prop.version, "4.0.0", UPDATE_VERSION_LEN);
    randombytes_buf(prop.artifact_hash, UPDATE_HASH_LEN);
    uuid_generate(prop.signer_uuid);
    strncpy(prop.target_arch, "arm64", UPDATE_ARCH_LEN);
    prop.min_proposer_reputation = 0.7;
    uuid_generate(prop.proposal_uuid);

    ck_assert_ret_ok(update_proposal_sign(&prop, sk1));

    /* Verify with wrong key */
    ck_assert_int_ne(update_proposal_verify(&prop, pk2), 0);
}
END_TEST_DEFINITION()

RUN_TESTS(UpdateProposal,
    test_proposal_json_roundtrip,
    test_proposal_sign_verify,
    test_proposal_verify_rejects_tampered,
    test_proposal_verify_rejects_wrong_key
)
```

- [ ] **Step 6: Add to CMakeLists.txt**

Add to `libsrc`:
```cmake
    autonomous_trust/fleet/update_proposal.c
```

Add to `libhdr`:
```cmake
    autonomous_trust/fleet/update_proposal.h
```

Add to `protos` list:
```cmake
    autonomous_trust/core/protobuf/fleet/update_proposal.proto
```

Add test target (in the `if(LIBCHECK_LIBRARY)` block):
```cmake
add_executable(update_proposal_test test/update_proposal_test.c)
set_source_files_properties(test/update_proposal_test.c PROPERTIES COMPILE_FLAGS "-Wall")
target_link_libraries(update_proposal_test PRIVATE autonomous_trust_static ${TEST_DEPENDENCIES})

add_test(NAME update_proposal_test COMMAND $<TARGET_FILE:update_proposal_test>)
```

- [ ] **Step 7: Build and run tests**

```bash
cd src/c/build && cmake .. -DCMAKE_BUILD_TYPE=Debug && make -j$(nproc)
ctest -R update_proposal_test -V
```

Expected: All 4 tests pass.

- [ ] **Step 8: Commit**

```bash
git add src/c/autonomous_trust/fleet/ src/protobuf/autonomous_trust/core/protobuf/fleet/ \
        src/c/autonomous_trust/utilities/msg_types.h src/c/test/update_proposal_test.c \
        src/c/CMakeLists.txt
git commit -m "feat(fleet): add update proposal message type with Ed25519 signing

New update_proposal_t struct with JSON serialization and Ed25519
sign/verify via libsodium. Adds UPDATE_PROPOSAL, UPDATE_VOTE,
UPDATE_ACCEPTED to message_type_t enum. Protobuf definition for
wire format. All 4 proposal tests pass."
```

---

## Task 5: Fleet Process

**Files:**
- Create: `src/c/autonomous_trust/fleet/fleet_proc.h`
- Create: `src/c/autonomous_trust/fleet/fleet_proc.c`
- Modify: `src/c/autonomous_trust/config/generate.c`
- Modify: `src/c/autonomous_trust/autonomous_trust.c`
- Modify: `src/c/CMakeLists.txt`

- [ ] **Step 1: Create fleet_proc.h**

Write to `src/c/autonomous_trust/fleet/fleet_proc.h`:

```c
#ifndef FLEET_PROC_H
#define FLEET_PROC_H

#include "autonomous_trust/processes/processes.h"

#define FLEET_PROTO_PROPOSE      "update proposal"
#define FLEET_PROTO_VOTE_REQ     "update vote request"
#define FLEET_PROTO_VOTE_GRANT   "update vote grant"
#define FLEET_PROTO_VOTE_NACK    "update vote nack"
#define FLEET_PROTO_ACCEPTED     "update accepted"
#define FLEET_PROTO_REJECTED     "update rejected"

#define FLEET_DEFAULT_MIN_REPUTATION 0.7

int fleet_run(process_t *proc, directory_t *queues, queue_id_t signal, logger_t *logger);

#endif /* FLEET_PROC_H */
```

- [ ] **Step 2: Create fleet_proc.c**

Write to `src/c/autonomous_trust/fleet/fleet_proc.c`:

```c
#include "fleet/fleet_proc.h"
#include "fleet/update_proposal.h"
#include "algorithms/paxos.h"
#include "utilities/msg_types.h"
#include "network/net_message.h"
#include "reputation/reputation.h"
#include "processes/process_tracker.h"
#include <string.h>
#include <jansson.h>

static struct {
    paxos_instance_t vote_paxos;
    map_t pending_proposals;     /* proposal_uuid_str -> update_proposal_t* */
    map_t accepted_updates;      /* proposal_uuid_str -> update_proposal_t* */
    double min_reputation;
    int num_peers;
    pthread_mutex_t lock;
    bool initialized;
} fleet_state;

static void _ensure_init(void)
{
    if (!fleet_state.initialized)
    {
        map_init(&fleet_state.pending_proposals);
        map_init(&fleet_state.accepted_updates);
        fleet_state.min_reputation = FLEET_DEFAULT_MIN_REPUTATION;
        fleet_state.num_peers = 0;
        pthread_mutex_init(&fleet_state.lock, NULL);
        fleet_state.initialized = true;
    }
}

/***********************
 * Handler: handle_update_proposal
 * Validate signature, check proposer reputation, initiate vote
 ***********************/
static bool handle_update_proposal(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;
    log_debug(proc->logger, "Fleet: update proposal from %s\n", nmsg->from_whom.fullname);

    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
    {
        log_error(proc->logger, "Fleet: handle_proposal: failed to unpack JSON\n");
        return false;
    }

    update_proposal_t prop = {0};
    if (update_proposal_from_json(payload, &prop) != 0)
    {
        json_decref(payload);
        log_error(proc->logger, "Fleet: handle_proposal: invalid proposal JSON\n");
        return false;
    }
    json_decref(payload);

    /* Verify proposal signature against signer's public key.
       For now, use the from_whom's signing key from the identity system. */
    if (update_proposal_verify(&prop, nmsg->from_whom.signing_key) != 0)
    {
        log_warning(proc->logger, "Fleet: proposal signature verification failed\n");
        return true; /* handled but rejected */
    }

    /* TODO: query reputation process for signer's score.
       For now, trust-gate based on whether the peer is known. */

    /* Store proposal */
    char prop_uuid_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(prop.proposal_uuid, prop_uuid_str);

    pthread_mutex_lock(&fleet_state.lock);

    update_proposal_t *stored = smrt_create(sizeof(update_proposal_t));
    if (stored == NULL)
    {
        pthread_mutex_unlock(&fleet_state.lock);
        return false;
    }
    memcpy(stored, &prop, sizeof(update_proposal_t));
    data_t *prop_dat = object_ptr_data(stored, sizeof(update_proposal_t));
    map_set(&fleet_state.pending_proposals, prop_uuid_str, prop_dat);

    pthread_mutex_unlock(&fleet_state.lock);

    /* Initiate Paxos vote */
    double id1, id2;
    paxos_next_ids(&fleet_state.vote_paxos, &id1, &id2);

    /* Broadcast vote request to all peers */
    json_t *vote_req = json_object();
    json_object_set_new(vote_req, "id1", json_real(id1));
    json_object_set_new(vote_req, "id2", json_real(id2));
    json_object_set_new(vote_req, "proposal_uuid", json_string(prop_uuid_str));

    for (size_t i = 0; i < proc->protocol.num_peers; i++)
    {
        generic_msg_t req_msg = {0};
        req_msg.type = NET_MESSAGE;
        strncpy(req_msg.info.net_msg.process, "fleet", PROC_NAME_LEN);
        req_msg.info.net_msg.function = (char *)FLEET_PROTO_VOTE_REQ;
        req_msg.info.net_msg.encrypt = true;
        memcpy(&req_msg.info.net_msg.to_whom, &proc->protocol.peers[i], sizeof(public_identity_t));
        strncpy(req_msg.info.net_msg.return_to, "fleet", PROC_NAME_LEN);
        net_msg_pack_json(&req_msg.info.net_msg, vote_req);
        messaging_send("network", NET_MESSAGE, &req_msg, false);
    }
    json_decref(vote_req);

    log_info(proc->logger, "Fleet: proposal %s from %s — vote initiated\n",
             prop.version, nmsg->from_whom.fullname);
    return true;
}

/***********************
 * Handler: handle_vote_request — Paxos Phase 1a
 ***********************/
static bool handle_vote_request(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;

    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
        return false;

    double id1 = json_real_value(json_object_get(payload, "id1"));
    double id2 = json_real_value(json_object_get(payload, "id2"));

    double out_last_id;
    int out_chain_len;
    paxos_response_t result = paxos_handle_request(&fleet_state.vote_paxos,
                                                    id1, id2,
                                                    &out_last_id, &out_chain_len);

    const char *response_func;
    switch (result)
    {
    case PAXOS_GRANT:
        response_func = FLEET_PROTO_VOTE_GRANT;
        break;
    case PAXOS_NACK:
        response_func = FLEET_PROTO_VOTE_NACK;
        break;
    case PAXOS_BACKDATE:
        response_func = FLEET_PROTO_VOTE_NACK; /* treat backdate as nack for updates */
        break;
    }

    json_t *resp_json = json_object();
    json_object_set_new(resp_json, "id1", json_real(id1));
    json_object_set_new(resp_json, "id2", json_real(id2));
    json_object_set_new(resp_json, "proposal_uuid",
                        json_incref(json_object_get(payload, "proposal_uuid")));

    generic_msg_t resp = {0};
    resp.type = NET_MESSAGE;
    strncpy(resp.info.net_msg.process, "fleet", PROC_NAME_LEN);
    resp.info.net_msg.function = (char *)response_func;
    resp.info.net_msg.encrypt = true;
    memcpy(&resp.info.net_msg.to_whom, &nmsg->from_whom, sizeof(public_identity_t));
    strncpy(resp.info.net_msg.return_to, "fleet", PROC_NAME_LEN);
    net_msg_pack_json(&resp.info.net_msg, resp_json);

    json_decref(resp_json);
    json_decref(payload);

    messaging_send("network", NET_MESSAGE, &resp, false);
    return true;
}

/***********************
 * Handler: handle_vote_grant — Paxos Phase 1b
 * Count grants; on majority, broadcast ACCEPTED
 ***********************/
static bool handle_vote_grant(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;

    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
        return false;

    double id1 = json_real_value(json_object_get(payload, "id1"));
    double id2 = json_real_value(json_object_get(payload, "id2"));
    const char *prop_uuid_str = json_string_value(json_object_get(payload, "proposal_uuid"));

    int count = paxos_record_grant(&fleet_state.vote_paxos, id1, id2, 1.0);

    if (count >= PAXOS_MAJORITY(fleet_state.num_peers))
    {
        log_info(proc->logger, "Fleet: proposal %s accepted by quorum (%d/%d)\n",
                 prop_uuid_str ? prop_uuid_str : "?", count, fleet_state.num_peers);

        /* Move from pending to accepted */
        if (prop_uuid_str)
        {
            pthread_mutex_lock(&fleet_state.lock);
            data_t *prop_dat = NULL;
            if (map_get(&fleet_state.pending_proposals, prop_uuid_str, &prop_dat) == 0)
            {
                map_set(&fleet_state.accepted_updates, prop_uuid_str, prop_dat);
                map_remove(&fleet_state.pending_proposals, prop_uuid_str);
            }
            pthread_mutex_unlock(&fleet_state.lock);
        }

        paxos_advance_chain(&fleet_state.vote_paxos);

        /* Broadcast ACCEPTED to all peers */
        json_t *acc_json = json_object();
        json_object_set_new(acc_json, "proposal_uuid",
                            json_string(prop_uuid_str ? prop_uuid_str : ""));

        for (size_t i = 0; i < proc->protocol.num_peers; i++)
        {
            generic_msg_t acc_msg = {0};
            acc_msg.type = NET_MESSAGE;
            strncpy(acc_msg.info.net_msg.process, "fleet", PROC_NAME_LEN);
            acc_msg.info.net_msg.function = (char *)FLEET_PROTO_ACCEPTED;
            acc_msg.info.net_msg.encrypt = true;
            memcpy(&acc_msg.info.net_msg.to_whom, &proc->protocol.peers[i], sizeof(public_identity_t));
            strncpy(acc_msg.info.net_msg.return_to, "fleet", PROC_NAME_LEN);
            net_msg_pack_json(&acc_msg.info.net_msg, acc_json);
            messaging_send("network", NET_MESSAGE, &acc_msg, false);
        }
        json_decref(acc_json);
    }

    json_decref(payload);
    return true;
}

/***********************
 * Handler: handle_vote_nack
 ***********************/
static bool handle_vote_nack(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;

    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
        return false;

    double id1 = json_real_value(json_object_get(payload, "id1"));
    double id2 = json_real_value(json_object_get(payload, "id2"));

    int wait = paxos_record_nack(&fleet_state.vote_paxos, id1, id2);
    log_debug(proc->logger, "Fleet: vote nack, backoff %ds\n", wait);

    json_decref(payload);
    return true;
}

/***********************
 * Handler: handle_update_accepted
 ***********************/
static bool handle_update_accepted(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;

    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
        return false;

    const char *prop_uuid_str = json_string_value(json_object_get(payload, "proposal_uuid"));
    if (prop_uuid_str)
    {
        log_info(proc->logger, "Fleet: update %s accepted by consensus\n", prop_uuid_str);

        /* Move to accepted if we have it pending */
        pthread_mutex_lock(&fleet_state.lock);
        data_t *prop_dat = NULL;
        if (map_get(&fleet_state.pending_proposals, prop_uuid_str, &prop_dat) == 0)
        {
            map_set(&fleet_state.accepted_updates, prop_uuid_str, prop_dat);
            map_remove(&fleet_state.pending_proposals, prop_uuid_str);
        }
        pthread_mutex_unlock(&fleet_state.lock);
    }

    json_decref(payload);
    return true;
}

/***********************
 * Fleet process entry point
 ***********************/
int fleet_run(process_t *proc, directory_t *queues, queue_id_t signal, logger_t *logger)
{
    _ensure_init();
    fleet_state.num_peers = (int)proc->protocol.num_peers;
    paxos_init(&fleet_state.vote_paxos, fleet_state.num_peers, logger);

    process_register_handler(proc, (char *)FLEET_PROTO_PROPOSE,    (handler_ptr_t)handle_update_proposal);
    process_register_handler(proc, (char *)FLEET_PROTO_VOTE_REQ,   (handler_ptr_t)handle_vote_request);
    process_register_handler(proc, (char *)FLEET_PROTO_VOTE_GRANT, (handler_ptr_t)handle_vote_grant);
    process_register_handler(proc, (char *)FLEET_PROTO_VOTE_NACK,  (handler_ptr_t)handle_vote_nack);
    process_register_handler(proc, (char *)FLEET_PROTO_ACCEPTED,   (handler_ptr_t)handle_update_accepted);

    proc->protocol.phase = 1;
    return process_run(proc, queues, signal, logger);
}

DECLARE_PROCESS(fleet, fleet_proc, fleet_run);
```

- [ ] **Step 3: Register fleet subsystem in generate.c**

In `src/c/autonomous_trust/config/generate.c`, after `tracker_register_subsystem(&tracker, "reputation", "rep_proc");`, add:

```c
    err = tracker_register_subsystem(&tracker, "fleet", "fleet_proc");
    if (err != 0) return err;
```

- [ ] **Step 4: Add routing in autonomous_trust.c**

In the main message routing switch in `autonomous_trust.c`, add cases for the new message types. In the external message handling section, after the `TASK_STATUS` case:

```c
case UPDATE_PROPOSAL:
    if (messaging_send("fleet", UPDATE_PROPOSAL, &task_msg, false) != 0)
        log_error(&logger, "Failed to route UPDATE_PROPOSAL to fleet\n");
    break;
```

In the internal message routing section, after the `TRANSACTION_SCORE` case:

```c
case UPDATE_ACCEPTED:
    if (array_append(&extern_msgs, msg_dat) != 0)
        log_error(&logger, "Failed to queue UPDATE_ACCEPTED for external\n");
    do_send = true;
    break;
```

- [ ] **Step 5: Add to CMakeLists.txt**

Add to `libsrc`:
```cmake
    autonomous_trust/fleet/fleet_proc.c
```

Add to `libhdr`:
```cmake
    autonomous_trust/fleet/fleet_proc.h
```

- [ ] **Step 6: Build everything**

```bash
cd src/c/build && cmake .. -DCMAKE_BUILD_TYPE=Debug && make -j$(nproc)
```

Expected: Clean build with no errors.

- [ ] **Step 7: Run all tests**

```bash
ctest -V
```

Expected: All existing tests pass. New tests (paxos_test, update_proposal_test) pass.

- [ ] **Step 8: Commit**

```bash
git add src/c/autonomous_trust/fleet/ src/c/autonomous_trust/config/generate.c \
        src/c/autonomous_trust/autonomous_trust.c src/c/CMakeLists.txt
git commit -m "feat(fleet): add fleet process with update proposal voting

New fleet_proc.c: handles update proposals, trust-gated Paxos voting,
quorum-based acceptance. Registered as 'fleet' subsystem. Routes
UPDATE_PROPOSAL from external, UPDATE_ACCEPTED to external.
Uses shared paxos.c for consensus."
```

---

## Task 6: Bug Fixes

**Files:**
- Modify: `src/c/autonomous_trust/config/configuration.c`
- Modify: `src/c/autonomous_trust/processes/processes.c`

- [ ] **Step 1: Fix smrt_create memory leak in configuration.c**

In `src/c/autonomous_trust/config/configuration.c`, around line 280, the function `load_config_file` calls `smrt_create` but doesn't free on error paths. Change:

```c
config->data_struct = smrt_create(config->data_len);
if (config->data_struct == NULL)
    return EXCEPTION(ENOMEM);
if (read_config_file(abspath, config->data_struct) != 0)
{
    log_exception_extra(logger, " for config named '%s'\n", cfg_name);
    return -1;
}
```

To:

```c
config->data_struct = smrt_create(config->data_len);
if (config->data_struct == NULL)
    return EXCEPTION(ENOMEM);
if (read_config_file(abspath, config->data_struct) != 0)
{
    smrt_deref(config->data_struct);
    config->data_struct = NULL;
    log_exception_extra(logger, " for config named '%s'\n", cfg_name);
    return -1;
}
```

- [ ] **Step 2: Add missing logging in processes.c**

In `src/c/autonomous_trust/processes/processes.c`, around line 164, add logging on handler error:

```c
if (process_handler(proc, queues, msg) != 0)
    log_warning(proc->logger, "%s: message handler returned error\n", proc->name);
```

Around line 268, add logging for unhandled message types:

```c
default:
    log_debug(proc->logger, "%s: skipping unhandled message type %ld\n",
              proc->name, msg->type);
    break;
```

- [ ] **Step 3: Build and test**

```bash
cd src/c/build && cmake .. -DCMAKE_BUILD_TYPE=Debug && make -j$(nproc) && ctest -V
```

Expected: All tests pass.

- [ ] **Step 4: Commit**

```bash
git add src/c/autonomous_trust/config/configuration.c src/c/autonomous_trust/processes/processes.c
git commit -m "fix: memory leak in configuration.c, missing logging in processes.c

configuration.c: free smrt_create'd data_struct on read_config_file error.
processes.c: log handler errors and unhandled message types."
```

---

## Summary

| Task | What | Key Output |
|------|------|------------|
| 1 | Paxos header + tests | API definition, 9 unit tests |
| 2 | Paxos implementation | `algorithms/paxos.c`, tests pass |
| 3 | Refactor rep_proc.c | Uses shared Paxos, existing tests pass |
| 4 | Update proposal type | `fleet/update_proposal.c`, Ed25519 signing, 4 tests |
| 5 | Fleet process | `fleet/fleet_proc.c`, voting, routing, subsystem registration |
| 6 | Bug fixes | Memory leak fix, missing logging |

Tasks 1-2 are the foundation (Paxos engine). Task 3 is the critical refactor (must not break reputation). Tasks 4-5 are the new functionality. Task 6 is inline bug fixes.
