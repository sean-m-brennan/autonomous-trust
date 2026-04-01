# Phase 5A: Update Proposal + Consensus — Design Spec

## Goal

Enable peers in an AutonomousTrust mesh to propose, verify, and vote on software updates via decentralized Paxos consensus, with no central server. This is the trust backbone for Phase 5 (Decentralized Fleet Management).

## Scope

This sub-project covers:
- Shared Paxos engine (extracted from reputation code)
- Update proposal message type and protobuf definition
- Fleet process with proposal validation and trust-gated voting
- Message routing in the main loop
- Inline bug fixes in C code encountered during implementation

This sub-project does NOT cover:
- Artifact distribution (Phase 5B)
- Binary self-update / rollback mechanics (Phase 5C)
- Configuration distribution (Phase 5D)

## Decomposition Context

Phase 5 (Decentralized Fleet Management) is decomposed into four sub-projects:

| Sub-project | Scope | Dependency |
|-------------|-------|------------|
| **A. Update Proposal + Consensus** (this spec) | Propose, verify, vote on updates | None |
| B. Artifact Distribution | Chunked P2P binary transfer | A |
| C. Self-Update + Health Check | Device-side apply, rollback, health | A, B |
| D. Configuration Distribution | Config files via same mechanism | A, B |

Each gets its own spec, plan, and implementation cycle. Bugs found in the C codebase during implementation are fixed inline rather than deferred.

## Architecture

### Overview

A new `UPDATE_PROPOSAL` message type flows through a dedicated fleet process. Peers propose software updates, which are voted on via a Paxos consensus mechanism extracted from the existing reputation code into a shared `paxos.c` module. Update votes are tracked on a separate chain from reputation scores, so voting on updates does not distort peer trust scores.

### Data Flow

```
Proposer peer                    Receiving peers
     |                                |
     |-- UPDATE_PROPOSAL ------------>|
     |   (version, hash, sig, arch)   |
     |                                |-- verify sig against known identities
     |                                |-- check proposer reputation >= threshold
     |                                |
     |<-- UPDATE_VOTE_REQUEST --------|  (Paxos Phase 1a)
     |-- UPDATE_VOTE_GRANT ---------->|  (Paxos Phase 1b)
     |                                |
     |<-- UPDATE_VOTE (accept/reject)-|  (Paxos Phase 2)
     |                                |
     |   [quorum reached]             |
     |                                |
     |<-- UPDATE_ACCEPTED ----------->|  (broadcast to all)
```

## Components

### 1. Shared Paxos Engine

**Files:**
- `src/c/autonomous_trust/algorithms/paxos.h`
- `src/c/autonomous_trust/algorithms/paxos.c`

**Purpose:** Extract the Paxos state machine from `rep_proc.c` into a reusable module. Both reputation scoring and update voting call this engine.

**Interface:**

```c
// Paxos instance — one per consensus topic (reputation chain, update vote, etc.)
typedef struct {
    double last_id;          // Highest proposal ID seen
    int chain_len;           // Current chain length
    int num_peers;           // Total peers in group
    int quorum;              // Required votes (num_peers / 2 + 1)
    map_t proposals;         // proposal_id -> paxos_proposal_t
    map_t acceptances;       // proposal_id -> acceptance count
    logger_t *logger;
} paxos_instance_t;

// Callbacks for protocol-specific behavior
typedef struct {
    // Called when a proposal is granted (Phase 1b)
    int (*on_grant)(paxos_instance_t *inst, const void *proposal, void *ctx);
    // Called when quorum is reached (Phase 2 complete)
    int (*on_accepted)(paxos_instance_t *inst, const void *proposal, void *ctx);
    // Called on nack (proposal rejected)
    int (*on_nack)(paxos_instance_t *inst, double id, void *ctx);
} paxos_callbacks_t;

int paxos_init(paxos_instance_t *inst, int num_peers, logger_t *logger);
void paxos_destroy(paxos_instance_t *inst);

// Phase 1a: Propose (returns 0 on success, sends REQUEST to peers)
int paxos_propose(paxos_instance_t *inst, double id1, double id2, void *proposal_data);

// Phase 1b: Handle incoming request (returns GRANT, NACK, or BACKDATE)
int paxos_handle_request(paxos_instance_t *inst, double id1, double id2,
                         double *out_last_id, int *out_chain_len);

// Phase 1b: Handle grant response
int paxos_handle_grant(paxos_instance_t *inst, double id1, int grant_count,
                       paxos_callbacks_t *cb, void *ctx);

// Phase 2: Handle acceptance
int paxos_handle_accepted(paxos_instance_t *inst, const char *proposal_id,
                          paxos_callbacks_t *cb, void *ctx);

// Query
bool paxos_has_quorum(paxos_instance_t *inst, const char *proposal_id);
```

**Refactoring approach:** Extract the core state machine logic from `rep_proc.c` handlers (`handle_request`, `handle_grant`, `handle_nack`, `handle_transaction`, `handle_accepted`) into `paxos.c`. Replace the `rep_proc.c` handlers with thin wrappers that call `paxos_*` functions with reputation-specific callbacks. Existing C tests must pass after extraction.

### 2. Update Proposal Message Type

**Files:**
- `src/c/autonomous_trust/fleet/update_proposal.h`
- `src/c/autonomous_trust/fleet/update_proposal.c`
- `src/protobuf/autonomous_trust/core/protobuf/fleet/update_proposal.proto`
- `src/c/autonomous_trust/utilities/msg_types.h` (modified)

**Struct:**

```c
#define UPDATE_VERSION_LEN 64
#define UPDATE_HASH_LEN 32  // blake2b-256

typedef struct {
    char version[UPDATE_VERSION_LEN + 1];   // Semantic version string
    uint8_t artifact_hash[UPDATE_HASH_LEN]; // blake2b-256 of the binary artifact
    uuid_t signer_uuid;                     // Identity of the proposer
    char target_arch[16];                   // "arm64", "amd64"
    double min_proposer_reputation;         // Minimum reputation to propose
    uuid_t proposal_uuid;                   // Unique ID for this proposal
    uint8_t signature[64];                  // Ed25519 signature over (version + hash + arch)
} update_proposal_t;
```

**Protobuf:**

```protobuf
syntax = "proto3";
package autonomous_trust.core.protobuf.fleet;

message UpdateProposal {
    string version = 1;
    bytes artifact_hash = 2;        // 32 bytes, blake2b-256
    bytes signer_uuid = 3;          // 16 bytes
    string target_arch = 4;
    double min_proposer_reputation = 5;
    bytes proposal_uuid = 6;        // 16 bytes
    bytes signature = 7;            // 64 bytes, Ed25519
}
```

**Message type enum additions** (in `msg_types.h`):

```c
typedef enum {
    SIGNAL = 1,
    GROUP,
    PEER,
    PEER_CAPABILITIES,
    TASK,
    NET_MESSAGE,
    TASK_STATUS,
    TASK_RESULT,
    TRANSACTION_SCORE,
    UPDATE_PROPOSAL,       // New
    UPDATE_VOTE,           // New
    UPDATE_ACCEPTED,       // New
} message_type_t;
```

**Generic message union additions** (in `msg_types.h`):

```c
typedef struct {
    uuid_t proposal_uuid;
    uuid_t voter_uuid;
    bool accept;            // true = accept, false = reject
} update_vote_t;

typedef struct {
    uuid_t proposal_uuid;
    int accept_count;
    int reject_count;
} update_accepted_t;
```

### 3. Fleet Process

**Files:**
- `src/c/autonomous_trust/fleet/fleet_proc.h`
- `src/c/autonomous_trust/fleet/fleet_proc.c`

**Purpose:** New `Process` subclass that handles update proposals and voting.

**Registration:**

```c
DECLARE_PROCESS(fleet, fleet_proc, fleet_run);
```

**Protocol constants:**

```c
#define FLEET_PROTO_PROPOSE      "update proposal"
#define FLEET_PROTO_VOTE_REQ     "update vote request"
#define FLEET_PROTO_VOTE_GRANT   "update vote grant"
#define FLEET_PROTO_VOTE_NACK    "update vote nack"
#define FLEET_PROTO_ACCEPTED     "update accepted"
#define FLEET_PROTO_REJECTED     "update rejected"
```

**State:**

```c
static struct {
    paxos_instance_t vote_paxos;       // Paxos instance for update voting
    map_t pending_proposals;           // proposal_uuid -> update_proposal_t
    map_t accepted_updates;            // proposal_uuid -> update_proposal_t
    map_t my_votes;                    // proposal_uuid -> bool (my vote)
    double min_reputation_threshold;   // Configurable, default 0.7
    pthread_mutex_t lock;
    bool initialized;
} fleet_state;
```

**Handlers:**

- `handle_update_proposal(proc, queues, msg)`:
  1. Deserialize `update_proposal_t` from net message
  2. Verify proposal signature against known peer identities
  3. Query reputation of `signer_uuid` — reject if below `min_proposer_reputation`
  4. Store in `pending_proposals`
  5. Initiate Paxos vote via `paxos_propose()`

- `handle_vote_request(proc, queues, msg)`:
  1. Delegate to `paxos_handle_request()`
  2. If granted, send `FLEET_PROTO_VOTE_GRANT`
  3. If rejected, send `FLEET_PROTO_VOTE_NACK`

- `handle_vote_grant(proc, queues, msg)`:
  1. Delegate to `paxos_handle_grant()`
  2. If quorum reached, broadcast `FLEET_PROTO_ACCEPTED`

- `handle_update_accepted(proc, queues, msg)`:
  1. Move proposal from `pending_proposals` to `accepted_updates`
  2. Send `UPDATE_ACCEPTED` message to main loop (for Phase 5B/C consumption)

**Trust-gating:** The fleet process queries the reputation process for a peer's score before accepting proposals. This is done via the existing inter-process messaging: send `REP_PROTO_REP_REQ` to "reputation", receive `REP_PROTO_REP_RESP` with the score. This also fixes the pattern gap noted in `negprocess.py:128` (reputation-based rejection not implemented).

### 4. Routing Update

**File:** `src/c/autonomous_trust/autonomous_trust.c` (modified)

Add to the main message routing loop:

```c
case UPDATE_PROPOSAL:
    messaging_send(&queues, "fleet", msg);
    break;
case UPDATE_VOTE:
    messaging_send(&queues, "fleet", msg);
    break;
case UPDATE_ACCEPTED:
    // Forward to external (for Phase 5B/C to consume)
    messaging_send_external(&queues, q_out, msg);
    break;
```

### 5. Subsystems Config Update

The fleet process must be registered in the subsystems config so `autonomous_trust.c` starts it. This follows the existing pattern in `config/generate.c`:

```c
err = tracker_register_subsystem(&tracker, "fleet", "fleet_proc");
```

### 6. CMakeLists.txt Update

Add the new source files to the `autonomous_trust` library and `autonomous_trust_static` library targets:
- `autonomous_trust/fleet/fleet_proc.c`
- `autonomous_trust/fleet/update_proposal.c`
- `autonomous_trust/algorithms/paxos.c`

Add the new protobuf file:
- `autonomous_trust/core/protobuf/fleet/update_proposal.proto`

Add new test files:
- `test/paxos_test.c`
- `test/update_proposal_test.c`
- `test/fleet_proc_test.c`

## Bug Fixes (Inline)

These existing bugs will be fixed as they are encountered during implementation:

| Bug | File | Fix |
|-----|------|-----|
| `task.proto` empty | `src/protobuf/.../negotiation/task.proto` | Populate with `Task` message fields matching `task_t` struct |
| `smrt_create` memory leak | `configuration.c:280` | Free `data_struct` on error paths |
| Error handling in main loop | `autonomous_trust.c:231-232,346,358,364` | Add proper error logging and recovery for `EMAP_NOKEY`, `ECONNREFUSED` |
| Missing logging | `processes.c:164,268` | Add log statements for handler errors and unhandled message types |
| Paxos code duplication | `rep_proc.c` | Resolved by extraction to `paxos.c` (Component 1) |

## Testing Strategy

### Unit Tests (C, via libcheck)

1. **Paxos engine tests** (`test/paxos_test.c`):
   - Propose/grant/accept state machine
   - Quorum detection (odd and even peer counts)
   - Nack on stale proposal ID
   - Multiple concurrent proposals

2. **Update proposal tests** (`test/update_proposal_test.c`):
   - Serialization round-trip (struct <-> protobuf <-> struct)
   - Signature generation and verification
   - Invalid signature rejection

3. **Fleet process tests** (`test/fleet_proc_test.c`):
   - Trust-gating: low-reputation proposer rejected
   - Valid proposal accepted and vote initiated
   - Quorum reached triggers accepted broadcast
   - Duplicate proposal handling

### Integration Tests

4. **Reputation still works after Paxos extraction:**
   - Run existing reputation tests (`reputation_test`, `reputation2_test`, `reputation3_test`)
   - Must pass unchanged

5. **Multi-node update proposal** (extend `embedded/test-qemu.sh`):
   - 3-node cluster, peer A proposes update
   - All peers receive proposal, quorum vote completes
   - Proposal appears in accepted list on all peers

## File Summary

### New Files

| File | Purpose |
|------|---------|
| `src/c/autonomous_trust/algorithms/paxos.h` | Shared Paxos engine header |
| `src/c/autonomous_trust/algorithms/paxos.c` | Shared Paxos engine implementation |
| `src/c/autonomous_trust/fleet/fleet_proc.h` | Fleet process header |
| `src/c/autonomous_trust/fleet/fleet_proc.c` | Fleet process implementation |
| `src/c/autonomous_trust/fleet/update_proposal.h` | Update proposal struct and helpers |
| `src/c/autonomous_trust/fleet/update_proposal.c` | Serialization, signature, validation |
| `src/protobuf/autonomous_trust/core/protobuf/fleet/update_proposal.proto` | Protobuf definition |
| `src/c/test/paxos_test.c` | Paxos engine unit tests |
| `src/c/test/update_proposal_test.c` | Proposal serialization/signing tests |
| `src/c/test/fleet_proc_test.c` | Fleet process handler tests |

### Modified Files

| File | Change |
|------|--------|
| `src/c/autonomous_trust/utilities/msg_types.h` | Add `UPDATE_PROPOSAL`, `UPDATE_VOTE`, `UPDATE_ACCEPTED` to enum; add `update_vote_t`, `update_accepted_t` structs |
| `src/c/autonomous_trust/autonomous_trust.c` | Add routing cases for new message types; fix error handling bugs |
| `src/c/autonomous_trust/reputation/rep_proc.c` | Refactor to use shared `paxos.c` |
| `src/c/autonomous_trust/config/generate.c` | Register "fleet" subsystem |
| `src/c/autonomous_trust/config/configuration.c` | Fix `smrt_create` memory leak at line 280 |
| `src/c/autonomous_trust/processes/processes.c` | Add missing logging at lines 164, 268 |
| `src/c/CMakeLists.txt` | Add new source files, protobuf, and test targets |
| `src/protobuf/autonomous_trust/core/protobuf/negotiation/task.proto` | Populate with actual Task message fields |

## Decision Record

- **New message type over extending `task_t`**: Update proposals have fundamentally different fields (artifact hash, version, architecture) from tasks (capability, duration, timeout). Separate types keep both clean.
- **Separate vote chain from reputation chain**: Update votes are binary (accept/reject), not trust scores. Mixing them would distort the reputation model.
- **Shared Paxos extraction**: Two consumers now (reputation + fleet), code is well-contained (~200 lines), and having two copies would diverge. Existing tests verify the refactor.
- **Trust-gating in fleet process**: Fixes a known gap (negprocess.py:128 pattern) and is essential for security — low-reputation peers must not be able to push updates.
