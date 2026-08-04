[< Networking](networking.md)

# Identity Protocol

The identity protocol handles peer discovery, group formation, and ongoing admission of new nodes. It is a permissionless consensus protocol that must mitigate Sybil attacks.

## Protocol messages

| Message | Constant | Payload |
|---------|----------|---------|
| `request_access` | `announce` | `(identity, package_hash, capabilities_list)` |
| `access_granted` | `accept` | `(identity, package_hash, capabilities_list)` |
| `full_history` | `history` | `(list[LinkedStep], Group)` |
| `history_diff` | `diff` | `list[LinkedStep]` |
| `propose_peer` | `propose` | `IdentityObj` |
| `vote_on_peer` | `vote` | `(IdentityObj, AgreementProof, (message_bytes, signature_bytes))` |
| `peer_accepted` | `confirm` | `IdentityObj` |
| `group_key_update` | `update` | `Group` |

## Phases

### Phase 0: acquire capabilities

The identity process waits (up to 10 seconds) for other local processes to register their capabilities via the IPC queue. This determines what services this node can offer to the network.

### Phase 1: announce identity

The node broadcasts its identity on the **open broadcast channel** (unencrypted UDP broadcast/multicast). The announcement contains the node's published identity (public keys only), package hash (to verify software authenticity), and capability list.

### Phase 2: choose group

The node waits to receive `full_history` messages from existing peers. These contain a group key and the identity DAG history. After a timeout period:

- If histories were received, the node selects the one with the longest step list, adopts that group, and sends a `history_diff` on the **encrypted group channel** containing any steps the group doesn't have.
- If no histories were received, the node creates its own group from scratch.

### Phase 3: border guard mode (concurrent)

Once in a group, the node enters border guard mode and concurrently:

- **Listens** for `request_access` announcements from new nodes on the open channel
- **Proposes** new peers to the group via `propose_peer` on the **encrypted group channel**
- **Votes** on proposed peers and collects votes from others
- **Confirms** accepted peers via `peer_accepted` on the **encrypted group channel**
- **Sends** identity acceptance and history to newly admitted peers on **encrypted peer-to-peer**
- **Handles** history diffs, group updates, and peer confirmations from other group members

### Post-admission: bootstrap corpus and recovery (concurrent)

After a node is in a group, two further mechanisms run alongside border guard mode:

- **Bootstrap corpus.** A `BootstrapWorker` issues bilateral bootstrap-capability exchanges (`at.handshake`, `at.time-attest`, `at.echo-challenge`) shortly after the first peer joins, so freshly-admitted peers accumulate a baby-steps transaction history and don't sit at flat reputation. See [Trust Tiers §6](trust-tiers.md) and [Node Lifecycle](node-lifecycle.md).
- **Capability & identity resync.** Because the confirm-time directed `caps_query` and the announce broadcast can be lost (UDP over a Docker bridge, late joiners), `IdentityProcess` runs periodic backstop sweeps: a caps-resync that re-queries admitted peers with no registered capabilities, and an identity-resync that backfills missing peer Identities for addresses already in the group. See [Partition Recovery §12](partition-recovery.md).

## Cross-runtime serialization

- **Canonical wire form.** Identity and `Group` payloads are serialized in a **DRY canonical flat-dict JSON form** (`to_canonical()` / `from_canonical()`) that is byte-parseable by the C implementation. Python's default `ConfigJSONEncoder` form (with `__type__` / `_uuid` markers and a base64-wrapped hex seed) is *not* C-parseable, so all cross-runtime deliveries (`full_history`, `group_key_update`, accept/confirm) emit the canonical form. The C twin's `group_to_json` produces a byte-identical shape. See [Native / FFI Dual Implementation](native-ffi-dual-implementation.md) §6.
- **Zooko-triangle names.** An Identity carries two human-readable names. The **`nickname`** is the *online* / global name (formerly `fullname`): e.g. `squad-warrant@dod-demo`, and **is** part of the canonical wire form so a receiver learns the peer's self-asserted global name. The **`petname`** is the *local* name a node assigns for itself (e.g. the bare roster role `squad-warrant`); it is purely local, **never serialized or transmitted**, and each receiver assigns its own. `public_identity_to_canonical()` (`_python/identity/identity.py`, mirrored in `src/c/.../identity/identity.c`) emits `nickname` and omits `petname`; a unit/conformance test asserts the canonical set includes `'nickname'` and that `'petname' not in canonical`.

## Peer hierarchy

Peers are organized into 3 levels with a 10-level valuation scale. New peers enter at the middle level. Peers can be demoted for bad behavior (sending invalid messages, persistent failures). Reputation-derived **trust tiers** layer on top of this, see [Trust Tiers](trust-tiers.md).

## Identity protocol sequence

The diagram below is generated from `conformance/scenarios/identity/identity-canonical.yaml` by `scripts/build-docs.sh`: it cannot drift from the executable corpus.

<!-- at_diagram:start protocol=identity scenario=identity-canonical -->
```mermaid
sequenceDiagram
    participant bg as border_guard
    participant peer_a as border_guard
    participant newcomer as new_node
    Note over newcomer: broadcast: request_access
    Note right of newcomer: newcomer broadcasts its identity, package hash, and capabilities. bg receives the announce and runs welcoming_committee.
    Note over bg: broadcast: propose_peer
    Note right of bg: bg's welcoming_committee emits a propose_peer to the encrypted group channel so other border guards (peer_a here) can vote.
    peer_a->>bg: vote_on_peer
    Note right of peer_a: peer_a (another BG) votes to admit newcomer. bg's handle_count_vote tallies via vote_collection_increment.
    Note over bg: broadcast: peer_accepted
    Note right of bg: After synchronous _vote_collection finalizes, _peer_accepted broadcasts a peer_accepted to the encrypted group channel.
    bg-->>newcomer: access_granted (re: 1)
    Note right of bg: bg sends its own published identity to newcomer in the open so the newcomer can encrypt subsequent traffic to bg.
    bg-->>newcomer: full_history (re: 1)
    Note right of bg: bg sends the group key and identity-history DAG so newcomer can join and decrypt subsequent group-encrypted traffic.
```
<!-- at_diagram:end -->

**Channel semantics:** `request_access` travels on the **open broadcast channel** (unencrypted UDP). `propose_peer`, `vote_on_peer`, and `peer_accepted` travel on the **encrypted group channel**. `access_granted` is sent peer-to-peer in the open (the newcomer has no group key yet), and `full_history` is peer-to-peer encrypted with the leader's box key once `access_granted` has been processed.

**Internal steps not on the wire** (omitted from the diagram, but part of the protocol):

- After receiving `propose_peer`, each receiver runs `_process_id()` to verify the candidate's UUID and keys don't collide with existing peers; rejection short-circuits the vote.
- After receiving each `vote_on_peer`, the leader runs `count_vote()` to verify the signature and increment the vote tally.
- After receiving `access_granted`, the newcomer runs `handle_acceptance()` to add the leader as a peer, then `receive_history()` on the subsequent `full_history` to adopt the group key.
- The newcomer's `choose_group()` selects the longest history if multiple groups responded, and sends a `history_diff` back to the group with any steps the group is missing.

**Alternate path: amnesia readmission.** If the leader recognizes the newcomer's UUID from history (a previously-known peer rejoining), it skips the voting round and emits `peer_accepted` / `access_granted` / `full_history` directly. The amnesia trace is pinned by `conformance/scenarios/identity/amnesia-readmission.yaml`. v1 of the diagram tool does not render `alt`/`else` branches; the two paths are documented as separate scenarios.

**Group key rotation.** When the group composition changes, the leader broadcasts `group_key_update` (encrypted peer-to-peer) so existing members rotate to the new key. Covered by `conformance/scenarios/identity/group-key-update.yaml`.

## Agreement implementations

The voting mechanism is pluggable via `AgreementImpl`:

| Implementation | Class | Description |
|---------------|-------|-------------|
| Proof of Work | `IdentityByWork` | Computational proof required |
| Proof of Stake | `IdentityByStake` | Stake-weighted voting (timeout: 5s) |
| Proof of Authority | `IdentityByAuthority` | Authority-weighted voting (timeout: 5s) |

## Security properties

- **Package hash verification**: Nodes running different software versions are rejected
- **Duplicate detection**: UUID, signing key, and encryption key collisions are detected and rejected during voting
- **Signature verification**: All votes include Ed25519 signatures verified against the voter's public key
- **Open-channel minimization**: Only `announce` and `accept` use the open channel; `accept` is unencrypted because the new peer doesn't yet have the group key or the leader's public key for Box encryption

[Task Negotiation >](negotiation.md)
