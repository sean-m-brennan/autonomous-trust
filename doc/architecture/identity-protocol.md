[< Networking](networking.md)

# Identity Protocol

The identity protocol handles peer discovery, group formation, and ongoing admission of new nodes. It is a permissionless consensus protocol that must mitigate Sybil attacks.

## Protocol Messages

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

### Phase 0: Acquire Capabilities

The identity process waits (up to 10 seconds) for other local processes to register their capabilities via the IPC queue. This determines what services this node can offer to the network.

### Phase 1: Announce Identity

The node broadcasts its identity on the **open broadcast channel** (unencrypted UDP broadcast/multicast). The announcement contains the node's published identity (public keys only), package hash (to verify software authenticity), and capability list.

### Phase 2: Choose Group

The node waits to receive `full_history` messages from existing peers. These contain a group key and the identity DAG history. After a timeout period:

- If histories were received, the node selects the one with the longest step list, adopts that group, and sends a `history_diff` on the **encrypted group channel** containing any steps the group doesn't have.
- If no histories were received, the node creates its own group from scratch.

### Phase 3: Border Guard Mode (Concurrent)

Once in a group, the node enters border guard mode and concurrently:

- **Listens** for `request_access` announcements from new nodes on the open channel
- **Proposes** new peers to the group via `propose_peer` on the **encrypted group channel**
- **Votes** on proposed peers and collects votes from others
- **Confirms** accepted peers via `peer_accepted` on the **encrypted group channel**
- **Sends** identity acceptance and history to newly admitted peers on **encrypted peer-to-peer**
- **Handles** history diffs, group updates, and peer confirmations from other group members

## Peer Hierarchy

Peers are organized into 3 levels with a 10-level valuation scale. New peers enter at the middle level. Peers can be demoted for bad behavior (sending invalid messages, persistent failures).

## Identity Protocol Sequence

```mermaid
sequenceDiagram
    participant New as New Node
    participant Leader as Border Guard<br/>(existing peer)
    participant Others as Other Group<br/>Members

    note over New,Others: Phase 1 - Announce (open broadcast channel)

    New->>+Leader: announce<br/>(identity, pkg_hash, capabilities)
    New->>Others: announce<br/>(identity, pkg_hash, capabilities)

    note over Leader,Others: Phase 3 - Border guard evaluates

    alt Amnesiac peer (already known UUID)
        Leader->>Others: confirm (IdentityObj)<br/>[encrypted group]
        Leader->>New: accept (leader identity, pkg_hash, caps)<br/>[unencrypted peer-to-peer]
        Leader->>New: full_history (steps, group key)<br/>[encrypted peer-to-peer]
    else New peer
        Leader->>Others: propose (IdentityObj)<br/>[encrypted group]

        note over Leader,Others: Voting round (encrypted group channel)

        Others->>Others: _process_id()<br/>verify no UUID/key collision
        Leader->>Leader: _process_id()<br/>verify no UUID/key collision
        Others->>Leader: vote (IdentityObj, proof, signature)<br/>[encrypted group]
        Leader->>Leader: count_vote()<br/>verify signatures

        note over Leader: Vote collection timeout expires

        alt Votes sufficient (finalize succeeds)
            Leader->>Others: confirm (IdentityObj)<br/>[encrypted group]
            Leader->>New: accept (leader identity, pkg_hash, caps)<br/>[unencrypted peer-to-peer]
            Leader->>New: full_history (steps, group key)<br/>[encrypted peer-to-peer]
        end
    end

    note over New: Phase 2 - New node processes acceptance

    New->>New: handle_acceptance()<br/>add leader as peer
    New->>New: receive_history()<br/>adopt group key

    note over New: choose_group() selects longest history

    New->>Others: history_diff (new steps)<br/>[encrypted group]
    Others->>Others: handle_history_diff()<br/>merge branch

    note over Leader,Others: Group update (encrypted peer-to-peer)

    Leader->>Others: group_key_update (updated Group)<br/>[encrypted peer-to-peer]
```

## Agreement Implementations

The voting mechanism is pluggable via `AgreementImpl`:

| Implementation | Class | Description |
|---------------|-------|-------------|
| Proof of Work | `IdentityByWork` | Computational proof required |
| Proof of Stake | `IdentityByStake` | Stake-weighted voting (timeout: 5s) |
| Proof of Authority | `IdentityByAuthority` | Authority-weighted voting (timeout: 5s) |

## Security Properties

- **Package hash verification**: Nodes running different software versions are rejected
- **Duplicate detection**: UUID, signing key, and encryption key collisions are detected and rejected during voting
- **Signature verification**: All votes include Ed25519 signatures verified against the voter's public key
- **Open-channel minimization**: Only `announce` and `accept` use the open channel; `accept` is unencrypted because the new peer doesn't yet have the group key or the leader's public key for Box encryption

[Task Negotiation >](negotiation.md)
