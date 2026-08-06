# ******************
#  Copyright 2023 TekFive, Inc., Sean M. Brennan, and contributors
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
# ******************

from ..protocol import Protocol


class IdentityProtocol(Protocol):
    """
    Protocol for establishing Identity
    ----------------------------------

    Permissionless consensus (must mitigate Sybil attack)

    Three channels:
        - unsecured broadcast channel
        - secure broadcast channel with group key
        - secure private channel with private key

    1. announce: open broadcast my own Identity
    2. full_history on secure private channel:
       a. wait to receive history + group <- steps list + Group
          - merge with my own
          - send history_diff on closed broadcast -> steps list
       b. timeout, create group
    3. border-mode: listen on open broadcast channel for announce
       a. propose: initiate internal voting (closed broadcast) -> IdentityObj
       b. listen for propose <- IdentityObj
          - eldest n remain in border-mode
       c. vote -> (blob, proof, sig)
       d. listen for votes <- (blob, proof, sig)
          - if approved:
             * respond first with my id and hash in open privately
             * then respond with full_history + group key privately (closed) -> steps list + Group
       e. confirm peer -> IdentityObj
       f. update group -> Group
    4. listen on closed broadcast channel for peer confirmation <- IdentityObj
    5. listen on closed broadcast channel for history_diffs <- steps list
       a. add as branch to history
       b. merge if ok
    6. listen on closed broadcast channel for group updates (address list additions) <- Group
    7. listen for hierarchy roots # FIXME

    Items 3, 4, & 5 are concurrent
    """
    announce = 'request_access'  # msg.obj <- (identity, package hash, capabilities list) of new node
    accept = 'access_granted'  # msg.obj <- (identity, package hash, capabilities list) of lead peer
    history = 'full_history'  # msg.obj <- (list[LinkedSteps], group)
    diff = 'history_diff'  # msg.obj <- list[LinkedSteps]
    propose = 'propose_peer'  # msg.obj <- identity
    vote = 'vote_on_peer'  # msg.obj <- (identityobj, proof, signature)
    confirm = 'peer_accepted'  # msg.obj <- identityobj
    update = 'group_key_update'  # msg.obj <- group
    # Recovery path for the announce-broadcast loss case: when a peer
    # admits another via confirm but never received its announce
    # (no_prior_potential), it sends caps_query directly. The target
    # responds with caps_response carrying its capability list. Both
    # messages flow via reliable group/TCP, not UDP broadcast.
    caps_query = 'peer_caps_query'  # msg.obj <- '' (sender just asks)
    caps_response = 'peer_caps_response'  # msg.obj <- caps list (json)
    # Identity backfill for a node that holds a group member's address (in
    # group.addresses) but never received its full Identity — the cold/late
    # joiner case (e.g. the dod_mission coordinator: group.addresses grows via
    # the merge/partition path but self.peers stays sparse, so consensus
    # reputations can't be named). id_query broadcasts the uuids we lack; the
    # matching member answers with id_response carrying its published
    # identity, which we add to self.peers. See _periodic_identity_resync and
    # dod-coordinator-partition-nonconvergence.md (layer 3).
    id_query = 'peer_identity_query'  # msg.obj <- json list[uuid_str] we lack
    id_response = 'peer_identity_response'  # msg.obj <- json {'from_identity': publish()}
    # Subtree member-roster enumeration (hierarchy-aware membership). A node
    # asks a gateway to enumerate its subtree; the gateway replies with its
    # LOCAL members plus the child gateways to recurse into, and the requestor
    # aggregates breadth-first across the tree (aggregate_subtree_roster). This
    # surfaces community members hidden behind member gateways, at any depth.
    # See doc/architecture/gateway-reputation-tree.md.
    roster_req = 'subtree_roster_query'  # msg.obj <- json {'requestor': uuid_str}
    roster_resp = 'subtree_roster_response'  # msg.obj <- json {'members': [...], 'child_gateways': [uuid_str]}
    # Local-only IPC (no wire egress). ReputationProcess emits these to
    # CfgIds.identity when a peer's reputation crosses a TIER_FLOORS
    # boundary so IdentityProcess can update the peer's trust tier on
    # its local mirror; capability-gated negotiation reads peer._tier.
    # See doc/architecture/trust-tiers.md for the rank-vs-tier split.
    tier_update = 'tier_update'  # msg.obj <- (peer_uuid_str, new_tier_int)
    # Local-only IPC (no wire egress). ReputationProcess emits this to
    # CfgIds.negotiation when a peer's trust tier drops (demotion).
    # NegotiationProcess.handle_tier_lost cancels any in-flight tasks
    # whose capability.required_tier exceeds new_tier. See
    # doc/architecture/trust-tiers.md §7.2.
    tier_lost = 'tier_lost'  # msg.obj <- (peer_uuid_str, new_tier_int)
    # Group partition recovery (doc/architecture/partition-recovery.md).
    # partition_signal: local-only IPC. NetProcess emits this when it
    # receives group-channel traffic from a sender that is not in our
    # group's address list — a possible split-brain signal.
    #   msg.obj <- str (from_addr "host:port" of the rejected message)
    partition_signal = 'partition_signal'
    # partition_probe / partition_response: wire-facing, unsecured
    # multicast. Probe broadcasts our group's uuid+size; response
    # carries the responder's group uuid+size+leader-address so the
    # probe sender can decide whether to initiate a normal request_access
    # to join the larger group.
    #   probe.obj    <- {"from_uuid", "from_address", "my_group_uuid",
    #                    "my_group_size", "signature"}
    #   response.obj <- {"from_uuid", "from_address", "in_response_to",
    #                    "my_group_uuid", "my_group_size",
    #                    "my_group_leader", "my_group_leader_address",
    #                    "signature"}
    partition_probe = 'group_partition_probe'
    partition_response = 'group_partition_response'
    # Operator-attended pull (ethne D8 guardian edge, attended-now half).
    # A consumer asks a node whether a human is at its console RIGHT NOW;
    # the node answers with a freshly stamped, independently verifiable
    # attestation (the same payload shape the admission path carries, so the
    # receiver re-verifies the real operator credential rather than trusting
    # an asserted bool). Pull-on-demand by design: there is no periodic
    # keepalive re-announce, so an idle network carries no attestation
    # traffic at all. The requestor's nonce is echoed back and is
    # load-bearing — without it a signed attestation could be replayed
    # forever, which would defeat the whole point of attended-NOW.
    # See doc/architecture/operator-attended.md.
    attest_req = 'operator_attest_query'  # msg.obj <- json {'nonce': hex_str}
    attest_resp = 'operator_attest_response'  # msg.obj <- json {'nonce': hex_str, ...attestation}
    # Local-only IPC (no wire egress). A consumer (ethne's guardian edge, the
    # console, an app) asks the main loop to pull a peer; the main loop hands
    # the request to IdentityProcess, which owns the pull end to end. It must:
    # the answer is only worth anything if the operator credential in it is
    # re-verified against the DISTINCT operator trust anchor, and that anchor
    # lives in the identity process alongside the admission gate. So identity
    # mints the nonce, emits the query, verifies the reply, and reports the
    # verified stamp back for consumers to read.
    attest_trigger = 'operator_attest_trigger'  # msg.obj <- json {'target': uuid_str}
    # Local-only IPC (no wire egress). The live OperatorSession lives in the
    # console app's address space, which the node's MAIN LOOP shares (the
    # bridge runs run_forever in a daemon thread) — but IdentityProcess runs
    # in its own subprocess and cannot see it. So on an inbound attest_req
    # the identity process asks the main loop for the current session state
    # and answers the pull once it replies. A round trip per pull, rather
    # than a cached mirror: nothing is stored, so nothing can go stale.
    # See doc/architecture/operator-attended.md.
    operator_state_req = 'operator_state_query'  # msg.obj <- '' (identity asks main)
    operator_state_resp = 'operator_state_response'  # msg.obj <- json {'attended', 'epoch', 'have_session'}


# Verbs this implementation legitimately puts on the wire in PLAINTEXT
# (`Message(..., encrypt=False)`), and the only ones a receiver will accept
# unencrypted from a peer it already knows.
#
# Why an allowlist exists at all: the point-to-point receive path attributes a
# frame by source address, then decrypts. Once a peer is in the listing, every
# frame from it takes the decrypt branch -- so a plaintext handshake verb, which
# by design cannot be decrypted, was dropped (netprocess.py, and measured: it
# cost 3-peer convergence). The unknown-sender branch has always tried a
# plaintext parse first, so plaintext acceptance is not new; what is new is
# bounding it to named verbs instead of extending it to anything a known peer
# sends. A peer in the listing must not be able to downgrade, say, a reputation
# or negotiation message to plaintext and have it honored.
#
# MAINTENANCE: adding an `encrypt=False` send REQUIRES adding its verb here, or
# the receiver will drop it once the peer is known -- silently, on a path that
# only shows up in multi-peer convergence. test_unencrypted_verbs.py pins the
# set against the identity process's actual send sites.
UNENCRYPTED_VERBS = frozenset({
    IdentityProtocol.announce,           # request_access, pre-admission broadcast
    IdentityProtocol.accept,             # access_granted, sent before the key lands
    IdentityProtocol.id_query,           # identity backfill, both directions
    IdentityProtocol.id_response,
    IdentityProtocol.attest_req,         # operator-attended pull / answer
    IdentityProtocol.attest_resp,
    IdentityProtocol.roster_resp,        # subtree roster answer
    IdentityProtocol.partition_probe,    # partition recovery, by definition
    IdentityProtocol.partition_response, # spans a group-key boundary
})


if __name__ == '__main__':
    import napkin

    @napkin.seq_diagram()
    def identity_protocol(c):
        node = c.object('new_node')
        peer = c.object('leader')
        others = c.object('other_peers')
        with c.group('open'):
            with node:
                with peer.announce_identity('identity, hash, capabilities'):
                    with peer.welcoming_committee():
                        with c.alt():
                            with c.choice('new_node amnesia'):
                                c.note('leader already has new_node identity')
                                with c.group('encrypted'):
                                    with others.confirm():
                                        others.handle_confirm_peer()
                                with c.choice('else'):
                                    with c.group('encrypted / group'):
                                        with peer.vote_collection():
                                            with others.propose('identity'):
                                                others.handle_vote_on_peer()
                                                peer.vote('id, proof, sig')
                                            peer.count_vote()
                                        with others.confirm():
                                            others.handle_confirm_peer()
                        node.accept('leader identity')
                node.handle_acceptance().note(callee='others now have new_node identity')
        with c.group('encrypted / direct'):
            with peer:
                node.history('list of dag steps, group')
            with node:
                node.receive_history().note(callee="populates others' identities")
                node.choose_group().note(callee='joins group')
        with c.group('encrypted / group'):
            with node:
                with others.diff('list of dag steps'):
                    others.handle_history_diff().note(caller='may merge adjacent network')


    napkin.generate('plantuml_svg')
