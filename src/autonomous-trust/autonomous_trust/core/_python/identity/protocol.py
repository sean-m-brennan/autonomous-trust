# ******************
#  Copyright 2025 Sean M. Brennan and contributors
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
