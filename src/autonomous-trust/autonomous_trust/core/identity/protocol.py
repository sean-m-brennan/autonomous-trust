# ******************
#  Copyright 2024 TekFive, Inc. and contributors
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
