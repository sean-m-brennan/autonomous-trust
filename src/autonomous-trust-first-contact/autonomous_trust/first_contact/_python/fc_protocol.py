# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
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
"""First contact's wire and local verbs (FEATURE_SPLIT_PLAN Phase 7, C6).

They were part of :class:`.protocol.IdentityProtocol`; first contact owns them
now, as social owns ``SocialProtocol``, and its handlers register them on the
identity process through the extension hook. The wire strings are unchanged.
Pinned by test_identity_protocol.py (the core's count and this one's). Mirrors
the ``ID_FC_*`` strings in C's first_contact/first_contact.c.
"""
from autonomous_trust.core.protocol import Protocol


class FirstContactProtocol(Protocol):
    """The verbs of the optional first-contact feature, on the identity
    process: the 1:1 handshake, reachability records, the directory and area
    hubs, one human's devices, and their shared address book."""
    # The handshake (OPTIONAL, opt-in via AT_FIRST_CONTACT; see
    # doc/architecture/first-contact.md and first_contact/first_contact.py). The 1:1
    # introduction handshake, DISTINCT from the cohort vote: a node holding a
    # signed invitation reaches the inviter directly, and each side admits the
    # other as a DIRECT peer (Peers.add, no group key) — never a group member.
    # Both ride the OPEN unencrypted channel because the first `hello` arrives
    # before the sender is a known peer, exactly like access_granted. They are
    # deliberately NOT BOOTSTRAP_VERBS: they confer no group membership and hand
    # over no group key, so the gateway boundary need not refuse them.
    hello = 'first_contact_hello'          # msg.obj <- invitation blob (the ticket); from_whom = sender identity
    hello_ack = 'first_contact_hello_ack'  # msg.obj <- json {'nonce': hex}; from_whom = accepter identity
    # A contact's signed reachability record (contacts/reach.py): pushed by its
    # holder over the sealed channel, or handed on locally by the network
    # process from a relay lookup. msg.obj <- json {body, sig}.
    reach_record = 'reach_record'
    # Directory contact (FIRST_CONTACT_PLAN Phase 3, first_contact/directory_contact.py).
    # A finder's signed request, and the holder's answer once its app accepted
    # it. Plaintext for hello's reason: neither side is a peer of the other yet.
    contact_request = 'first_contact_request'  # msg.obj <- json {body, sig}; from_whom = requester
    contact_accept = 'first_contact_accept'    # msg.obj <- json {nonce, invitation}; from_whom = holder
    # network -> identity, local IPC: a directory lookup's outcome
    # ({handle, entry | null, relay, limited}) and a registry's answer to our
    # publish or withdraw ({op, handle, relay, reason, seq}).
    dir_result = 'dir_result'
    dir_status = 'dir_status'
    # network -> identity, local IPC: an area lookup's outcome ({area,
    # cards: [{card, relay}], limited}) and a hub's answer to our publish or
    # withdraw ({op, area, relay, reason, seq}).
    hub_result = 'hub_result'
    hub_status = 'hub_status'
    # One human, several devices (FIRST_CONTACT_PLAN Phase 4,
    # first_contact/device_contact.py). Our own device cert, pushed over the sealed
    # channel to a contact once we are peers; and a new device telling a
    # contact it belongs to one of theirs -- plaintext, the contact does not
    # know it yet. Neither is answered.
    device_cert = 'device_cert'            # msg.obj <- json {body, sig}; from_whom = its node
    device_announce = 'device_announce'    # msg.obj <- json {cert, relays}; from_whom = the new device
    # Our own devices keeping one address book (first_contact/sibling_sync.py):
    # a first_contact/sync.py payload, sealed, to a sibling -- the whole book or
    # what changed; answered once only when it carries ``reply: true``.
    contacts_sync = 'contacts_sync'        # msg.obj <- json sync payload (+ reply)
