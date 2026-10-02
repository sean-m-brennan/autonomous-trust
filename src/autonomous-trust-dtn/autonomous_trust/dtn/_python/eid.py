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
"""Endpoint identifiers for the DTN transport: the Python twin of
src/c/extensions/dtn/dtn_eid.c, and of the addressing half of
net_transport_dtn.c.

Scheme (at-over-dtn.md §2.1)::

    dtn://at-<uuid[0:4] hex>/            a node
    dtn://at-<uuid[0:4] hex>/peer        its unicast endpoint
    dtn://at-group-<hash[0:8] hex>/      a group
    .../bcast, .../group                 the group's broadcast and group endpoints

Every function here is pure, so the ``dtn`` conformance protocol runs them in
both runtimes and compares the strings.
"""
import uuid as _uuid

#: Longest EID either runtime builds (C's DTN_EID_MAX); one more is refused, as
#: C's snprintf into a DTN_EID_MAX+1 buffer refuses it.
EID_MAX = 127

PEER_SUFFIX = '/peer'
BCAST_SUFFIX = '/bcast'
GROUP_SUFFIX = '/group'

#: The three logical channels, numbered as C's net_channel_t.
CHAN_PEER = 0
CHAN_BROADCAST = 1
CHAN_GROUP = 2
CHANNELS = (CHAN_PEER, CHAN_BROADCAST, CHAN_GROUP)

_SUFFIX = {CHAN_PEER: PEER_SUFFIX, CHAN_BROADCAST: BCAST_SUFFIX, CHAN_GROUP: GROUP_SUFFIX}
_CHANNEL = {v: k for k, v in _SUFFIX.items()}

#: The group hash a node uses before it has joined a group, so every unjoined
#: node converges on one broadcast EID for discovery.
PRE_JOIN_HASH = b'AT-boot\x00'

#: A node EID used when the transport opens without an identity.
PLACEHOLDER_NODE_EID = 'dtn://at-local/'


class EIDError(ValueError):
    """An EID could not be formed: too long, or from too short a hash."""


def _checked(eid: str) -> str:
    if len(eid.encode('utf-8')) > EID_MAX:
        raise EIDError('EID longer than %d bytes: %r' % (EID_MAX, eid))
    return eid


def _uuid_bytes(value) -> bytes:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, _uuid.UUID):
        return value.bytes
    return _uuid.UUID(str(value)).bytes


def eid_from_uuid(node_uuid) -> str:
    """The node EID: the first four bytes of the uuid, in lower-case hex."""
    raw = _uuid_bytes(node_uuid)
    return _checked('dtn://at-%s/' % raw[:4].hex())


def eid_for_service(base_eid: str, service: str) -> str:
    """``base_eid`` (ending in '/') plus ``service`` without its leading '/'."""
    return _checked(base_eid + (service[1:] if service.startswith('/') else service))


def eid_for_group(group_hash: bytes) -> str:
    """The group EID from the first eight bytes of ``group_hash``."""
    group_hash = bytes(group_hash)
    if len(group_hash) < 8:
        raise EIDError('group hash shorter than 8 bytes')
    return _checked('dtn://at-group-%s/' % group_hash[:8].hex())


def group_hash(group_uuid) -> tuple[bytes, bool]:
    """The eight bytes a group EID is built from, and whether a group is
    joined: the joined group's uuid, or :data:`PRE_JOIN_HASH` when there is none
    (no group, or the all-zero uuid)."""
    if group_uuid is not None and str(group_uuid) != '':
        try:
            raw = _uuid_bytes(group_uuid)
        except (ValueError, TypeError):
            raw = b''
        if len(raw) >= 8 and any(raw):
            return raw[:8], True
    return PRE_JOIN_HASH, False


def channel_suffix(channel: int) -> str:
    return _SUFFIX[channel]


def service_to_channel(service) -> int | None:
    """The channel a bundle belongs to from the service it arrived on; None for
    an unknown service (the transport drops it)."""
    return _CHANNEL.get(service)


def endpoints(node_uuid, group_uuid) -> list[tuple[str, str]]:
    """The three ``(eid, service)`` endpoints a transport registers, in channel
    order: ``/peer`` on the node EID (the primary, and the source of every
    send), then ``/bcast`` and ``/group`` on the group EID."""
    node = eid_from_uuid(node_uuid) if node_uuid else PLACEHOLDER_NODE_EID
    grp = eid_for_group(group_hash(group_uuid)[0])
    return [(eid_for_service(node, PEER_SUFFIX), PEER_SUFFIX),
            (eid_for_service(grp, BCAST_SUFFIX), BCAST_SUFFIX),
            (eid_for_service(grp, GROUP_SUFFIX), GROUP_SUFFIX)]


def broadcast_eid(channel: int, group_uuid) -> str:
    """Where a broadcast (``CHAN_BROADCAST``) or group (``CHAN_GROUP``) send
    goes, from the group joined now."""
    if channel == CHAN_PEER:
        raise EIDError('the peer channel has no broadcast EID')
    return eid_for_service(eid_for_group(group_hash(group_uuid)[0]), channel_suffix(channel))


def is_eid_literal(target) -> bool:
    """True for a scheme-qualified EID (``dtn:`` or ``ipn:``)."""
    return isinstance(target, str) and target.startswith(('dtn:', 'ipn:'))


def peer_eid(target: str, uuid_for_address=None) -> str:
    """Where a unicast to ``target`` (a peer's address) goes, in C's order:

    1. ``target`` itself when it is already an EID;
    2. the ``/peer`` EID of the peer whose address is exactly ``target``
       (``uuid_for_address(target)`` returns its uuid, or None);
    3. ``dtn://at-<target>/peer``.
    """
    if not target:
        raise EIDError('empty unicast target')
    if is_eid_literal(target):
        return _checked(target)
    if uuid_for_address is not None:
        found = uuid_for_address(target)
        if found is not None:
            return eid_for_service(eid_from_uuid(found), PEER_SUFFIX)
    return _checked('dtn://at-%s/peer' % target)
