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
"""Keeping one user's address book the same on all of their devices
(FIRST_CONTACT_PLAN Phase 4, live pairing).

Each device is its own node with its own ``contacts.cfg.json``. Siblings --
the user's other devices, :mod:`.siblings` -- swap a *sync payload*:

    {v: 1, typename: "at-contacts-sync",
     contacts:   {uuid: <Contact canonical form>},
     tombstones: {uuid: removed_at}}

and :func:`merge` folds one into the local store, contact by contact, the
newer edit winning (last writer wins):

  - A record's version is :meth:`.Contact.version`: the latest of its
    ``added_at``, ``verified_at`` and ``updated_at``. Only edits the user makes
    date a record (add, verify, rename, a device or operator link); a
    reachability refresh does not, because each device hears those from the
    contact itself.
  - A removal is a tombstone ``{uuid: removed_at}``, kept for good. It beats
    any record of that uuid no newer than it, ties included; adding the
    contact again later is newer, and wins.
  - A remote time more than :data:`CLOCK_SKEW` past our clock is taken as now,
    so a sibling whose clock runs fast cannot pin its edits as the winner.
  - Equal versions go to the larger :func:`_tie_key`, a tuple both runtimes
    order the same way, so siblings converge whichever copy each saw first.
  - What can only ever be gained is never lost to a newer edit: nothing
    unverifies a contact, unlinks a device or unlearns an operator key, so
    the older copy's verification, devices and operator key are folded into
    the winner (:func:`_absorb`). A rename on one device cannot undo a
    verification the other made meanwhile, and both still end up the same.
  - A contact new on this device arrives as provenance ``sibling``; one
    already here keeps its own. Verification carries over with the record:
    the sibling that verified it is the same operator's.
  - Reachability is not part of the record's version: on a merge the highest
    ``reach_seq`` is kept and both hint lists are merged.

Same format and rules as C's ``contacts/sync.{h,c}``.
"""
import math
import time

from .contact import Contact, Provenance
from .store import is_uuid

SYNC_TYPENAME = 'at-contacts-sync'
VERSION = 1

#: How far past our clock a remote time may be before it is taken as now.
CLOCK_SKEW = 300.0

#: Hints kept on a contact after a merge: first_contact.MAX_RENDEZVOUS_HINTS.
_HINTS_MAX = 4


class InvalidSync(ValueError):
    """A sync payload that is not one."""


def build(store, uuids=None) -> dict:
    """The payload for ``store``: every contact and tombstone, or only those
    filed under ``uuids`` (a delta after a local edit)."""
    want = None if uuids is None else {str(u) for u in uuids}
    return {
        'v': VERSION, 'typename': SYNC_TYPENAME,
        'contacts': {u: c.to_canonical() for u, c in store.contacts.items()
                     if want is None or u in want},
        'tombstones': {u: float(t) for u, t in store.tombstones.items()
                       if want is None or u in want},
    }


def _clamp(t, now):
    return now if t > now + CLOCK_SKEW else t


def _time(v):
    if isinstance(v, bool) or not isinstance(v, (int, float)) \
            or not math.isfinite(v) or v < 0:
        return None
    return float(v)


def _tie_key(c):
    """What two records of equal version are ordered by. Built from values
    both runtimes compare the same way (no float printing involved)."""
    return (int(bool(c.verified)), float(c.trust_seed), c.petname,
            c.operator_key, ','.join(sorted(c.device_uuids())), c.nonce)


def _newer(remote, local) -> bool:
    rv, lv = remote.version(), local.version()
    if rv != lv:
        return rv > lv
    return _tie_key(remote) > _tie_key(local)


def _merge_hints(fresh, existing):
    out = []
    for h in list(fresh) + list(existing):
        if isinstance(h, str) and h and h not in out:
            out.append(h)
    return out[:_HINTS_MAX]


def _absorb(winner, loser) -> bool:
    """Fold into ``winner`` what ``loser`` has gained that it lacks: its
    verification, its operator key, and its devices under that key. Returns
    whether ``winner`` changed."""
    from .device import DEVICES_MAX
    changed = False
    if loser.verified and not winner.verified:
        winner.verified = True
        winner.verified_at = loser.verified_at
        winner.trust_seed = loser.trust_seed
        changed = True
    if loser.operator_key and not winner.operator_key:
        winner.operator_key = loser.operator_key
        changed = True
    if loser.operator_key == winner.operator_key:
        have = {winner.uuid} | set(winner.device_uuids())
        for dev in loser.devices:
            if dev.uuid not in have and len(winner.devices) < DEVICES_MAX:
                winner.devices.append(dev)
                have.add(dev.uuid)
                changed = True
    return changed


def _clamp_contact(c, now):
    """Take any time on ``c`` that is too far ahead of ours as now."""
    c.added_at = _clamp(c.added_at, now)
    c.verified_at = _clamp(c.verified_at, now)
    c.updated_at = _clamp(c.updated_at, now)


def _conflicts(store, contact, exclude) -> bool:
    """Whether taking ``contact`` would file one of its devices, or its
    operator key, twice, or file one of our own devices as a contact."""
    uuid = contact.uuid
    for ident in contact.identities():
        u = str(ident.uuid)
        if u in exclude:
            return True
        holder = store.get(u)
        if holder is not None and holder.uuid != uuid:
            return True
    if contact.operator_key:
        holder = store.by_operator(contact.operator_key)
        if holder is not None and holder.uuid != uuid:
            return True
    return False


def merge(store, payload, now=None, exclude=()):
    """Fold the sync ``payload`` into ``store``. Returns the changes as a list
    of ``(uuid, 'added' | 'updated' | 'removed' | 'tombstone')`` in uuid
    order, 'tombstone' being a removal of a contact this device never had,
    kept to pass on; an empty list means there is nothing to save. ``exclude`` is this node's own uuid and
    its siblings': never taken as contacts. Raises :class:`InvalidSync` on a
    payload that is not one; a malformed record inside one is skipped.
    """
    v = payload.get('v') if isinstance(payload, dict) else None
    if not isinstance(payload, dict) or payload.get('typename') != SYNC_TYPENAME \
            or not isinstance(v, int) or isinstance(v, bool) or v != VERSION:
        raise InvalidSync('not a version-%d contacts sync' % VERSION)
    contacts = payload.get('contacts', {})
    tombstones = payload.get('tombstones', {})
    if not isinstance(contacts, dict) or not isinstance(tombstones, dict):
        raise InvalidSync('contacts sync: contacts and tombstones are maps')
    now = float(now if now is not None else time.time())
    exclude = {str(u) for u in exclude}
    changes = {}

    for uuid in sorted(tombstones):
        at = _time(tombstones[uuid])
        if at is None or not is_uuid(uuid):
            continue
        at = _clamp(at, now)
        local = store.contacts.get(uuid)
        if local is not None:
            if at >= local.version():
                store.remove(uuid, at=at)
                changes[uuid] = 'removed'
        elif at > store.tombstones.get(uuid, -1.0):
            # Kept, so it reaches a third device that still has the contact.
            store.tombstones[uuid] = at
            changes[uuid] = 'tombstone'

    for key in sorted(contacts):
        remote = Contact.from_canonical(contacts[key])
        if remote is None or remote.uuid != key:
            continue
        _clamp_contact(remote, now)
        uuid = remote.uuid
        if store.tombstones.get(uuid, -1.0) >= remote.version():
            continue
        if _conflicts(store, remote, exclude):
            continue
        local = store.contacts.get(uuid)
        if local is None:
            remote.provenance = Provenance.sibling
            store.add(remote)
            changes[uuid] = 'added'
        elif _newer(remote, local):
            _absorb(remote, local)
            remote.provenance = local.provenance
            remote.reach_seq = max(remote.reach_seq, local.reach_seq)
            remote.rendezvous = _merge_hints(local.rendezvous, remote.rendezvous)
            if _conflicts(store, remote, exclude):
                continue
            store.add(remote)
            changes[uuid] = 'updated'
        else:
            # Ours stays, gaining what the older copy has that ours lacks.
            mine = Contact.from_canonical(local.to_canonical())
            if _absorb(mine, remote) and not _conflicts(store, mine, exclude):
                store.add(mine)
                changes[uuid] = 'updated'
    return sorted(changes.items())
