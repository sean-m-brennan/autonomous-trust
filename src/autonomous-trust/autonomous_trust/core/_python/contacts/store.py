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
"""The durable, user-owned contacts store.

Persists as ``<data_dir>/contacts.cfg.json`` through the same atomic-write
:class:`Configuration` machinery every other on-disk config uses
(``config/configuration.py`` ``atomic_write``/``to_file``), so a concurrent
reader never sees a torn file. Unlike ``Peers.filtered_for_persist`` -- which
prunes untrusted cohort members on every restart -- this store is authoritative
personal state and is never pruned automatically.
"""
import json
import math
import os
import time

from ..config.configuration import Configuration, atomic_write
from .contact import Contact

CONTACTS_TYPENAME = 'contacts'
CONTACTS_VERSION = 1


class Contacts(Configuration):
    """A UUID-keyed address book of :class:`Contact` records.

    Keyed by the peer's UUID string -- the stable cryptographic identifier --
    NOT by petname (local, mutable) or nickname (global but not unique), so a
    peer that changes its self-asserted nickname still resolves to one entry and
    re-adding a known peer replaces rather than duplicates it.
    """

    default_filename = 'contacts'

    def __init__(self, contacts=None, tombstones=None):
        super().__init__()
        # uuid_str -> Contact. dict(...) so a decoded mapping (config round-trip)
        # and a caller-supplied dict both work.
        self.contacts = dict(contacts or {})
        # uuid_str -> when the user removed that contact (Phase 4,
        # contacts/sync.py): the removal the user's other devices copy. Kept
        # for good -- one is a few dozen bytes, and dropping it would let a
        # device that was away long enough bring the contact back.
        self.tombstones = dict(tombstones or {})
        self.reindex()

    def reindex(self):
        """Rebuild the device index: every further device's uuid -> the uuid
        its contact is filed under (Phase 4, contacts/device.py). Call after
        changing a contact's ``devices``."""
        self._device_of = {dev.uuid: uuid for uuid, c in self.contacts.items()
                           for dev in getattr(c, 'devices', [])}

    def to_dict(self):
        # The device index is derived state, rebuilt by __init__: keep it out
        # of the cls(**to_dict()) config round-trip.
        d = super().to_dict()
        d.pop('_device_of', None)
        return d

    # -- membership -------------------------------------------------------
    def add(self, contact: Contact) -> Contact:
        """Add or replace a contact (keyed by UUID). Returns the stored contact.
        Adding a contact again undoes an earlier removal of it."""
        self.contacts[str(contact.uuid)] = contact
        self.tombstones.pop(str(contact.uuid), None)
        self.reindex()
        return contact

    def get(self, uuid) -> Contact:
        """The contact ``uuid`` belongs to: its first device, or any further
        one."""
        uuid = str(uuid)
        return self.contacts.get(uuid) or self.contacts.get(self._device_of.get(uuid))

    def by_operator(self, operator_key: str) -> Contact:
        """The contact whose operator key this is, or None."""
        if not operator_key:
            return None
        for contact in self.contacts.values():
            if getattr(contact, 'operator_key', '') == operator_key:
                return contact
        return None

    def by_petname(self, petname: str) -> Contact:
        for contact in self.contacts.values():
            if contact.petname == petname:
                return contact
        return None

    def by_nickname(self, nickname: str):
        """All contacts asserting this ONLINE nickname (not unique, so a list)."""
        return [c for c in self.contacts.values() if c.nickname == nickname]

    def remove(self, uuid, at=None) -> bool:
        """Drop the contact filed under ``uuid`` (its first device), with every
        device it lists, leaving a tombstone dated ``at`` (default now) so the
        user's other devices drop it too."""
        gone = self.contacts.pop(str(uuid), None)
        if gone is not None:
            at = float(at if at is not None else time.time())
            self.tombstones[str(uuid)] = max(at, gone.version(),
                                             self.tombstones.get(str(uuid), 0.0))
        self.reindex()
        return gone is not None

    def all(self):
        return list(self.contacts.values())

    def verified(self):
        return [c for c in self.contacts.values() if c.verified]

    def __len__(self):
        return len(self.contacts)

    def __iter__(self):
        return iter(self.contacts.values())

    def __contains__(self, uuid):
        return str(uuid) in self.contacts or str(uuid) in self._device_of

    # -- cross-runtime canonical form -------------------------------------
    # The on-disk shape is the DRY canonical form (flat, C-parseable), NOT the
    # default config __type__ encoder: a contacts.cfg.json written by the C twin
    # (contacts/store.c) must load here and vice versa. See Contact.to_canonical.
    def to_canonical(self) -> dict:
        d = {
            'typename': CONTACTS_TYPENAME,
            'version': CONTACTS_VERSION,
            'contacts': {uuid: c.to_canonical()
                         for uuid, c in self.contacts.items()},
        }
        # Only once something was removed, so an older store stays
        # byte-identical.
        if self.tombstones:
            d['tombstones'] = {u: float(t) for u, t in self.tombstones.items()}
        return d

    @classmethod
    def from_canonical(cls, d: dict) -> 'Contacts':
        contacts = {}
        for uuid, cd in (d.get('contacts') or {}).items():
            contact = Contact.from_canonical(cd)
            if contact is not None:
                # Key by the contact's own UUID, not the map key, so a crafted
                # file cannot file a contact under the wrong identity.
                contacts[str(contact.uuid)] = contact
        return cls(contacts, _tombstones(d.get('tombstones'), contacts))

    # -- persistence ------------------------------------------------------
    @classmethod
    def default_path(cls, data_dir=None) -> str:
        data_dir = data_dir or cls.get_data_dir()
        return os.path.join(data_dir, cls.default_filename + cls.file_ext)

    @classmethod
    def load(cls, data_dir=None) -> 'Contacts':
        """Load from disk, returning an empty store if no file exists yet.

        A brand-new install has no contacts file; that is the normal first-run
        state, not an error -- so a missing file yields an empty store rather
        than raising, and the first :meth:`save` creates it.
        """
        path = cls.default_path(data_dir)
        if not os.path.exists(path):
            return cls()
        with open(path, 'r') as fh:
            return cls.from_canonical(json.load(fh))

    def save(self, data_dir=None) -> str:
        """Atomically write the store, creating the data directory if needed."""
        path = self.default_path(data_dir)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with atomic_write(path) as fh:
            json.dump(self.to_canonical(), fh, indent=2, sort_keys=True)
        return path


def is_uuid(v) -> bool:
    """Whether ``v`` is a uuid in its canonical lowercase text form."""
    return isinstance(v, str) and len(v) == 36 \
        and all(c in '0123456789abcdef-' for c in v)


def _tombstones(v, contacts):
    """The stored tombstones that are well formed: a lowercase uuid key, a
    non-negative time, and no live contact under the same uuid."""
    out = {}
    for uuid, at in (v.items() if isinstance(v, dict) else ()):
        if is_uuid(uuid) and uuid not in contacts and not isinstance(at, bool) \
                and isinstance(at, (int, float)) and math.isfinite(at) and at >= 0:
            out[uuid] = float(at)
    return out
