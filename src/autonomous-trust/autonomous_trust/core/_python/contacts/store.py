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
import os

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

    def __init__(self, contacts=None):
        super().__init__()
        # uuid_str -> Contact. dict(...) so a decoded mapping (config round-trip)
        # and a caller-supplied dict both work.
        self.contacts = dict(contacts or {})

    # -- membership -------------------------------------------------------
    def add(self, contact: Contact) -> Contact:
        """Add or replace a contact (keyed by UUID). Returns the stored contact."""
        self.contacts[str(contact.uuid)] = contact
        return contact

    def get(self, uuid) -> Contact:
        return self.contacts.get(str(uuid))

    def by_petname(self, petname: str) -> Contact:
        for contact in self.contacts.values():
            if contact.petname == petname:
                return contact
        return None

    def by_nickname(self, nickname: str):
        """All contacts asserting this ONLINE nickname (not unique, so a list)."""
        return [c for c in self.contacts.values() if c.nickname == nickname]

    def remove(self, uuid) -> bool:
        return self.contacts.pop(str(uuid), None) is not None

    def all(self):
        return list(self.contacts.values())

    def verified(self):
        return [c for c in self.contacts.values() if c.verified]

    def __len__(self):
        return len(self.contacts)

    def __iter__(self):
        return iter(self.contacts.values())

    def __contains__(self, uuid):
        return str(uuid) in self.contacts

    # -- cross-runtime canonical form -------------------------------------
    # The on-disk shape is the DRY canonical form (flat, C-parseable), NOT the
    # default config __type__ encoder: a contacts.cfg.json written by the C twin
    # (contacts/store.c) must load here and vice versa. See Contact.to_canonical.
    def to_canonical(self) -> dict:
        return {
            'typename': CONTACTS_TYPENAME,
            'version': CONTACTS_VERSION,
            'contacts': {uuid: c.to_canonical()
                         for uuid, c in self.contacts.items()},
        }

    @classmethod
    def from_canonical(cls, d: dict) -> 'Contacts':
        contacts = {}
        for uuid, cd in (d.get('contacts') or {}).items():
            contact = Contact.from_canonical(cd)
            if contact is not None:
                # Key by the contact's own UUID, not the map key, so a crafted
                # file cannot file a contact under the wrong identity.
                contacts[str(contact.uuid)] = contact
        return cls(contacts)

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
