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
"""This user's own other devices (FIRST_CONTACT_PLAN Phase 4, live pairing).

A sibling is another node whose device cert names the same operator key as
this node's own cert (:mod:`.device`). Siblings share one address book
(:mod:`.sync`), so they are kept apart from it, in
``<data_dir>/siblings.cfg.json``:

    {typename: "siblings", version: 1, operator: <hex>,
     devices: [<Device canonical form> + optional rendezvous, reach_seq]}

and never appear as contacts: contact lists, the tier cap and the directory
do not see them. The file is plain JSON in the user's data dir, so on load a
device is kept only if its cert still verifies for its identity under the
stored operator key. Same format and rules as C's ``contacts/siblings.{h,c}``.
"""
import json
import os

from ..config.configuration import Configuration, atomic_write
from .contact import _operator_key
from .device import Device, DeviceCert, InvalidDevice, DEVICES_MAX

SIBLINGS_TYPENAME = 'siblings'
SIBLINGS_VERSION = 1
SIBLINGS_FILENAME = 'siblings'


class Siblings:
    """The operator key this node's cert names, and the other devices it has
    paired with under that key (at most :data:`.device.DEVICES_MAX`)."""

    def __init__(self, operator='', devices=None, hints=None, reach_seq=None):
        self.operator = operator or ''
        self.devices = list(devices or [])
        # Per sibling uuid: where it was last reached (most recent first), and
        # the highest reachability-record seq applied -- as a contact keeps
        # them (contacts/reach.py). Stored only once set.
        self.hints = dict(hints or {})
        self.reach_seq = dict(reach_seq or {})

    def set_hints(self, uuid, hints):
        self.hints[str(uuid)] = [h for h in hints if isinstance(h, str) and h][:4]

    def uuids(self):
        return [d.uuid for d in self.devices]

    def get(self, uuid):
        uuid = str(uuid)
        for dev in self.devices:
            if dev.uuid == uuid:
                return dev
        return None

    def __contains__(self, uuid):
        return self.get(uuid) is not None

    def __len__(self):
        return len(self.devices)

    def add(self, identity, cert, own_cert) -> str:
        """Pair with the node ``identity``, whose device cert is ``cert``.
        ``own_cert`` is this node's. Returns '' on success (pairing a known
        sibling again included), else a reason from :data:`.device.REASONS`:

          - ``unknown_operator``: this node has no cert of its own, so there
            is no operator to be a sibling under;
          - ``malformed`` / ``bad_signature``: ``cert`` is no good;
          - ``mismatch``: it does not name ``identity``, or names another
            operator than ours;
          - ``known``: ``identity`` is this node;
          - ``full``: already :data:`.device.DEVICES_MAX` siblings.

        A new operator on this node's own cert starts the list over: its old
        siblings were someone else's devices, as far as this cert says.
        """
        try:
            own = own_cert if isinstance(own_cert, DeviceCert) \
                else DeviceCert.from_wire(own_cert)
            own.verify()
        except (InvalidDevice, TypeError):
            return 'unknown_operator'
        try:
            cert = cert if isinstance(cert, DeviceCert) else DeviceCert.from_wire(cert)
            cert.verify()
        except InvalidDevice as err:
            return err.reason
        if not cert.names(identity) or cert.operator != own.operator:
            return 'mismatch'
        if str(identity.uuid).lower() == own.uuid:
            return 'known'
        if self.operator != own.operator:
            self.operator, self.devices = own.operator, []
            self.hints, self.reach_seq = {}, {}
        if self.get(identity.uuid) is not None:
            return ''
        if len(self.devices) >= DEVICES_MAX:
            return 'full'
        self.devices.append(Device(identity, cert))
        return ''

    def remove(self, uuid) -> bool:
        before = len(self.devices)
        self.devices = [d for d in self.devices if d.uuid != str(uuid)]
        self.hints.pop(str(uuid), None)
        self.reach_seq.pop(str(uuid), None)
        return len(self.devices) != before

    def _device_canonical(self, dev):
        d = dev.to_canonical()
        if self.hints.get(dev.uuid):
            d['rendezvous'] = list(self.hints[dev.uuid])
        if self.reach_seq.get(dev.uuid):
            d['reach_seq'] = int(self.reach_seq[dev.uuid])
        return d

    # -- cross-runtime canonical form -------------------------------------
    def to_canonical(self) -> dict:
        return {'typename': SIBLINGS_TYPENAME, 'version': SIBLINGS_VERSION,
                'operator': self.operator,
                'devices': [self._device_canonical(d) for d in self.devices]}

    @classmethod
    def from_canonical(cls, d) -> 'Siblings':
        if not isinstance(d, dict) or d.get('typename') != SIBLINGS_TYPENAME:
            return cls()
        operator = _operator_key(d.get('operator'))
        out, seen, hints, seqs = [], set(), {}, {}
        for rec in (d.get('devices') or []) if operator else []:
            dev = Device.from_canonical(rec)
            if dev is not None and dev.cert.operator == operator \
                    and dev.uuid not in seen and len(out) < DEVICES_MAX:
                seen.add(dev.uuid)
                out.append(dev)
                rv = rec.get('rendezvous')
                if isinstance(rv, list):
                    kept = [h for h in rv if isinstance(h, str) and h][:4]
                    if kept:
                        hints[dev.uuid] = kept
                seq = rec.get('reach_seq')
                if isinstance(seq, int) and not isinstance(seq, bool) and seq > 0:
                    seqs[dev.uuid] = seq
        return cls(operator, out, hints, seqs)

    # -- persistence ------------------------------------------------------
    @classmethod
    def default_path(cls, data_dir=None) -> str:
        data_dir = data_dir or Configuration.get_data_dir()
        return os.path.join(data_dir, SIBLINGS_FILENAME + Configuration.file_ext)

    @classmethod
    def load(cls, data_dir=None) -> 'Siblings':
        """Load from disk; no file (the normal state before pairing) or an
        unreadable one yields no siblings."""
        try:
            with open(cls.default_path(data_dir)) as fh:
                return cls.from_canonical(json.load(fh))
        except (OSError, ValueError):
            return cls()

    def save(self, data_dir=None) -> str:
        path = self.default_path(data_dir)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with atomic_write(path) as fh:
            json.dump(self.to_canonical(), fh, indent=2, sort_keys=True)
        return path
