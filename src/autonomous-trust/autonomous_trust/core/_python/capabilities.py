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

from collections.abc import Mapping
import multiprocessing

from .config import Configuration
from autonomous_trust.core.protobuf.processes import capabilities_pb2

# Strict bounds on capability-descriptor fields received over the wire
# (caps_response). A descriptor is untrusted peer input, so cap every string
# and collection to keep a malicious or buggy peer from inflating memory /
# slowing parsing / overwhelming a UI. Oversized values are truncated/dropped
# rather than rejecting the whole descriptor (the name + required_tier still
# carry useful directory info). See PIV_MFA_OPERATOR_ACCESS_PLAN.md §3.5/§8.
MAX_DESCRIPTION_LEN = 256
MAX_KIND_LEN = 32
MAX_ARG_SCHEMA_ENTRIES = 32
MAX_ARG_KEY_LEN = 64
MAX_ARG_VALUE_LEN = 64


def sanitize_descriptor(descriptor: dict) -> dict:
    """Clamp an untrusted capability descriptor to the size bounds above.

    Returns a new dict with only the recognized keys, each bounded. Unknown
    keys are dropped. ``name`` is intentionally not included (the caller keys
    by it).
    """
    clean: dict = {}
    if not isinstance(descriptor, dict):
        return clean
    rt = descriptor.get('required_tier')
    if isinstance(rt, bool):
        rt = None  # don't accept bools-as-ints
    if isinstance(rt, int):
        clean['required_tier'] = rt
    desc = descriptor.get('description')
    if isinstance(desc, str) and desc:
        clean['description'] = desc[:MAX_DESCRIPTION_LEN]
    kind = descriptor.get('kind')
    if isinstance(kind, str) and kind:
        clean['kind'] = kind[:MAX_KIND_LEN]
    schema = descriptor.get('arg_schema')
    if isinstance(schema, dict) and schema:
        bounded = {}
        for k, v in list(schema.items())[:MAX_ARG_SCHEMA_ENTRIES]:
            if not isinstance(k, str):
                continue
            bounded[k[:MAX_ARG_KEY_LEN]] = (
                v[:MAX_ARG_VALUE_LEN] if isinstance(v, str) else v)
        if bounded:
            clean['arg_schema'] = bounded
    return clean


class Capability(Configuration):
    """Name and function"""
    _msg_class = capabilities_pb2.Capability

    def __init__(self, name, function=None, arg_names=None, keywords=None,
                 required_tier: int = 0, transaction_weight: int = 1,
                 description: str = '', kind: str = '', arg_schema=None):
        super().__init__(capabilities_pb2.Capability)
        self.name = name
        self.function = function  # this will be None for remote handling
        self.arg_names = arg_names
        self.keywords = keywords
        # Trust-tier metadata. See doc/architecture/trust-tiers.md §4.
        # required_tier is the minimum peer._tier needed to invoke this
        # capability (0 = any admitted peer). transaction_weight is the
        # multiplier applied in _pure_reputation to TSs from tasks using
        # this capability (1 = no boost).
        self.required_tier = required_tier
        self.transaction_weight = transaction_weight
        # Operator-console descriptor metadata (PIV_MFA_OPERATOR_ACCESS_PLAN.md
        #). Runtime-only and NOT serialized -- like arg_names/keywords,
        # these are cleared by sync_from_message and have no wire form, so they
        # don't touch the Python<->C conformance corpus. The operator's local
        # registry carries them so its resource directory is self-describing;
        # broadcasting them on caps_response is a separate, conformance-gated
        # follow-up. kind is a ResourceKind value (compute/data_stream/service).
        self.description = description
        self.kind = kind
        self.arg_schema = arg_schema

    def execute(self, task, pid_q):
        pid_q.put_nowait(multiprocessing.current_process().pid)
        try:
            return self.function(*task.parameters.args, **task.parameters.kwargs)
        except Exception as e:
            raise RuntimeError('Capability %r execution failed for task %s: %s' % (self.name, task.uuid, e)) from e

    def __eq__(self, other):
        return self.name == other.name

    def to_dict(self):
        # Intentionally minimal — `to_dict` is for log/repr surfaces; the
        # cross-impl wire form is the protobuf `Capability` message
        # (capabilities.proto / sync_to_message). `arg_names` and
        # `keywords` are runtime-only fields cleared by sync_from_message,
        # so they have no meaningful serialized representation. See
        # divergence.md H15 (re-audit) for the unified C-side equivalent
        # via `capability_t.arguments`.
        return dict(name=self.name,
                    required_tier=self.required_tier,
                    transaction_weight=self.transaction_weight)

    def sync_to_message(self):
        self.message.name = self.name
        self.message.category = ''
        self.message.required_tier = self.required_tier
        self.message.transaction_weight = self.transaction_weight

    def sync_from_message(self):
        self.name = self.message.name
        self.function = None
        self.arg_names = None
        self.keywords = None
        # Descriptor metadata is runtime-only / not on the wire (see __init__).
        self.description = ''
        self.kind = ''
        self.arg_schema = None
        self.required_tier = int(self.message.required_tier)
        # proto3 can't distinguish "not set" from 0; treat 0 as the
        # default weight (1) so peers without the field interoperate.
        w = int(self.message.transaction_weight)
        self.transaction_weight = w if w > 0 else 1


class Capabilities(Mapping):
    """Mapping of name to Capability"""
    def __init__(self):
        self._listing = {}

    def __len__(self):
        return len(self._listing)

    def __iter__(self):
        return self._listing.__iter__()

    def __getitem__(self, key):
        return self._listing[key]

    def __contains__(self, item):
        return item in self._listing.values()

    def to_list(self) -> list[str]:
        return [cap.name for cap in self._listing.values()]

    def register_ability(self, name, function, arg_names=None, keywords=None,
                         required_tier: int = 0, transaction_weight: int = 1,
                         description: str = '', kind: str = '', arg_schema=None):
        self._listing[name] = Capability(name, function, arg_names, keywords,
                                         required_tier=required_tier,
                                         transaction_weight=transaction_weight,
                                         description=description, kind=kind,
                                         arg_schema=arg_schema)


class PeerCapabilities(Mapping, Configuration):
    """Mapping of capability names to peer ids"""
    _msg_class = capabilities_pb2.PeerCapabilities

    def __init__(self, _listing=None):
        super().__init__(capabilities_pb2.PeerCapabilities)
        self._listing = _listing
        if _listing is None:
            self._listing = {}
        # Optional per-capability descriptors {cap_name: {required_tier,
        # description, kind, arg_schema}} learned from caps_response. Runtime-
        # only and NOT serialized (excluded from sync_to/from_message and from
        # the persisted peer-capabilities.cfg.json), so the protobuf/persist
        # wire form is unchanged. It rides the intra-node pickle hop
        # (idprocess -> main) for free; inter-node, descriptors travel in the
        # JSON caps_response payload (PIV_MFA_OPERATOR_ACCESS_PLAN.md §3.5).
        self.descriptors: dict = {}

    def __len__(self):
        return len(self._listing)

    def __iter__(self):
        return self._listing.__iter__()

    def __getitem__(self, key):
        return self._listing[key]

    def register(self, peer_id, caps: list[str]):
        for name in caps:
            if name not in self._listing:
                self._listing[name] = []
            self._listing[name].append(peer_id)

    def register_descriptor(self, name: str, descriptor: dict):
        """Record an optional capability descriptor learned from caps_response.

        The descriptor is **untrusted peer input**, so it is size-bounded via
        `sanitize_descriptor` before storage. Idempotent / last-writer-wins (the
        descriptor is a property of the capability, not the provider). An empty
        descriptor (or one that sanitizes to nothing) is ignored so a legacy
        name-only advertisement never clobbers a known descriptor.
        """
        if not descriptor:
            return
        clean = sanitize_descriptor(descriptor)
        if clean:
            self.descriptors[name] = clean

    def filtered_for_persist(self, keep_uuids):
        """Return a copy with peer-ids not in keep_uuids removed.

        Capability names with no remaining peers after the filter are
        dropped entirely. Used by the persistent-cohort save path so
        untrusted (rep<=0.5) peers' capability advertisements don't
        survive a process restart.
        """
        keep = {str(u) for u in keep_uuids}
        new_listing = {}
        for cap_name, peer_ids in self._listing.items():
            kept = [pid for pid in peer_ids if str(pid) in keep]
            if kept:
                new_listing[cap_name] = kept
        return PeerCapabilities(_listing=new_listing)

    def to_dict(self):
        # `descriptors` is runtime-only metadata learned from caps_response; it
        # is intentionally absent from both the protobuf wire form and the
        # persisted peer-capabilities.cfg.json. Drop it here so the JSON persist
        # path (ConfigJSONEncoder -> to_dict) and the reload path (cls(**kwargs),
        # which only accepts `_listing`) stay symmetric.
        d = super().to_dict()
        d.pop('descriptors', None)
        return d

    def sync_to_message(self):
        # Invert Python's {cap_name: [peer_ids]} to proto's {peer: [capabilities]}
        peer_caps = {}
        for cap_name, peer_ids in self._listing.items():
            for pid in peer_ids:
                peer_key = str(pid)
                if peer_key not in peer_caps:
                    peer_caps[peer_key] = []
                peer_caps[peer_key].append(cap_name)
        del self.message.listing[:]
        for peer, cap_names in peer_caps.items():
            entry = self.message.listing.add()
            entry.peer = peer
            for cn in cap_names:
                cap = entry.capability.add()
                cap.name = cn
                cap.category = ''

    def sync_from_message(self):
        # Invert proto's {peer: [capabilities]} back to Python's {cap_name: [peer_ids]}
        self._listing = {}
        # Descriptors are runtime-only (not on the wire); ensure the attribute
        # exists on objects reconstructed via from_wire_bytes (which bypasses
        # __init__).
        self.descriptors = {}
        for entry in self.message.listing:
            for cap in entry.capability:
                if cap.name not in self._listing:
                    self._listing[cap.name] = []
                self._listing[cap.name].append(entry.peer)
