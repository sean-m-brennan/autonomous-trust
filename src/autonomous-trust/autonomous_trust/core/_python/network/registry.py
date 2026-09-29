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
"""The directory registry: an opt-in role on a relay (FIRST_CONTACT_PLAN
Phase 3). ``AT_REGISTRY=1`` on a node that also serves as a relay.

It holds directory entries (contacts/directory.py) filed by the relay's own
registrants and answers one-handle-at-a-time lookups, over the relay's
existing TCP link, whose two-way signed registration already proved who each
client is. Ops (one JSON frame each, as the relay's)::

    client -> registry  {"op": "dir_publish", "entry": {body, sig}}
    registry -> client  {"op": "dir_published", "handle": H, "seq": N}
                      | {"op": "dir_refused", "handle": H, "reason": R}
    client -> registry  {"op": "dir_withdraw", "handle": H}
    registry -> client  {"op": "dir_withdrawn", "handle": H}
    client -> registry  {"op": "dir_lookup", "handle": H}
    registry -> client  {"op": "dir_entry", "handle": H, "entry": {body, sig} | null}
                      | {"op": "dir_limited", "handle": H}

What bounds it: an entry is filed only from the registered holder of its key,
only with an attestation from an issuer this registry trusts
(``<cfg_dir>/registry_issuers.cfg.json``: ``{"issuers": [hex key, ...]}``),
and only over a lower ``seq``. A lookup names one handle; past the rate limit
(``AT_REGISTRY_RATE`` a minute per client uuid, default 10) the answer is
``dir_limited``. An entry whose visibility is ``published`` is shown only to a
client that has an entry here itself; to anyone else, and for a holder this
node has come to distrust, the answer is the same ``null`` as for a handle
nobody filed. Entries live in memory: a restarted registry is refilled as its
registrants re-register. Same ops and rules as C's
``network/net_registry.{h,c}``.
"""
import json
import logging
import os
import threading
import time

from ..config.configuration import Configuration
from ..contacts import directory as _dir

_logger = logging.getLogger(__name__)

ISSUERS_FILE = 'registry_issuers.cfg.json'
RATE_ENV = 'AT_REGISTRY_RATE'
#: Lookups a client may make per minute, by default. Same as C's.
DEFAULT_RATE = 10
#: Most entries one registry holds; past it expired ones go first, then the
#: soonest to expire. Same as C's AT_REGISTRY_MAX_ENTRIES.
MAX_ENTRIES = 4096


def registry_enabled() -> bool:
    """True iff this node serves as a registry (``AT_REGISTRY``). Only
    meaningful on a node that is also a relay."""
    return os.environ.get('AT_REGISTRY', '').strip().lower() in ('1', 'true', 'yes', 'on')


def lookup_rate() -> int:
    try:
        rate = int(os.environ.get(RATE_ENV, '') or DEFAULT_RATE)
    except ValueError:
        return DEFAULT_RATE
    return rate if rate > 0 else DEFAULT_RATE


def load_issuers(path=None):
    """The trusted issuer keys (lower-case hex) from ``path`` (default
    ``<cfg_dir>/registry_issuers.cfg.json``). Missing or unreadable -> empty,
    logged: a registry with no issuers files nothing."""
    path = path or os.path.join(Configuration.get_cfg_dir(), ISSUERS_FILE)
    try:
        with open(path) as f:
            issuers = json.load(f).get('issuers', [])
    except FileNotFoundError:
        _logger.warning('Registry: no %s; no entry can be filed', path)
        return frozenset()
    except (OSError, ValueError, AttributeError) as exc:
        _logger.warning('Registry: cannot read %s (%s); no entry can be filed', path, exc)
        return frozenset()
    keys = {str(k).lower() for k in issuers if isinstance(k, str) and _dir._is_hex_key(k.lower())}
    if len(keys) != len(issuers):
        _logger.warning('Registry: %s lists %d entries that are not hex keys; skipped',
                        path, len(issuers) - len(keys))
    return frozenset(keys)


class Registry:
    """Directory entries and the rate limits on reading them."""

    def __init__(self, issuers, rate=None, distrusted=None, clock=time.monotonic,
                 wallclock=time.time, logger=None):
        self.issuers = frozenset(issuers)
        self.rate = rate or lookup_rate()
        self.distrusted = distrusted
        self.clock = clock
        self.wallclock = wallclock
        self.logger = logger or _logger
        self._entries = {}          # handle -> DirectoryEntry
        self._buckets = {}          # uuid -> (tokens, last)
        self._lock = threading.Lock()

    def publish(self, uuid, pubkey, wire):
        """File ``uuid``'s entry. Returns the reply frame."""
        handle = ''
        try:
            entry = _dir.DirectoryEntry.from_wire(wire)
            handle = entry.handle if isinstance(entry.handle, str) else ''
            entry.verify(self.issuers, self.wallclock())
        except _dir.InvalidEntry as err:
            return {'op': 'dir_refused', 'handle': handle, 'reason': err.reason}
        # Only the holder files: the registrant proved its key, and the entry
        # must be signed by that same key, for that same uuid.
        if entry.key != pubkey or entry.uuid != uuid:
            return {'op': 'dir_refused', 'handle': handle, 'reason': 'not_holder'}
        with self._lock:
            held = self._entries.get(handle)
            if held is not None and held.key != entry.key \
                    and not held.is_expired(self.wallclock()):
                # Two holders cannot both prove one handle unless an issuer
                # attested it twice; the first stands until it expires.
                return {'op': 'dir_refused', 'handle': handle, 'reason': 'taken'}
            if held is not None and held.key == entry.key:
                if entry.seq == held.seq and entry.body_str == held.body_str:
                    return {'op': 'dir_published', 'handle': handle, 'seq': entry.seq}
                if entry.seq <= held.seq:
                    return {'op': 'dir_refused', 'handle': handle, 'reason': 'stale'}
            if held is None and len(self._entries) >= MAX_ENTRIES:
                self._evict_locked()
            self._entries[handle] = entry
        self.logger.info('Registry: %s filed %s (seq %d)', uuid[:8], handle, entry.seq)
        return {'op': 'dir_published', 'handle': handle, 'seq': entry.seq}

    def withdraw(self, uuid, pubkey, handle):
        handle = _dir.normalize_handle(handle) or ''
        with self._lock:
            held = self._entries.get(handle)
            if held is not None and held.key == pubkey and held.uuid == uuid:
                del self._entries[handle]
        return {'op': 'dir_withdrawn', 'handle': handle}

    def _take_token(self, uuid):
        now = self.clock()
        with self._lock:
            tokens, last = self._buckets.get(uuid, (float(self.rate), now))
            tokens = min(float(self.rate), tokens + (now - last) * self.rate / 60.0)
            if tokens < 1.0:
                self._buckets[uuid] = (tokens, now)
                return False
            self._buckets[uuid] = (tokens - 1.0, now)
            return True

    def _is_published(self, uuid):
        return any(e.uuid == uuid for e in self._entries.values())

    def lookup(self, uuid, handle):
        """``uuid``'s lookup of ``handle``. Returns the reply frame."""
        folded = _dir.normalize_handle(handle) or ''
        if not self._take_token(uuid):
            return {'op': 'dir_limited', 'handle': folded}
        with self._lock:
            entry = self._entries.get(folded)
            if entry is not None and entry.visibility == _dir.VISIBILITY_PUBLISHED \
                    and not self._is_published(uuid):
                entry = None
        if entry is not None and entry.is_expired(self.wallclock()):
            entry = None
        if entry is not None and self.distrusted is not None \
                and self.distrusted(entry.uuid, entry.key):
            entry = None
        return {'op': 'dir_entry', 'handle': folded,
                'entry': entry.to_wire() if entry is not None else None}

    def _evict_locked(self):
        now = self.wallclock()
        for handle in [h for h, e in self._entries.items() if e.is_expired(now)]:
            del self._entries[handle]
        if len(self._entries) >= MAX_ENTRIES:
            soonest = min(self._entries, key=lambda h: self._entries[h].expiry)
            del self._entries[soonest]
