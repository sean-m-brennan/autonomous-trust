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

"""Durable local moderation state: ``etc/at/social.cfg.json``.

Twin of C ``identity/social_store.{c,h}`` (Phase 4 P4.1).

WHY THIS EXISTS. Until P4.1 no social state was persisted at all -- the five
files ``doc/architecture/persistent-cohort.md`` lists do not include one, and
``connection_edges`` is equally in-memory. A block could live with that only for
as long as a block did nothing; now that it gates every inbound path, a restart
silently restoring a blocked peer's reach is a moderation failure, not a cache
miss. The person blocked someone and the daemon forgot.

THE TWO RUNTIMES MUST WRITE THIS FILE BYTE-IDENTICALLY for the same block set.
That is why ``sort_keys=True`` and ``indent=2`` are not cosmetic here, and why
``reason`` is always written even though nothing collects one yet: a key that
appeared only sometimes would make the files differ by whether anyone had typed
something. C writes the same document with
``JSON_INDENT(2) | JSON_SORT_KEYS``. A conformance case compares them.
"""

import json
import os

from ..config.configuration import atomic_write

#: The file, beside the other config documents in ``etc/at``.
SOCIAL_FILENAME = 'social.cfg.json'

#: Schema version written into the document.
#:
#: The shape is ``{"version": 1, "blocks": {"<uuid>": {"at": <epoch>,
#: "reason": ""}}}``. A MAP rather than an array so an unblock is a delete and a
#: rewrite is idempotent; a top-level ``blocks`` key beside ``version`` so box
#: 5's per-community content policy can add a sibling without a migration.
SOCIAL_STORE_VERSION = 1


def social_store_path(cfg_dir):
    """The document's path inside ``cfg_dir``."""
    return os.path.join(str(cfg_dir), SOCIAL_FILENAME)


def social_store_load(cfg_dir):
    """Load the block set, as ``{uuid_str: at_epoch_float}``.

    A missing file yields an empty store -- the ordinary first-boot case, not an
    error. A malformed document raises, and the caller decides; the C twin
    returns -1 and leaves the store empty for the same reason, so a corrupt file
    fails toward "nobody is blocked" rather than toward an arbitrary subset.
    """
    path = social_store_path(cfg_dir)
    if not os.path.exists(path):
        return {}
    with open(path, 'r') as f:
        doc = json.load(f)
    blocks = doc.get('blocks')
    if not isinstance(blocks, dict):
        raise ValueError('%s: no blocks object' % path)
    # The VERSION is read but not enforced: an older reader meeting a newer
    # document should keep the blocks it understands rather than discard
    # somebody's moderation state over a number.
    out = {}
    for uuid_str, entry in blocks.items():
        at = 0.0
        if isinstance(entry, dict):
            try:
                at = float(entry.get('at', 0.0))
            except (TypeError, ValueError):
                at = 0.0
        out[str(uuid_str)] = at
    return out


def social_store_save(blocks, cfg_dir):
    """Write @p blocks (``{uuid_str: at_epoch_float}``) to the document.

    Atomic, via :func:`atomic_write` -- a reader or a crash never sees a torn
    file. Called on every mutation rather than at shutdown, matching C: a block
    that survives only a graceful stop is not much of a block.
    """
    path = social_store_path(cfg_dir)
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    doc = {
        'version': SOCIAL_STORE_VERSION,
        'blocks': {
            str(uuid_str): {'at': float(at), 'reason': ''}
            for uuid_str, at in blocks.items()
        },
    }
    with atomic_write(path) as f:
        json.dump(doc, f, indent=2, sort_keys=True)
    return path
