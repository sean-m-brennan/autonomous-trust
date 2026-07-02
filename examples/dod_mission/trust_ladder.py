# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
#  Licensed under the Apache License, Version 2.0
# ******************
"""DoD demo trust-ladder loader.

Parses ``trust_ladder.yaml`` and exposes a small surface so the
coordinator and participants can register the DoD-specific
capabilities consistently. See ``trust_ladder.yaml`` for the
authoritative mapping; the loader's job is just to apply it.

The ladder is metadata-only — `register_trust_ladder(capabilities)`
calls `capabilities.register_ability(name, function=None, ...)` for
each DoD entry, which is exactly what
``examples/dod_mission/participant.py`` already does for the `data`
capability. The negotiation pipeline and weighted-reputation math
pick up the metadata via the standard cap-lookup path
(``_resolve_tx_weight``, ``handle_invite``).
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path

from ruamel.yaml import YAML

_yaml = YAML(typ='safe')


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CapMeta:
    name: str
    required_tier: int
    transaction_weight: int


# DoD ladder entries (the bootstrap stanza in the YAML is informational —
# bootstrap_capabilities.py owns the registration of at.* and they should
# not be re-registered here).
_DOD_CAP_NAMES = (
    'dod.network-presence',
    'dod.sensor-report',
    'dod.fusion-validate',
    'dod.command-issue',
)


def _default_ladder_path() -> Path:
    return Path(__file__).resolve().parent / 'trust_ladder.yaml'


def load_trust_ladder(path: Path | None = None) -> dict[str, CapMeta]:
    """Parse the trust ladder YAML and return a dict keyed by cap name.

    Returns the DoD entries only (the bootstrap stanza is documented in
    the YAML for visibility but is registered by the AT core, not by
    this loader). Raises FileNotFoundError if the YAML is missing —
    the demo cannot function without it.
    """
    ladder_path = path or _default_ladder_path()
    with ladder_path.open('r') as fh:
        data = _yaml.load(fh) or {}
    dod_entries = (data.get('dod') or {})
    out: dict[str, CapMeta] = {}
    for name, fields in dod_entries.items():
        if name not in _DOD_CAP_NAMES:
            logger.warning(
                'trust_ladder: unknown DoD capability %r — ignoring; '
                'expected one of %s', name, _DOD_CAP_NAMES)
            continue
        try:
            out[name] = CapMeta(
                name=name,
                required_tier=int(fields.get('required_tier', 0)),
                transaction_weight=int(fields.get('transaction_weight', 1)),
            )
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f'trust_ladder: malformed entry for {name!r}: {exc}'
            ) from exc
    missing = [n for n in _DOD_CAP_NAMES if n not in out]
    if missing:
        # Don't hard-fail — `dod.command-issue` is scaffolded today, and
        # forcing a YAML to ship every name would make split-rollout
        # awkward. Just log so an accidental drop is visible.
        logger.warning(
            'trust_ladder: missing DoD entries %s (continuing without)',
            missing)
    return out


def register_trust_ladder(capabilities,
                          path: Path | None = None) -> dict[str, CapMeta]:
    """Register every DoD cap on ``capabilities`` as a metadata-only
    Capability (function=None). Returns the loaded ladder so callers
    can use it directly (e.g. to tag TSs with the matching cap name
    without re-parsing the YAML).

    Idempotent — calling twice replaces the entries with identical
    metadata. Skips gracefully if AT_DOD_TRUST_LADDER_DISABLED=1
    (escape hatch for unit tests that want a quiet capability set).
    """
    if os.environ.get('AT_DOD_TRUST_LADDER_DISABLED') == '1':
        logger.info(
            'trust_ladder: AT_DOD_TRUST_LADDER_DISABLED=1, '
            'skipping registration')
        return {}
    ladder = load_trust_ladder(path)
    for name, meta in ladder.items():
        capabilities.register_ability(
            name, None,
            required_tier=meta.required_tier,
            transaction_weight=meta.transaction_weight,
        )
    logger.info(
        'trust_ladder: registered %d DoD capabilities: %s',
        len(ladder), sorted(ladder.keys()))
    return ladder
