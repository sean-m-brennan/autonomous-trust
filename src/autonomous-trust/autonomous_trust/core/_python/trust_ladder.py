# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
#  Licensed under the Apache License, Version 2.0
# ******************
"""Generic AT-core trust-ladder loader (doc/architecture/trust-tiers.md §8).

A scenario declares a ``trust_ladder.yaml`` alongside its ``scenario.yaml``,
mapping capability names to a required trust tier and a transaction weight and
parameterising the bootstrap worker. This module is the *generic* core-AT
loader the architecture doc calls for: it parses that YAML and registers the
capabilities onto a :class:`~autonomous_trust.core.capabilities.Capabilities`
mapping, so domain code never hard-codes tier or weight.

Schema — every field is optional and the documented defaults apply when
absent (§8: "everything tier 0, weight 1, bootstrap on")::

    version: 1
    bootstrap:
      enabled: true        # bootstrap corpus on/off
      duration_sec: 30
      pairs: 20
    capabilities:
      at.handshake:      { required_tier: 0, transaction_weight: 1 }
      dod.sensor-report: { required_tier: 2, transaction_weight: 4 }
    tier_demotion_epsilon: 0.02

Set ``AT_TRUST_LADDER`` to a YAML path to drive registration from config; with
nothing set, :func:`load_trust_ladder` returns the all-defaults ladder so the
mechanism is inert until a scenario opts in.

The DoD demo ships its own older loader (``examples/dod_mission/
trust_ladder.py``) that reads a ``dod:`` stanza variant; this core module is
the reusable mechanism §8 specifies for future scenarios and for
parameterising the bootstrap corpus from config rather than code.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Mapping, Optional, Union

from ruamel.yaml import YAML

_yaml = YAML(typ='safe')
logger = logging.getLogger(__name__)

# Documented defaults (trust-tiers §8).
DEFAULT_REQUIRED_TIER = 0
DEFAULT_TRANSACTION_WEIGHT = 1
DEFAULT_BOOTSTRAP_DURATION_SEC = 30
DEFAULT_BOOTSTRAP_PAIRS = 20
DEFAULT_TIER_DEMOTION_EPSILON = 0.02

# Env escape hatch: point at a trust_ladder.yaml to drive registration.
TRUST_LADDER_ENV = 'AT_TRUST_LADDER'

PathLike = Union[str, 'os.PathLike[str]', Path]


@dataclass(frozen=True)
class CapMeta:
    """Tier/weight metadata for a single capability."""
    name: str
    required_tier: int = DEFAULT_REQUIRED_TIER
    transaction_weight: int = DEFAULT_TRANSACTION_WEIGHT


@dataclass(frozen=True)
class BootstrapParams:
    """Bootstrap-worker parameters drawn from the ``bootstrap:`` stanza."""
    enabled: bool = True
    duration_sec: int = DEFAULT_BOOTSTRAP_DURATION_SEC
    pairs: int = DEFAULT_BOOTSTRAP_PAIRS


@dataclass(frozen=True)
class TrustLadder:
    """A parsed trust ladder: capability metadata plus bootstrap params."""
    capabilities: dict[str, CapMeta] = field(default_factory=dict)
    bootstrap: BootstrapParams = field(default_factory=BootstrapParams)
    tier_demotion_epsilon: float = DEFAULT_TIER_DEMOTION_EPSILON

    # Mapping-ish conveniences so callers can treat a ladder like the
    # capability dict it mostly is.
    def __getitem__(self, name: str) -> CapMeta:
        return self.capabilities[name]

    def __contains__(self, name: object) -> bool:
        return name in self.capabilities

    def __iter__(self):
        return iter(self.capabilities)

    def __len__(self) -> int:
        return len(self.capabilities)


def default_ladder() -> TrustLadder:
    """The all-defaults ladder used when no YAML is present (§8)."""
    return TrustLadder()


def _coerce_caps(raw: Optional[Mapping]) -> dict[str, CapMeta]:
    out: dict[str, CapMeta] = {}
    for name, fields in (raw or {}).items():
        fields = fields or {}
        try:
            out[name] = CapMeta(
                name=name,
                required_tier=int(
                    fields.get('required_tier', DEFAULT_REQUIRED_TIER)),
                transaction_weight=int(
                    fields.get('transaction_weight',
                               DEFAULT_TRANSACTION_WEIGHT)),
            )
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f'trust_ladder: malformed entry for {name!r}: {exc}'
            ) from exc
    return out


def load_trust_ladder(path: Optional[PathLike] = None) -> TrustLadder:
    """Parse a trust-ladder YAML into a :class:`TrustLadder`.

    With no ``path`` (and no ``AT_TRUST_LADDER`` env), returns the
    all-defaults ladder. An *explicit* missing path raises
    ``FileNotFoundError`` — the caller asked for a specific file. A missing
    env-pointed file falls back to defaults with a warning, so a
    misconfigured deployment degrades rather than crashes.
    """
    explicit = path is not None
    if path is None:
        env = os.environ.get(TRUST_LADDER_ENV)
        path = Path(env) if env else None
    if path is None:
        return default_ladder()
    path = Path(path)
    if not path.exists():
        if explicit:
            raise FileNotFoundError(f'trust_ladder: {path} not found')
        logger.warning('trust_ladder: %s=%s not found; using defaults',
                       TRUST_LADDER_ENV, path)
        return default_ladder()
    with path.open('r') as fh:
        data = _yaml.load(fh) or {}
    boot_raw = data.get('bootstrap') or {}
    try:
        bootstrap = BootstrapParams(
            enabled=bool(boot_raw.get('enabled', True)),
            duration_sec=int(
                boot_raw.get('duration_sec', DEFAULT_BOOTSTRAP_DURATION_SEC)),
            pairs=int(boot_raw.get('pairs', DEFAULT_BOOTSTRAP_PAIRS)),
        )
        epsilon = float(
            data.get('tier_demotion_epsilon', DEFAULT_TIER_DEMOTION_EPSILON))
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f'trust_ladder: malformed bootstrap/epsilon in {path}: {exc}'
        ) from exc
    return TrustLadder(
        capabilities=_coerce_caps(data.get('capabilities')),
        bootstrap=bootstrap,
        tier_demotion_epsilon=epsilon,
    )


def register_trust_ladder(
        capabilities,
        ladder: Union[TrustLadder, PathLike, None] = None,
        *,
        functions: Optional[Mapping[str, Callable]] = None) -> TrustLadder:
    """Register every capability in ``ladder`` onto ``capabilities``.

    ``ladder`` may be a :class:`TrustLadder`, a path, or ``None`` (load from
    ``AT_TRUST_LADDER`` / defaults). ``functions`` maps capability name to a
    server callable to attach (e.g. the bootstrap ``at.*`` handlers); names
    absent from the map register metadata-only (``function=None``), which is
    the right shape for remote-only domain capabilities. Returns the ladder.

    Idempotent — re-registering replaces entries with identical metadata.
    """
    if not isinstance(ladder, TrustLadder):
        ladder = load_trust_ladder(ladder)
    functions = functions or {}
    for name, meta in ladder.capabilities.items():
        capabilities.register_ability(
            name, functions.get(name),
            required_tier=meta.required_tier,
            transaction_weight=meta.transaction_weight,
        )
    logger.info('trust_ladder: registered %d capabilities: %s',
                len(ladder.capabilities), sorted(ladder.capabilities))
    return ladder
