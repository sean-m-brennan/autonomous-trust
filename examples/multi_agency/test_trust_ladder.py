# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
#  Licensed under the Apache License, Version 2.0
# ******************
"""Tests for the multi-agency demo trust-ladder loader.

Run from the repo root:
    pytest examples/multi_agency/test_trust_ladder.py

Mirror of examples/dod_mission/test_trust_ladder.py; kept separate so
each demo can iterate on its own capability set.
"""

from __future__ import annotations

import os

from autonomous_trust.core.capabilities import Capabilities

from examples.multi_agency.trust_ladder import (
    CapMeta, _MULTI_CAP_NAMES, load_trust_ladder, register_trust_ladder,
)


def test_load_returns_all_multi_caps():
    ladder = load_trust_ladder()
    for name in _MULTI_CAP_NAMES:
        assert name in ladder, f'{name!r} missing from YAML'
        meta = ladder[name]
        assert isinstance(meta, CapMeta)
        assert meta.required_tier >= 0
        assert meta.transaction_weight >= 1


def test_load_tier_weight_mapping_matches_spec():
    # Pinned against dod-demo-implementation-plan.md §Phase 6 multi-agency
    # port (this file's design notes alongside trust_ladder.yaml).
    ladder = load_trust_ladder()
    assert ladder['multi.network-presence'].required_tier == 1
    assert ladder['multi.network-presence'].transaction_weight == 2
    assert ladder['multi.sensor-report'].required_tier == 2
    assert ladder['multi.sensor-report'].transaction_weight == 4
    assert ladder['multi.fusion-validate'].required_tier == 3
    assert ladder['multi.fusion-validate'].transaction_weight == 8
    assert ladder['multi.coordinate'].required_tier == 4
    assert ladder['multi.coordinate'].transaction_weight == 8


def test_register_populates_capabilities():
    caps = Capabilities()
    ladder = register_trust_ladder(caps)
    assert ladder, 'register returned empty ladder'
    for name, meta in ladder.items():
        cap = caps[name]
        assert cap.required_tier == meta.required_tier
        assert cap.transaction_weight == meta.transaction_weight
        # Metadata-only registration: function should be None.
        assert cap.function is None


def test_register_idempotent():
    caps = Capabilities()
    a = register_trust_ladder(caps)
    b = register_trust_ladder(caps)
    assert a == b
    # Same keys, no duplicate entries.
    assert sorted(caps.to_list()) == sorted(_MULTI_CAP_NAMES)


def test_disabled_env_skips_registration(monkeypatch):
    monkeypatch.setenv('AT_MULTI_TRUST_LADDER_DISABLED', '1')
    caps = Capabilities()
    out = register_trust_ladder(caps)
    assert out == {}
    assert list(caps.to_list()) == []
