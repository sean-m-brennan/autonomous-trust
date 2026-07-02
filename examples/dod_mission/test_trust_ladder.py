# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
#  Licensed under the Apache License, Version 2.0
# ******************
"""Tests for the DoD demo trust-ladder loader.

Run from the repo root:
    pytest examples/dod_mission/test_trust_ladder.py
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from autonomous_trust.core.capabilities import Capabilities

from examples.dod_mission.trust_ladder import (
    CapMeta, _DOD_CAP_NAMES, load_trust_ladder, register_trust_ladder,
)


def test_load_returns_all_dod_caps():
    ladder = load_trust_ladder()
    for name in _DOD_CAP_NAMES:
        assert name in ladder, f'{name!r} missing from YAML'
        meta = ladder[name]
        assert isinstance(meta, CapMeta)
        assert meta.required_tier >= 0
        assert meta.transaction_weight >= 1


def test_load_tier_weight_mapping_matches_spec():
    # Pinned against dod-demo-implementation-plan.md §Phase 6 / scope #1.
    ladder = load_trust_ladder()
    assert ladder['dod.network-presence'].required_tier == 1
    assert ladder['dod.network-presence'].transaction_weight == 2
    assert ladder['dod.sensor-report'].required_tier == 2
    assert ladder['dod.sensor-report'].transaction_weight == 4
    assert ladder['dod.fusion-validate'].required_tier == 3
    assert ladder['dod.fusion-validate'].transaction_weight == 8
    assert ladder['dod.command-issue'].required_tier == 4
    assert ladder['dod.command-issue'].transaction_weight == 8


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
    assert sorted(caps.to_list()) == sorted(_DOD_CAP_NAMES)


def test_disabled_env_skips_registration(monkeypatch):
    monkeypatch.setenv('AT_DOD_TRUST_LADDER_DISABLED', '1')
    caps = Capabilities()
    out = register_trust_ladder(caps)
    assert out == {}
    assert list(caps.to_list()) == []
