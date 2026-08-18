# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
#  Licensed under the Apache License, Version 2.0
# ******************
"""Tests for the generic AT-core trust-ladder loader.

Run from the repo root:
    pytest src/autonomous-trust/tests/a_unit/test_trust_ladder.py
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from autonomous_trust.core.capabilities import Capabilities
from autonomous_trust.core.trust_ladder import (
    BootstrapParams, CapMeta, TrustLadder, default_ladder,
    load_trust_ladder, register_trust_ladder,
)
from autonomous_trust.core.bootstrap_capabilities import (
    BOOTSTRAP_FUNCTIONS, register_bootstrap_capabilities,
)


_SAMPLE = textwrap.dedent("""\
    version: 1
    bootstrap:
      enabled: true
      duration_sec: 45
      pairs: 12
    capabilities:
      at.handshake:       { required_tier: 0, transaction_weight: 1 }
      at.time-attest:     { required_tier: 0, transaction_weight: 1 }
      dod.sensor-report:  { required_tier: 2, transaction_weight: 4 }
    tier_demotion_epsilon: 0.05
""")


def _write(tmp_path, text):
    p = tmp_path / 'trust_ladder.yaml'
    p.write_text(text)
    return p


def test_defaults_when_absent(monkeypatch):
    # No path, no env -> documented all-defaults ladder (§8).
    monkeypatch.delenv('AT_TRUST_LADDER', raising=False)
    ladder = load_trust_ladder()
    assert ladder == default_ladder()
    assert ladder.capabilities == {}
    assert ladder.bootstrap == BootstrapParams()
    assert ladder.bootstrap.duration_sec == 30
    assert ladder.tier_demotion_epsilon == pytest.approx(0.02)


def test_load_parses_schema(tmp_path):
    ladder = load_trust_ladder(_write(tmp_path, _SAMPLE))
    assert isinstance(ladder, TrustLadder)
    assert ladder.bootstrap == BootstrapParams(
        enabled=True, duration_sec=45, pairs=12)
    assert ladder.tier_demotion_epsilon == pytest.approx(0.05)
    assert ladder['dod.sensor-report'] == CapMeta(
        'dod.sensor-report', required_tier=2, transaction_weight=4)
    assert 'at.handshake' in ladder
    assert len(ladder) == 3


def test_capability_defaults_fill_missing_fields(tmp_path):
    text = "capabilities:\n  bare.cap: {}\n"
    ladder = load_trust_ladder(_write(tmp_path, text))
    assert ladder['bare.cap'] == CapMeta(
        'bare.cap', required_tier=0, transaction_weight=1)


def test_explicit_missing_path_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_trust_ladder(tmp_path / 'nope.yaml')


def test_env_missing_path_falls_back(monkeypatch, tmp_path):
    monkeypatch.setenv('AT_TRUST_LADDER', str(tmp_path / 'nope.yaml'))
    assert load_trust_ladder() == default_ladder()


def test_malformed_entry_raises(tmp_path):
    text = "capabilities:\n  bad.cap: { required_tier: not-an-int }\n"
    with pytest.raises(ValueError):
        load_trust_ladder(_write(tmp_path, text))


def test_register_metadata_only(tmp_path):
    caps = Capabilities()
    register_trust_ladder(caps, _write(tmp_path, _SAMPLE))
    cap = caps['dod.sensor-report']
    assert cap.required_tier == 2
    assert cap.transaction_weight == 4
    assert cap.function is None  # no function supplied -> metadata only


def test_register_attaches_supplied_functions(tmp_path):
    caps = Capabilities()
    register_trust_ladder(caps, _write(tmp_path, _SAMPLE),
                          functions=BOOTSTRAP_FUNCTIONS)
    assert caps['at.handshake'].function is BOOTSTRAP_FUNCTIONS['at.handshake']
    # dod.sensor-report is not in the function map -> still metadata-only.
    assert caps['dod.sensor-report'].function is None


def test_register_idempotent(tmp_path):
    caps = Capabilities()
    p = _write(tmp_path, _SAMPLE)
    a = register_trust_ladder(caps, p)
    b = register_trust_ladder(caps, p)
    assert a == b
    assert sorted(caps.to_list()) == sorted(
        ['at.handshake', 'at.time-attest', 'dod.sensor-report'])


# --- bootstrap integration -------------------------------------------------

def test_bootstrap_defaults_unchanged(monkeypatch):
    # No ladder configured -> the three caps at tier 0 / weight 1, nothing
    # else (the historical contract).
    monkeypatch.delenv('AT_TRUST_LADDER', raising=False)
    caps = Capabilities()
    register_bootstrap_capabilities(caps)
    assert sorted(caps.to_list()) == sorted(BOOTSTRAP_FUNCTIONS)
    for name in BOOTSTRAP_FUNCTIONS:
        assert caps[name].required_tier == 0
        assert caps[name].transaction_weight == 1
        assert caps[name].function is BOOTSTRAP_FUNCTIONS[name]


def test_bootstrap_ladder_overrides_tier_weight(tmp_path):
    # A ladder reweights the bootstrap caps and adds a domain cap.
    caps = Capabilities()
    ladder = load_trust_ladder(_write(tmp_path, _SAMPLE))
    register_bootstrap_capabilities(caps, ladder)
    # at.handshake keeps its function but takes tier/weight from the ladder.
    assert caps['at.handshake'].function is BOOTSTRAP_FUNCTIONS['at.handshake']
    assert caps['at.handshake'].required_tier == 0
    # at.echo-challenge isn't in the sample ladder -> code default tier/weight.
    assert caps['at.echo-challenge'].required_tier == 0
    assert caps['at.echo-challenge'].transaction_weight == 1
    # the domain cap is registered metadata-only.
    assert caps['dod.sensor-report'].required_tier == 2
    assert caps['dod.sensor-report'].function is None


# --- One ladder file, both runtimes (doc/architecture/trust-tiers.md) -----
#
# The C twin (`src/c/autonomous_trust/config/trust_ladder.c`) parses the ladder
# with jansson, and the format is JSON precisely so this side needs no change:
# YAML is a superset of JSON, so the Python loader reads the same bytes. These
# cases assert the SAME numbers `trust_ladder_test.c::test_the_shared_example_
# parses` asserts, against the SAME file — without that pairing, "both runtimes
# read one file" is an intention rather than a fact.

def _find_shared_example():
    """Locate the example both suites pin, by searching upward rather than
    counting directories.

    `parents[4]` assumed this file sits exactly four levels below a repo root
    (`<repo>/src/<pkg>/tests/a_unit/`). Anywhere the tree is shallower — an
    installed package, or the test image, where these run from `/app/tests/
    a_unit` — indexing that far raised `IndexError` while the MODULE was being
    imported. That is a collection error, not a skip: it fails the run before
    any of these tests are considered, which defeats the `skipif` below.

    Searching upward also means the tests RUN wherever the file does travel,
    instead of being skipped on a layout that happens to carry it.
    """
    rel = Path('config') / 'cfg' / 'trust_ladder.example.json'
    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / rel
        if candidate.exists():
            return candidate
    return here.parent / rel        # absent -> the skipif below fires


_SHARED_EXAMPLE = _find_shared_example()


@pytest.mark.skipif(not _SHARED_EXAMPLE.exists(),
                    reason='shared example ladder not in this tree')
def test_the_shared_json_example_parses_here_too():
    ladder = load_trust_ladder(_SHARED_EXAMPLE)
    assert len(ladder.capabilities) == 6
    assert ladder.bootstrap.enabled is True
    assert ladder.bootstrap.duration_sec == 45
    assert ladder.bootstrap.pairs == 12
    assert ladder.tier_demotion_epsilon == pytest.approx(0.05)


@pytest.mark.skipif(not _SHARED_EXAMPLE.exists(),
                    reason='shared example ladder not in this tree')
def test_the_shared_example_capability_metadata_matches_c():
    ladder = load_trust_ladder(_SHARED_EXAMPLE)
    assert (ladder['demo.sensor-report'].required_tier,
            ladder['demo.sensor-report'].transaction_weight) == (2, 4)
    # Partial entry: tier from the file, weight from the documented default.
    assert (ladder['demo.fusion'].required_tier,
            ladder['demo.fusion'].transaction_weight) == (3, 1)
    # Empty entry: both defaults.
    assert (ladder['demo.command'].required_tier,
            ladder['demo.command'].transaction_weight) == (0, 1)


def test_a_json_ladder_needs_no_special_handling(tmp_path):
    """The whole reason the format is JSON: this loader is unchanged."""
    path = tmp_path / 'trust_ladder.json'
    path.write_text('{"capabilities": {"x": {"required_tier": 3}},'
                    ' "bootstrap": {"pairs": 4}}')
    ladder = load_trust_ladder(path)
    assert ladder['x'].required_tier == 3
    assert ladder.bootstrap.pairs == 4
