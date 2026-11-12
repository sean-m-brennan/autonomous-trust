# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
#  Licensed under the Apache License, Version 2.0
# ******************
"""The deployment manifest's Python half (RD_13.4 §3.3).

The validation rules are pinned on both runtimes by the conformance case
network/deployment-manifest. These cover what that case does not: the load
paths, the active-manifest lifecycle, and what a parsed manifest holds. Twin of
src/c/test/deployment_manifest_test.c.
"""

from __future__ import annotations

import json

import pytest

from autonomous_trust.core import deployment_manifest as dm

GW1 = 'aaaaaaaa-0000-4000-8000-000000000001'
GW2 = 'aaaaaaaa-0000-4000-8000-000000000002'
LEAF = '11111111-0000-4000-8000-000000000001'

TWO_GATEWAYS = {
    'version': 1,
    'cohorts': {
        'a': {'members': [GW1, GW2, LEAF], 'n_min': 4},
        'b': {'members': [GW1, GW2]},
    },
    'gateways': [
        {'node': GW1, 'between': ['b', 'a']},
        {'node': GW2, 'between': ['a', 'b']},
    ],
}


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    monkeypatch.delenv(dm.DEPLOYMENT_MANIFEST_ENV, raising=False)
    dm.reset()
    yield
    dm.reset()


def _write(tmp_path, body) -> str:
    path = tmp_path / 'manifest.json'
    path.write_text(body if isinstance(body, str) else json.dumps(body))
    return str(path)


def test_a_valid_manifest_holds_what_it_says(tmp_path):
    m = dm.load_manifest(_write(tmp_path, TWO_GATEWAYS))
    assert set(m.cohorts) == {'a', 'b'}
    # A pair has one spelling, whichever order the file used.
    assert m.gateways[0].between == ('a', 'b')
    assert m.gateway_pairs(GW1) == 1
    assert m.may_be_gateway(GW2)
    assert not m.may_be_gateway(LEAF)
    assert m.cohorts['a'].n_min == 4 and m.cohorts['b'].n_min is None


def test_an_explicit_missing_path_is_an_error(tmp_path):
    with pytest.raises(FileNotFoundError):
        dm.load_manifest(tmp_path / 'absent.json')


def test_the_environment_names_the_file(tmp_path, monkeypatch, caplog):
    assert dm.load_manifest().is_empty()
    # Missing: empty, the restrictive answer, not a refusal.
    monkeypatch.setenv(dm.DEPLOYMENT_MANIFEST_ENV, str(tmp_path / 'absent.json'))
    assert dm.load_manifest().is_empty()
    assert 'not found' in caplog.text
    monkeypatch.setenv(dm.DEPLOYMENT_MANIFEST_ENV, _write(tmp_path, TWO_GATEWAYS))
    assert len(dm.load_manifest().gateways) == 2


def test_a_refused_configure_keeps_the_active_manifest(tmp_path):
    assert dm.active().is_empty()
    dm.configure(_write(tmp_path, TWO_GATEWAYS))
    assert dm.active().gateway_pairs(GW2) == 1
    with pytest.raises(dm.ManifestError):
        dm.configure(_write(tmp_path, {'version': 2}))
    assert dm.active().gateway_pairs(GW2) == 1
    dm.reset()
    assert dm.active().is_empty()


def test_a_uuid_object_is_looked_up_as_its_string(tmp_path):
    from uuid import UUID
    m = dm.load_manifest(_write(tmp_path, TWO_GATEWAYS))
    assert m.gateway_pairs(UUID(GW1)) == 1
