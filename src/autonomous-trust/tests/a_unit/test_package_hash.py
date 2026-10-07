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
"""The package-hash gate (IdentityProcess._package_hash_admissible): an
allowlist in etc/at when one ships, the old same-runtime equality when none
does. Mirrors src/c/test/package_hash_test.c, whose pinned slot is what this
runtime sends for blake2b(b'stele')."""

import json
from types import SimpleNamespace

import pytest
from nacl.hash import blake2b

from autonomous_trust.core.config import (Configuration, from_json_string,
                                          to_json_string)
from autonomous_trust.core.identity.idprocess import IdentityProcess

OURS = blake2b(b'stele')
PY_TAGGED = 'py:8c1b5579fa0de85e1a2e8c87a2919958103e022efd357612e3dbac25302d795f'
C_TAGGED = 'c:' + 'ab' * 32


@pytest.fixture
def node(tmp_path, monkeypatch):
    monkeypatch.setattr(Configuration, 'get_cfg_dir',
                        staticmethod(lambda: str(tmp_path)))
    stub = SimpleNamespace(package_hash=OURS,
                           PACKAGE_HASHES_FILE=IdentityProcess.PACKAGE_HASHES_FILE,
                           _tagged_package_hash=IdentityProcess._tagged_package_hash)
    return (lambda ph: IdentityProcess._package_hash_admissible(stub, ph)), tmp_path


def _allow(tmp_path, *hashes):
    (tmp_path / IdentityProcess.PACKAGE_HASHES_FILE).write_text(
        json.dumps({'accepted': list(hashes)}))


def test_our_digest_on_the_wire_is_the_pinned_tag():
    (ph,) = from_json_string(to_json_string((OURS,)))
    assert IdentityProcess._tagged_package_hash(ph) == PY_TAGGED


def test_without_an_allowlist_the_old_rule_holds(node):
    admit, _ = node
    assert admit(OURS)[0]
    assert admit('')[0]
    assert admit(C_TAGGED)[0]
    assert not admit(blake2b(b'patched'))[0]


def test_with_an_allowlist_only_listed_hashes_get_in(node):
    admit, tmp = node
    _allow(tmp, PY_TAGGED, C_TAGGED)
    assert admit(OURS)[0]
    assert admit(C_TAGGED)[0]
    ok, why = admit('')
    assert not ok and 'not on the allowlist' in why
    assert not admit('c:' + 'cd' * 32)[0]
    assert not admit(blake2b(b'patched'))[0]
    assert not admit(C_TAGGED[:-1])[0]


def test_an_allowlist_without_us_refuses_us_too(node):
    admit, tmp = node
    _allow(tmp, C_TAGGED)
    assert not admit(OURS)[0]
