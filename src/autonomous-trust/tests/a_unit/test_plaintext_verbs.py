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
"""The plaintext-verbs file, unencrypted_verbs.cfg.json (FEATURE_SPLIT_PLAN D8).

The core's plaintext verbs are compiled in; an optional feature's come from
this file. The rules pinned here, each a refusal to start unless noted:

* no file: the core verbs only (not a refusal);
* a malformed file;
* a verb no loaded extension declares eligible, a core verb above all -- the
  file must never be a way to downgrade the core;
* a loaded extension whose declared verbs the file does not name.

The rules are the core's, so they are exercised with a stand-in extension.
First contact's own half (its five verbs, and the start check that reads
AT_FIRST_CONTACT) is in that distribution's test_first_contact_plaintext.py.
"""
import json
from dataclasses import dataclass

import pytest

from autonomous_trust.core import plaintext_verbs as pv
from autonomous_trust.core.identity.protocol import (CORE_UNENCRYPTED_VERBS,
                                                     IdentityProtocol)


@dataclass(frozen=True)
class _Ext:
    name: str
    plaintext_verbs: tuple = ()


#: A stand-in optional feature that declares two plaintext verbs.
DEMO = _Ext('demo', ('demo_ack', 'demo_hello'))
DEMO_VERBS = sorted(DEMO.plaintext_verbs)


@pytest.fixture(autouse=True)
def _reset():
    pv.reset()
    yield
    pv.reset()


def _write(tmp_path, doc):
    text = doc if isinstance(doc, str) else json.dumps(doc)
    (tmp_path / pv.FILENAME).write_text(text)


def test_the_core_has_nine_and_they_are_always_on():
    assert len(CORE_UNENCRYPTED_VERBS) == 9
    assert pv.active() == CORE_UNENCRYPTED_VERBS
    for verb in CORE_UNENCRYPTED_VERBS:
        assert pv.is_unencrypted(verb)


def test_no_file_is_the_core_only(tmp_path):
    assert pv.configure(str(tmp_path), []) == frozenset()
    assert pv.active() == CORE_UNENCRYPTED_VERBS


def test_the_file_grants_a_loaded_extensions_verbs(tmp_path):
    _write(tmp_path, {'verbs': DEMO_VERBS})
    assert pv.configure(str(tmp_path), [DEMO]) == frozenset(DEMO_VERBS)
    assert pv.active() == CORE_UNENCRYPTED_VERBS | set(DEMO_VERBS)
    assert pv.is_unencrypted('demo_hello')


def test_no_file_with_the_feature_on_refuses_naming_the_verbs(tmp_path):
    with pytest.raises(pv.PlaintextVerbsError) as err:
        pv.configure(str(tmp_path), [DEMO])
    text = str(err.value)
    assert pv.FILENAME in text and 'no such file' in text
    for verb in DEMO_VERBS:
        assert verb in text


def test_a_file_missing_one_verb_refuses_naming_it(tmp_path):
    _write(tmp_path, {'verbs': DEMO_VERBS[1:]})
    with pytest.raises(pv.PlaintextVerbsError, match=DEMO_VERBS[0]):
        pv.configure(str(tmp_path), [DEMO])


@pytest.mark.parametrize('verb', [IdentityProtocol.update,   # group_key_update
                                  IdentityProtocol.history,  # full_history
                                  IdentityProtocol.announce])  # already core
def test_a_core_verb_refuses(tmp_path, verb):
    """The file cannot downgrade the core: not even a verb that is already
    core plaintext, since naming it is a sign the file is not what it seems."""
    _write(tmp_path, {'verbs': DEMO_VERBS + [verb]})
    with pytest.raises(pv.PlaintextVerbsError, match=verb):
        pv.configure(str(tmp_path), [DEMO])
    assert not pv.is_unencrypted(IdentityProtocol.update)


def test_a_feature_verb_with_the_feature_off_refuses(tmp_path):
    _write(tmp_path, {'verbs': DEMO_VERBS})
    with pytest.raises(pv.PlaintextVerbsError, match='no loaded extension'):
        pv.configure(str(tmp_path), [])


@pytest.mark.parametrize('text', [
    'not json',
    '[]',
    '{}',
    '{"verbs": "demo_hello"}',
    '{"verbs": [1]}',
    '{"verbs": [""]}',
    '{"verbs": [], "extra": true}',
    '{"verb": []}',
    '{"verbs": ["demo_hello", "demo_hello"]}',
    json.dumps({'verbs': ['v%d' % i for i in range(33)]}),
    json.dumps({'verbs': ['v' * 65]}),
])
def test_a_malformed_file_refuses(tmp_path, text):
    _write(tmp_path, text)
    with pytest.raises(pv.PlaintextVerbsError):
        pv.configure(str(tmp_path), [_Ext('x', ('demo_hello',))])


def test_an_empty_list_is_valid(tmp_path):
    _write(tmp_path, {'verbs': []})
    assert pv.configure(str(tmp_path), []) == frozenset()


def test_a_refusal_keeps_the_previous_grant(tmp_path):
    _write(tmp_path, {'verbs': DEMO_VERBS})
    pv.configure(str(tmp_path), [DEMO])
    _write(tmp_path, 'broken')
    with pytest.raises(pv.PlaintextVerbsError):
        pv.configure(str(tmp_path), [DEMO])
    assert pv.is_unencrypted('demo_hello')


@pytest.mark.parametrize('verb', [None, '', 42])
def test_nothing_odd_is_plaintext(verb):
    assert pv.is_unencrypted(verb) is False
