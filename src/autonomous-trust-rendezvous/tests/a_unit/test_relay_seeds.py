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
"""The signed relay seed list (network/relay_seeds.py), FIRST_CONTACT_PLAN §10.1."""
import json
import os

import pytest
from nacl.encoding import HexEncoder
from nacl.signing import SigningKey

from autonomous_trust.core.config import Configuration
from autonomous_trust.rendezvous._python import relay, relay_seeds as seeds

RELEASE = SigningKey(b'\x11' * 32)
RELEASE_SEED = HexEncoder.encode(bytes(RELEASE)).decode()
RELEASE_KEY = RELEASE.verify_key.encode(HexEncoder).decode()
NODE = SigningKey(b'\x22' * 32)
NODE_SEED = HexEncoder.encode(bytes(NODE)).decode()
PINNED = 'relay://00000000-0000-4000-8000-000000000001:%s@198.51.100.1:27790' % ('ab' * 16)


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv(Configuration.ROOT_VARIABLE_NAME, str(tmp_path))
    monkeypatch.delenv('AT_USE_RELAY', raising=False)
    monkeypatch.delenv(seeds.SEEDS_ENV, raising=False)
    monkeypatch.setenv('AT_RELAY_SEED_FALLBACK', '1')
    monkeypatch.setattr(seeds, 'RELEASE_KEY', RELEASE_KEY)
    relay._seed_cache.update(key=None, hints=[])
    os.makedirs(Configuration.get_cfg_dir(), exist_ok=True)
    os.makedirs(Configuration.get_data_dir(), exist_ok=True)
    with open(os.path.join(Configuration.get_cfg_dir(), 'identity.cfg.json'), 'w') as f:
        json.dump({'typename': 'identity', 'signature': {'hex_seed': NODE_SEED}}, f)


def _ship(seq, hints, seed=RELEASE_SEED):
    with open(os.path.join(Configuration.get_cfg_dir(), seeds.SEEDS_FILE), 'w') as f:
        f.write(seeds.sign_seeds(seed, seq, hints))


def _local(add=(), remove=(), seed=NODE_SEED):
    with open(os.path.join(Configuration.get_data_dir(), seeds.LOCAL_FILE), 'w') as f:
        f.write(seeds.sign_local(seed, add, remove))


def test_a_signed_list_round_trips():
    text = seeds.sign_seeds(RELEASE_SEED, 3, [PINNED, 'relay://203.0.113.9:1'])
    seq, hints = seeds.verify_seeds(text, RELEASE_KEY)
    assert seq == 3
    assert hints == [(('198.51.100.1', 27790),
                      ('00000000-0000-4000-8000-000000000001', 'ab' * 16)),
                     (('203.0.113.9', 1), None)]


def test_the_signature_covers_the_exact_body():
    obj = json.loads(seeds.sign_seeds(RELEASE_SEED, 1, ['relay://a:1']))
    obj['body'] = obj['body'].replace('a:1', 'b:1')
    with pytest.raises(seeds.InvalidSeeds):
        seeds.verify_seeds(json.dumps(obj), RELEASE_KEY)


def test_another_key_or_no_key_is_refused():
    other = HexEncoder.encode(b'\x33' * 32).decode()
    with pytest.raises(seeds.InvalidSeeds):
        seeds.verify_seeds(seeds.sign_seeds(other, 1, ['relay://a:1']), RELEASE_KEY)
    with pytest.raises(seeds.InvalidSeeds):
        seeds.verify_seeds(seeds.sign_seeds(RELEASE_SEED, 1, ['relay://a:1']), '')


def test_a_local_edit_signature_does_not_verify_as_a_list():
    """Domain separation: the two files cannot stand in for each other."""
    text = seeds.sign_local(RELEASE_SEED, ['relay://a:1'])
    with pytest.raises(seeds.InvalidSeeds):
        seeds.verify_seeds(text, RELEASE_KEY)


def test_one_bad_entry_refuses_the_whole_list():
    body = json.dumps({'v': 1, 'typename': 'at-seeds', 'seq': 1,
                       'relays': ['relay://a:1', 'nonsense']}, separators=(',', ':'))
    sig = RELEASE.sign((seeds.SEEDS_DOMAIN + body).encode()).signature
    with pytest.raises(seeds.InvalidSeeds):
        seeds.verify_seeds(json.dumps({'body': body, 'sig': sig.hex()}), RELEASE_KEY)


def test_seed_list_stands_in_only_without_an_explicit_relay(monkeypatch):
    _ship(1, ['relay://203.0.113.9:1'])
    assert relay.own_relays() == [('203.0.113.9', 1)]
    monkeypatch.setenv('AT_USE_RELAY', '198.51.100.5:2')
    assert relay.own_relays() == [('198.51.100.5', 2)]


def test_off_means_off(monkeypatch):
    _ship(1, ['relay://203.0.113.9:1'])
    monkeypatch.delenv('AT_RELAY_SEED_FALLBACK')
    assert relay.own_relays() == []


def test_no_release_key_trusts_no_shipped_list(monkeypatch):
    monkeypatch.setattr(seeds, 'RELEASE_KEY', '')
    _ship(1, ['relay://203.0.113.9:1'])
    _local(add=['relay://198.51.100.7:3'])
    assert relay.own_relays() == [('198.51.100.7', 3)]


def test_an_older_list_is_refused_once_a_newer_was_seen():
    _ship(5, ['relay://203.0.113.9:1'])
    assert relay.own_relays() == [('203.0.113.9', 1)]
    _ship(4, ['relay://203.0.113.10:1'])
    assert relay.own_relays() == []
    # A new size: a same-size rewrite in one mtime tick would share a stamp.
    _ship(5, ['relay://203.0.113.11:11'])
    assert relay.own_relays() == [('203.0.113.11', 11)]


def test_local_adds_come_first_and_removes_drop_by_endpoint():
    _ship(1, [PINNED, 'relay://203.0.113.9:1', 'relay://203.0.113.10:1'])
    _local(add=['relay://198.51.100.7:3'], remove=['198.51.100.1:27790'])
    assert relay.own_relays() == [('198.51.100.7', 3), ('203.0.113.9', 1),
                                  ('203.0.113.10', 1)]


def test_the_merge_keeps_the_cap():
    _ship(1, ['relay://10.0.0.%d:1' % i for i in range(1, 9)])
    assert len(relay.own_relays()) == relay.MAX_RELAYS


def test_local_edits_signed_by_another_key_are_ignored():
    _ship(1, ['relay://203.0.113.9:1'])
    _local(add=['relay://198.51.100.7:3'], seed=RELEASE_SEED)
    assert relay.own_relays() == [('203.0.113.9', 1)]


def test_an_explicit_path_overrides_the_cfg_dir(monkeypatch, tmp_path):
    path = tmp_path / 'elsewhere.json'
    path.write_text(seeds.sign_seeds(RELEASE_SEED, 1, ['relay://203.0.113.12:1']))
    monkeypatch.setenv(seeds.SEEDS_ENV, str(path))
    assert relay.own_relays() == [('203.0.113.12', 1)]


def test_a_refused_list_is_logged_once(caplog):
    with open(os.path.join(Configuration.get_cfg_dir(), seeds.SEEDS_FILE), 'w') as f:
        f.write('{"body": "{}", "sig": "00"}')
    for _ in range(3):
        assert relay.own_relays() == []
    assert sum('refused' in r.getMessage() for r in caplog.records) == 1


@pytest.mark.parametrize('body', [
    '{"v":1.0,"typename":"at-seeds","seq":1,"relays":[]}',
    '{"v":true,"typename":"at-seeds","seq":1,"relays":[]}',
    '{"v":1,"typename":"at-seeds","seq":0,"relays":[]}',
    '{"v":1,"typename":"at-seeds","seq":true,"relays":[]}',
])
def test_a_version_must_be_the_integer_one(body):
    """Python's 1.0 == True == 1; C's jansson tells them apart, so both refuse."""
    sig = RELEASE.sign((seeds.SEEDS_DOMAIN + body).encode()).signature
    with pytest.raises(seeds.InvalidSeeds):
        seeds.verify_seeds(json.dumps({'body': body, 'sig': sig.hex()}), RELEASE_KEY)


def test_the_c_vector_is_what_python_signs():
    """net_relay_seeds_test.c pins these exact bytes (PY_SIGNED_LIST)."""
    text = seeds.sign_seeds('11' * 32, 7, ['relay://203.0.113.9:27790'])
    src = os.path.join(os.path.dirname(__file__), '..', '..', '..', 'c', 'extensions', 'rendezvous', 'test',
                       'net_relay_seeds_test.c')
    with open(src) as f:
        assert json.dumps(text) in f.read()


def test_the_node_key_is_read_from_a_python_written_identity():
    """The Python encoder's identity.cfg.json, not the C shape the fixture writes."""
    from autonomous_trust.core.identity import Identity
    ident = Identity.initialize('p', 'p', '10.0.0.1')
    ident.to_file(os.path.join(Configuration.get_cfg_dir(), 'identity.cfg.json'))
    seed = seeds.node_seed_hex()
    assert seed and SigningKey(HexEncoder.decode(seed.encode())).verify_key \
        .encode(HexEncoder).decode() == ident.signature.publish().decode()
    _ship(1, ['relay://203.0.113.9:1'])
    _local(add=['relay://198.51.100.7:3'], seed=seed)
    assert relay.own_relays() == [('198.51.100.7', 3), ('203.0.113.9', 1)]
