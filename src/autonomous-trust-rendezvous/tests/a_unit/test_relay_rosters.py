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
"""Community relay rosters (network/relay_rosters.py), FIRST_CONTACT_PLAN §4.2 /
§4.5. Mirrors C extensions/rendezvous/test/net_relay_rosters_test.c."""
import json
import os
import re
import types

import pytest
from nacl.encoding import HexEncoder
from nacl.signing import SigningKey

from autonomous_trust.core.config import Configuration
from autonomous_trust.rendezvous._python import relay, relay_rosters as rosters
from autonomous_trust.rendezvous._python import relay_seeds as seeds

A = SigningKey(b'\x31' * 32)
A_SEED = HexEncoder.encode(bytes(A)).decode()
A_KEY = A.verify_key.encode(HexEncoder).decode()
B = SigningKey(b'\x32' * 32)
B_SEED = HexEncoder.encode(bytes(B)).decode()
B_KEY = B.verify_key.encode(HexEncoder).decode()
RELEASE = SigningKey(b'\x11' * 32)

ETHNE_ISSUER = 'ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c'
ETHNE_RELAYS = [
    'relay://0f1e2d3c-4b5a-4968-8776-655443322110:7300c0ae1429cd153252736a781b78f4'
    '@relay.example.org:27790',
    'relay://1a2b3c4d-5e6f-4071-8293-a4b5c6d7e8f9:d7e1e084be213b01e506852af8198b99'
    '@[2001:db8::7]:27791',
]


def hint(i, port=27790):
    return 'relay://00000000-0000-4000-8000-00000000000%d:%s@198.51.100.%d:%d' % (
        i, 'ab' * 16, i, port)


def ethne_vector():
    """The bytes an Ethne polity emits, pinned in the C test (ETHNE_VECTOR), which
    carries en_uplift::rendezvous_roster's own byte-pinned vector."""
    src = os.path.join(os.path.dirname(__file__), '..', '..', '..', 'c', 'extensions', 'rendezvous', 'test',
                       'net_relay_rosters_test.c')
    with open(src) as f:
        m = re.search(r'#define ETHNE_VECTOR (".*")\n', f.read())
    return json.loads(m.group(1))


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv(Configuration.ROOT_VARIABLE_NAME, str(tmp_path))
    for name in ('AT_USE_RELAY', seeds.SEEDS_ENV, rosters.ROSTERS_ENV, rosters.ISSUERS_ENV):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv('AT_RELAY_SEED_FALLBACK', '1')
    monkeypatch.setattr(seeds, 'RELEASE_KEY', RELEASE.verify_key.encode(HexEncoder).decode())
    relay._seed_cache.update(key=None, hints=[])
    relay._roster_cache.update(key=None, hints=[])
    os.makedirs(os.path.join(Configuration.get_cfg_dir(), rosters.ROSTERS_DIR), exist_ok=True)
    os.makedirs(Configuration.get_data_dir(), exist_ok=True)


def _publish(name, seed, seq, hints):
    with open(os.path.join(rosters.rosters_dir(), name), 'w') as f:
        f.write(rosters.sign_roster(seed, seq, hints))


def _pin_file(keys):
    with open(rosters.issuers_path(), 'w') as f:
        json.dump({'issuers': keys}, f)


def test_an_ethne_emitted_roster_verifies():
    issuer, seq, relays = rosters.verify_roster(ethne_vector(), [ETHNE_ISSUER])
    assert (issuer, seq) == (ETHNE_ISSUER, 5)
    assert relays[0] == (('relay.example.org', 27790),
                         ('0f1e2d3c-4b5a-4968-8776-655443322110', '7300c0ae1429cd153252736a781b78f4'))
    assert relays[1][0] == ('2001:db8::7', 27791)


def test_python_signs_the_same_bytes_ethne_emits():
    """Three implementations, one format: AT's own signer, fed Ethne's inputs,
    reproduces Ethne's vector byte for byte."""
    assert rosters.sign_roster('07' * 32, 5, ETHNE_RELAYS) == ethne_vector()


def test_an_issuer_nobody_pinned_is_refused():
    with pytest.raises(rosters.InvalidRoster, match='not pinned'):
        rosters.verify_roster(ethne_vector(), [B_KEY])


def test_the_signature_covers_the_exact_body():
    tampered = ethne_vector().replace('seq\\":5', 'seq\\":6')
    assert tampered != ethne_vector()
    with pytest.raises(rosters.InvalidRoster):
        rosters.verify_roster(tampered, [ETHNE_ISSUER])


def test_a_seed_list_signature_does_not_verify_as_a_roster():
    body = json.dumps({'v': 1, 'typename': 'at-relay-roster', 'issuer': A_KEY, 'seq': 1,
                       'relays': [hint(1)]}, separators=(',', ':'))
    sig = A.sign((seeds.SEEDS_DOMAIN + body).encode()).signature
    with pytest.raises(rosters.InvalidRoster):
        rosters.verify_roster(json.dumps({'body': body, 'sig': sig.hex()}), [A_KEY])


def test_an_unpinned_entry_refuses_the_whole_roster():
    with pytest.raises(rosters.InvalidRoster):
        rosters.sign_roster(A_SEED, 1, [hint(1), 'relay://203.0.113.9:27790'])
    body = json.dumps({'v': 1, 'typename': 'at-relay-roster', 'issuer': A_KEY, 'seq': 1,
                       'relays': [hint(1), 'relay://203.0.113.9:27790']},
                      separators=(',', ':'))
    sig = A.sign((rosters.ROSTER_DOMAIN + body).encode()).signature
    with pytest.raises(rosters.InvalidRoster, match='pinned'):
        rosters.verify_roster(json.dumps({'body': body, 'sig': sig.hex()}), [A_KEY])


@pytest.mark.parametrize('field,value', [('seq', 0), ('v', 2), ('v', True), ('seq', '1')])
def test_a_version_or_seq_out_of_range_is_refused(field, value):
    body = {'v': 1, 'typename': 'at-relay-roster', 'issuer': A_KEY, 'seq': 1, 'relays': []}
    body[field] = value
    body_str = json.dumps(body, separators=(',', ':'))
    sig = A.sign((rosters.ROSTER_DOMAIN + body_str).encode()).signature
    with pytest.raises(rosters.InvalidRoster):
        rosters.verify_roster(json.dumps({'body': body_str, 'sig': sig.hex()}), [A_KEY])


def test_rosters_stand_in_ahead_of_the_seed_list():
    with open(seeds.seeds_path(), 'w') as f:
        f.write(seeds.sign_seeds(HexEncoder.encode(bytes(RELEASE)).decode(), 1, [hint(9)]))
    _publish('community.cfg.json', A_SEED, 1, [hint(1)])
    assert relay.own_relays() == [('198.51.100.9', 27790)], 'not pinned yet'
    _pin_file([A_KEY])
    assert relay.own_relays() == [('198.51.100.1', 27790), ('198.51.100.9', 27790)]


def test_an_explicit_relay_wins_and_off_means_off(monkeypatch):
    monkeypatch.setenv(rosters.ISSUERS_ENV, A_KEY)
    _publish('community.cfg.json', A_SEED, 1, [hint(1)])
    monkeypatch.setenv('AT_USE_RELAY', '203.0.113.5:27790')
    assert relay.own_relays() == [('203.0.113.5', 27790)]
    monkeypatch.delenv('AT_USE_RELAY')
    monkeypatch.delenv('AT_RELAY_SEED_FALLBACK')
    assert relay.own_relays() == []
    monkeypatch.setenv('AT_FIRST_CONTACT', '1')      # not the fallback's switch (D9)
    assert relay.own_relays() == []
    monkeypatch.delenv('AT_FIRST_CONTACT')
    monkeypatch.setenv('AT_RELAY_SEED_FALLBACK', '1')
    assert relay.own_relays() == [('198.51.100.1', 27790)]


def test_a_higher_seq_replaces_and_a_lower_is_refused(monkeypatch):
    monkeypatch.setenv(rosters.ISSUERS_ENV, A_KEY)
    _publish('community.cfg.json', A_SEED, 2, [hint(1)])
    assert relay.own_relays() == [('198.51.100.1', 27790)]
    # Replaced whole. (A new size: a same-size rewrite in one mtime tick would
    # share a stamp.)
    _publish('community.cfg.json', A_SEED, 30, [hint(2)])
    assert relay.own_relays() == [('198.51.100.2', 27790)]
    _publish('community.cfg.json', A_SEED, 1, [hint(3), hint(4)])
    assert relay.own_relays() == []


def test_an_empty_roster_says_the_community_runs_none(monkeypatch):
    monkeypatch.setenv(rosters.ISSUERS_ENV, A_KEY)
    _publish('community.cfg.json', A_SEED, 1, [hint(1)])
    assert relay.own_relays() == [('198.51.100.1', 27790)]
    _publish('community.cfg.json', A_SEED, 2, [])
    assert relay.own_relays() == []


def test_of_two_files_from_one_issuer_the_higher_seq_wins(monkeypatch):
    monkeypatch.setenv(rosters.ISSUERS_ENV, A_KEY)
    _publish('a-new.cfg.json', A_SEED, 5, [hint(5)])
    _publish('b-old.cfg.json', A_SEED, 4, [hint(4)])
    assert relay.own_relays() == [('198.51.100.5', 27790)]


def test_issuers_count_in_pin_order_env_first(monkeypatch):
    _publish('a.cfg.json', A_SEED, 1, [hint(1)])
    _publish('b.cfg.json', B_SEED, 1, [hint(2)])
    _pin_file([A_KEY, B_KEY])
    monkeypatch.setenv(rosters.ISSUERS_ENV, B_KEY)
    assert relay.own_relays() == [('198.51.100.2', 27790), ('198.51.100.1', 27790)]
    assert rosters.pinned_issuers() == [B_KEY, A_KEY]


def test_a_malformed_issuer_is_skipped(monkeypatch):
    monkeypatch.setenv(rosters.ISSUERS_ENV, 'not-a-key, %s ,%s' % (A_KEY, B_KEY[:63]))
    assert rosters.pinned_issuers() == [A_KEY]
    monkeypatch.setenv(rosters.ISSUERS_ENV, B_KEY.upper())
    assert rosters.pinned_issuers() == [B_KEY]


def test_an_explicit_dir_overrides_the_cfg_dir(monkeypatch, tmp_path):
    monkeypatch.setenv(rosters.ISSUERS_ENV, A_KEY)
    elsewhere = tmp_path / 'elsewhere'
    elsewhere.mkdir()
    monkeypatch.setenv(rosters.ROSTERS_ENV, str(elsewhere))
    (elsewhere / 'r.cfg.json').write_text(rosters.sign_roster(A_SEED, 1, [hint(7)]))
    assert relay.own_relays() == [('198.51.100.7', 27790)]


def test_the_merge_keeps_the_cap(monkeypatch):
    monkeypatch.setenv(rosters.ISSUERS_ENV, A_KEY)
    _publish('r.cfg.json', A_SEED, 1, [hint(i) for i in range(1, 7)])
    assert len(relay.own_relays()) == relay.MAX_RELAYS
    assert relay.own_relays()[0] == ('198.51.100.1', 27790)


def test_a_refused_roster_is_logged_once(monkeypatch, caplog):
    monkeypatch.setenv(rosters.ISSUERS_ENV, B_KEY)
    _publish('r.cfg.json', A_SEED, 1, [hint(1)])
    for _ in range(3):
        assert relay.own_relays() == []
    assert sum('refused' in r.getMessage() for r in caplog.records) == 1


# -- area hubs in a roster --------------------------------------------------------
def test_a_roster_without_hubs_keeps_its_bytes():
    """``areas`` is left out when no relay serves one: the Ethne vector still
    verifies, and still reproduces byte for byte."""
    assert '"areas"' not in json.loads(ethne_vector())['body']
    assert rosters.verify_roster_areas(ethne_vector(), [ETHNE_ISSUER])[3] == {}


def ethne_hub_vector():
    """D38: the Ethne polity's hub roster (en_uplift PINNED_HUB_VECTOR), pinned in the C test."""
    src = os.path.join(os.path.dirname(__file__), '..', '..', '..', 'c', 'extensions', 'rendezvous', 'test',
                       'net_relay_rosters_test.c')
    with open(src) as f:
        m = re.search(r'#define ETHNE_HUB_VECTOR (".*")\n', f.read())
    return json.loads(m.group(1))


def test_an_ethne_emitted_hub_roster_names_its_areas():
    issuer, seq, relays, areas = rosters.verify_roster_areas(ethne_hub_vector(), [ETHNE_ISSUER])
    assert seq == 6 and areas == {('2001:db8::7', 27791): ['u4pr', 'gcpv']}
    assert rosters.sign_roster('07' * 32, 6, ETHNE_RELAYS,
                               areas={ETHNE_RELAYS[1]: ['u4pr', 'gcpv']}) == ethne_hub_vector()


def test_a_roster_names_its_hubs_and_their_areas():
    text = rosters.sign_roster(A_SEED, 1, [hint(1), hint(2)], areas={hint(2): ['u4pr', 'gcpv']})
    issuer, seq, relays, areas = rosters.verify_roster_areas(text, [A_KEY])
    assert areas == {('198.51.100.2', 27790): ['u4pr', 'gcpv']}
    assert rosters.verify_roster(text, [A_KEY])[2] == relays


@pytest.mark.parametrize('areas', [
    {'relay://00000000-0000-4000-8000-000000000009:' + 'ab' * 16 + '@198.51.100.9:1': ['u4pr']},
    {hint(1): []},
    {hint(1): ['u4pa']},
    {hint(1): ['u4pr'] * (rosters.MAX_AREAS + 1)},
    ['u4pr'],
])
def test_bad_areas_refuse_the_whole_roster(areas):
    body = json.dumps({'v': 1, 'typename': rosters.ROSTER_TYPENAME, 'issuer': A_KEY, 'seq': 1,
                       'relays': [hint(1)], 'areas': areas}, separators=(',', ':'))
    sig = A.sign((rosters.ROSTER_DOMAIN + body).encode()).signature
    with pytest.raises(rosters.InvalidRoster):
        rosters.verify_roster(json.dumps({'body': body, 'sig': sig.hex()}), [A_KEY])


def test_a_hub_for_our_own_bucket_is_registered_first(monkeypatch):
    monkeypatch.setenv(rosters.ISSUERS_ENV, A_KEY)
    hints = [hint(i) for i in range(1, 7)]
    _publish('a.cfg.json', A_SEED, 1, hints)
    with open(os.path.join(rosters.rosters_dir(), 'a.cfg.json'), 'w') as f:
        f.write(rosters.sign_roster(A_SEED, 1, hints, areas={hint(6): ['u4pr'],
                                                              hint(5): ['gcpv']}))
    # No area provider (first contact absent): the roster's own order stands.
    monkeypatch.setattr(rosters, '_area_provider', None)
    assert [ep[1] for ep, _p in relay.own_relay_hints()] == [27790] * 4
    assert [ep[0] for ep, _p in relay.own_relay_hints()][0] == '198.51.100.1'
    # Listed under u4pru (what first contact's provider would say): the u4pr
    # hub moves to the front, inside the cap. The provider's file changing is
    # what tells the hint cache to look again.
    marker = os.path.join(Configuration.get_data_dir(), 'listings')
    with open(marker, 'w') as f:
        f.write('1')
    monkeypatch.setattr(rosters, '_area_provider', types.SimpleNamespace(
        listed_buckets=lambda: ['u4pru'], state_path=lambda: marker))
    assert [ep[0] for ep, _p in relay.own_relay_hints()] == [
        '198.51.100.6', '198.51.100.1', '198.51.100.2', '198.51.100.3']


def test_install_pins_the_issuer_and_remove_unpins_it():
    text = rosters.sign_roster(A_SEED, 3, [hint(1)], areas={hint(1): ['u4pr']})
    assert rosters.install(text) == A_KEY
    assert rosters.pinned_issuers() == [A_KEY]
    assert [ep for ep, _p in relay.own_relay_hints()] == [('198.51.100.1', 27790)]
    relay.own_relay_hints()                         # raises the seq floor to 3
    with pytest.raises(rosters.InvalidRoster, match='older'):
        rosters.install(rosters.sign_roster(A_SEED, 2, [hint(2)]))
    assert rosters.install(rosters.sign_roster(A_SEED, 4, [hint(2)])) == A_KEY
    assert rosters.pinned_issuers() == [A_KEY]      # pinned once
    assert rosters.remove(A_KEY) is True
    assert rosters.pinned_issuers() == [] and relay.own_relay_hints() == []
    assert rosters.remove(A_KEY) is False


def test_install_refuses_a_roster_that_does_not_verify_under_its_own_issuer():
    text = json.loads(rosters.sign_roster(A_SEED, 1, [hint(1)]))
    text['body'] = text['body'].replace(A_KEY, B_KEY)
    with pytest.raises(rosters.InvalidRoster):
        rosters.install(json.dumps(text))
    assert rosters.pinned_issuers() == []
