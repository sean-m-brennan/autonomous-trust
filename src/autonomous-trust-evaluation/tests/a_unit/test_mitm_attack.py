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
"""MITM, live: a sidecar in one node's network namespace captures its frames,
classifies them, and replays them to a peer."""

import json
import random
import struct

from autonomous_trust.evaluation.redteam import mitm_attack as mm
from autonomous_trust.evaluation.redteam import mitm_sidecar as sc
from autonomous_trust.core._python.identity.protocol import IdentityProtocol

ANNOUNCE = IdentityProtocol.announce


def _json_frame(function, process='identity'):
    return json.dumps({'process': process, 'function': function,
                       'encrypt': False, 'data': ''}).encode()


def _proto_frame(function, process='identity'):
    from autonomous_trust.core.protobuf.network import net_message_pb2
    pb = net_message_pb2.NetMessage()
    pb.process, pb.function = process, function
    return bytes([0xAB]) + pb.SerializeToString()


def test_random_bytes_starting_with_brace_or_marker_are_opaque():
    rnd = random.Random(20261110)
    for lead in (b'{', bytes([0xAB])):
        for _ in range(2000):
            frame = lead + bytes(rnd.getrandbits(8) for _ in range(rnd.randint(8, 200)))
            assert mm.classify(frame) == ('opaque', None)


def test_a_json_envelope_is_classified_by_function():
    assert mm.classify(_json_frame(ANNOUNCE)) == ('json', ANNOUNCE)
    assert mm.classify(b'{"process": "", "function": "x"}') == ('opaque', None)
    assert mm.classify(b'[1, 2]') == ('opaque', None)


def test_a_proto_envelope_is_classified_by_function():
    assert mm.classify(_proto_frame('id_query')) == ('proto', 'id_query')


def test_allowed_plaintext_is_imported_from_the_core_and_first_contact():
    from autonomous_trust.core._python.identity.protocol import (
        CORE_UNENCRYPTED_VERBS)
    assert CORE_UNENCRYPTED_VERBS <= mm.allowed_plaintext()
    assert 'first_contact_hello' in mm.allowed_plaintext()


def _frames(*payloads, dst='10.34.0.11', dport=27787):
    return '\n'.join(json.dumps({'t': 1000.0 + i, 'dir': 'out',
                                 'src': '10.34.0.10', 'dst': dst,
                                 'sport': 40000, 'dport': dport,
                                 'hex': p.hex()})
                     for i, p in enumerate(payloads))


def _dump(t, n, control):
    return 'x AT_REPDUMP %s' % json.dumps({'t': t, 'view': [
        {'nick': 'honest-1@tekfive.com', 'tier': 3, 'own': 5, 'n': n},
        {'nick': 'honest-3@tekfive.com', 'tier': 3, 'own': 5, 'n': control}]})


def _stamp(t):
    import datetime
    return datetime.datetime.fromtimestamp(
        t, datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S.000')


def _victim(points, refusals=0, refused_at=1610.0):
    """``points`` are (t, n of honest-1[, n of the control peer honest-3]);
    the control follows honest-1 unless given."""
    lines = [_dump(p[0], p[1], p[2] if len(p) > 2 else p[1]) for p in points]
    lines += ['%s - WARNING IdentityProcess: Peer confirmation from ab '
              'refused: sequence 3 not above mark (replay or unstamped)'
              % _stamp(refused_at)] * refusals
    return '\n'.join(lines)


STEADY = [(1000, 0), (1500, 10), (1560, 12), (1600, 14), (1640, 15),
          (1660, 16), (1700, 18)]


def _metrics(frames, victim, replayed=5, at=1600.0):
    side = 'MITM_REPLAYED %d at %.3f' % (replayed, at) if replayed is not None else ''
    return {'logs': {'honest-2': victim, 'mitm': side},
            'artifacts': {'frames.jsonl': frames}}


def _attack():
    return mm.MitmAttack(honest=3)


def test_a_secret_verb_in_plaintext_fails():
    frames = _frames(_json_frame(ANNOUNCE), _json_frame('transaction', 'reputation'),
                     bytes(64))
    out = _attack().collect(_metrics(frames, _victim(STEADY)))
    a = out['attack_specific']
    assert a['plaintext_verbs'] == {ANNOUNCE: 1, 'transaction': 1}
    assert any('transaction' in c for c in a['failed_checks'])
    assert a['opaque'] == 1


def test_allowed_plaintext_and_ciphertext_pass():
    frames = _frames(_json_frame(ANNOUNCE), bytes(64))
    out = _attack().collect(_metrics(frames, _victim(STEADY, refusals=4)))
    a = out['attack_specific']
    assert a['failed_checks'] == []
    assert a['refusals'] == 4
    assert a['replayed'] == 5
    assert 'error' not in out


def test_a_replay_that_moves_n_fails():
    # honest-1's count jumps after the replay while the control peer's does
    # not: the replay was acted on.
    jumped = [(1000, 0, 0), (1500, 10, 10), (1560, 12, 12), (1600, 14, 14),
              (1630, 60, 15), (1660, 61, 16)]
    frames = _frames(bytes(64))
    out = _attack().collect(_metrics(frames, _victim(jumped)))
    assert any('replay' in c for c in out['attack_specific']['failed_checks'])


def test_a_cohort_wide_rise_after_the_replay_passes():
    # The first placements land just after the replay and move every peer
    # alike (smoke run, 2026-11-10): not the replay.
    wave = [(1000, 0, 0), (1590, 0, 0), (1600, 0, 0), (1640, 18, 26),
            (1660, 18, 26)]
    out = _attack().collect(_metrics(_frames(bytes(64)), _victim(wave)))
    assert out['attack_specific']['failed_checks'] == []


def test_refusals_are_split_at_the_replay():
    text = _victim(STEADY, refusals=2, refused_at=1500.0) + '\n' + \
        _victim([], refusals=3, refused_at=1610.0)
    out = _attack().collect(_metrics(_frames(bytes(64)), text))
    a = out['attack_specific']
    assert (a['refusals'], a['refusals_after_replay']) == (5, 3)


def test_no_replayed_frames_is_no_data():
    out = _attack().collect(_metrics(_frames(bytes(64)), _victim(STEADY),
                                     replayed=0))
    assert out['error'] == 'no_metrics'
    out = _attack().collect(_metrics(_frames(bytes(64)), _victim(STEADY),
                                     replayed=None))
    assert out['error'] == 'no_metrics'


def test_the_sidecar_shares_the_targets_namespace_and_keeps_its_frames():
    doc = mm.compose(honest=3, capture_s=600, replay_at_s=660)
    side = doc['services']['mitm']
    assert side['network_mode'] == 'service:honest-1'
    assert side['cap_add'] == ['NET_RAW']
    assert side['user'] == 'root'
    assert 'networks' not in side
    assert side['volumes'] == ['{artifacts}:/capture']
    env = side['environment']
    assert env['AUTONOMOUS_TRUST_EXE'] == '-m autonomous_trust.evaluation.redteam.mitm_sidecar'
    assert env['MITM_TARGET'] == doc['services']['honest-1']['networks']['redteam']['ipv4_address']
    assert env['MITM_VICTIM'] == doc['services']['honest-2']['networks']['redteam']['ipv4_address']
    attack = mm.MitmAttack(honest=3)
    sim, comp = {}, {}
    attack.setup(sim, comp)
    assert comp['standalone'] is True and comp['artifacts'] == '{artifacts}'
    assert sim['collect_logs'] == ['honest-2', 'mitm']


def _packet(src, dst, sport, dport, payload):
    eth = b'\x00' * 12 + struct.pack('!H', 0x0800)
    ihl = 5
    ip = struct.pack('!BBHHHBBH4s4s', (4 << 4) | ihl, 0, 20 + 8 + len(payload),
                     0, 0, 64, 17, 0, bytes(map(int, src.split('.'))),
                     bytes(map(int, dst.split('.'))))
    udp = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0)
    return eth + ip + udp + payload


def test_the_sidecar_parses_udp_on_the_at_ports_only():
    pkt = _packet('10.34.0.10', '10.34.0.11', 40000, 27787, b'abc')
    assert sc.parse_frame(pkt) == ('10.34.0.10', '10.34.0.11', 40000, 27787, b'abc')
    assert sc.parse_frame(_packet('10.34.0.10', '10.34.0.11', 40000, 53, b'x')) is None
    assert sc.parse_frame(_packet('10.34.0.11', '10.34.0.10', 27788, 41000, b'y'))[4] == b'y'
    assert sc.parse_frame(b'\x00' * 14 + b'\x86\xdd') is None


def test_the_sidecar_replays_only_target_to_victim_point_to_point():
    rows = [{'src': 'T', 'dst': 'V', 'dport': 27787, 'hex': '01'},
            {'src': 'T', 'dst': 'V', 'dport': 27788, 'hex': '02'},
            {'src': 'V', 'dst': 'T', 'dport': 27787, 'hex': '03'},
            {'src': 'T', 'dst': 'X', 'dport': 27787, 'hex': '04'},
            {'src': 'T', 'dst': 'V', 'dport': 27787, 'hex': '05'}]
    assert sc.replayable(rows, 'T', 'V') == [b'\x01', b'\x05']


def test_an_empty_capture_is_no_data():
    out = _attack().collect(_metrics('', _victim(STEADY)))
    assert out['error'] == 'no_metrics'


def test_a_replay_with_no_control_or_no_target_is_no_data():
    out = mm.MitmAttack(honest=2).collect(
        _metrics(_frames(bytes(64)), _victim(STEADY)))
    assert out['error'] == 'no_metrics'
    hidden = _victim(STEADY).replace('honest-1@', 'other@')
    out = _attack().collect(_metrics(_frames(bytes(64)), hidden))
    assert out['error'] == 'no_metrics'
