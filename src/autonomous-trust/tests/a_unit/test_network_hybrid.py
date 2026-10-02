# ******************
#  Copyright 2023 TekFive, Inc., Sean M. Brennan, and contributors
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
"""The hybrid transport (core/_python/network/hybrid.py): C's routing rule
case for case (src/c/test/hybrid_route_test.c), its configuration checks, and
how the process hands sends to its legs."""
import logging
from types import SimpleNamespace

import pytest

from autonomous_trust.core.network import hybrid
from autonomous_trust.core.network.hybrid import (HybridConfig, HybridInner, HybridNetworkProcess,
                                                  addr_in_cidr, hybrid_config_from_json,
                                                  hybrid_route, group_route_lookup, leg_class)
from autonomous_trust.core.network.netprocess import TransmissionError


def _cfg(*inners):
    return HybridConfig(inners=[HybridInner(kind, cidr or '', eid, dflt)
                                for kind, cidr, eid, dflt in inners])


LAN_DTN = (('udp_net_4', '10.0.0.0/24', False, False), ('dtn_bp', None, True, True))
TWO_LANS = (('udp_net_4', '10.0.0.0/24', False, False), ('udp_net_4', '172.20.0.0/16', False, False))


# ---- hybrid_route: the cases in hybrid_route_test.c ----

def test_cidr_match_wins():
    assert hybrid_route(_cfg(*LAN_DTN), '10.0.0.5') == 0


def test_eid_goes_to_the_eid_leg():
    assert hybrid_route(_cfg(*LAN_DTN), 'dtn://at-abcd/peer') == 1
    assert hybrid_route(_cfg(*LAN_DTN), 'ipn:42.1') == 1


def test_unmatched_falls_to_the_default():
    assert hybrid_route(_cfg(*LAN_DTN), '192.168.1.10') == 1


def test_two_cidrs():
    assert hybrid_route(_cfg(*TWO_LANS), '10.0.0.50') == 0
    assert hybrid_route(_cfg(*TWO_LANS), '172.20.5.10') == 1


def test_no_default_no_route():
    assert hybrid_route(_cfg(*TWO_LANS), '192.168.1.10') == -1
    assert hybrid_route(_cfg(*TWO_LANS), 'dtn://at-x/peer') == -1


def test_cidr_edges():
    cfg = _cfg(('udp_net_4', '192.168.1.0/24', False, False))
    assert hybrid_route(cfg, '192.168.1.0') == 0
    assert hybrid_route(cfg, '192.168.1.255') == 0
    assert hybrid_route(cfg, '192.168.0.255') == -1
    assert hybrid_route(cfg, '192.168.2.0') == -1


def test_slash_zero_takes_every_v4_and_no_eid():
    cfg = _cfg(('udp_net_4', '0.0.0.0/0', False, False))
    assert hybrid_route(cfg, '1.2.3.4') == 0
    assert hybrid_route(cfg, '255.255.255.255') == 0
    assert hybrid_route(cfg, 'dtn://x/') == -1


def test_first_default_wins_and_order_matters():
    cfg = _cfg(('udp_net_4', None, False, True), ('tcp_net_4', None, False, True))
    assert hybrid_route(cfg, 'anything') == 0
    cfg = _cfg(('dtn_bp', None, True, False), ('udp_net_4', '0.0.0.0/0', False, False))
    assert hybrid_route(cfg, 'ipn:1.1') == 0


# ---- the matchers ----

def test_v6_cidrs():
    assert addr_in_cidr('fd00::5', 'fd00::/64')
    assert not addr_in_cidr('fd01::5', 'fd00::/64')
    assert addr_in_cidr('fd00:0:0:0:8000::1', 'fd00::/65') is False
    assert addr_in_cidr('fd00:0:0:0:7fff::1', 'fd00::/65')
    assert addr_in_cidr('::ffff:10.0.0.1', '::ffff:10.0.0.0/120')
    assert addr_in_cidr('::1', '::/0')


def test_family_never_crosses():
    assert not addr_in_cidr('10.0.0.1', 'fd00::/8')
    assert not addr_in_cidr('fd00::1', '10.0.0.0/8')


def test_malformed_cidrs_match_nothing():
    for bad in ('10.0.0.0', '10.0.0.0/33', '10.0.0.0/-1', 'ten/8', '010.0.0.0/8', 'fd00::/129'):
        assert not addr_in_cidr('10.0.0.1', bad) and not addr_in_cidr('fd00::1', bad), bad
    assert not addr_in_cidr(None, '10.0.0.0/8')
    assert not addr_in_cidr('10.0.0.1', None)


def test_prefix_read_as_c_atoi_reads_it():
    # atoi("24junk") is 24, atoi("junk") is 0 (so /junk matches everything v4).
    assert addr_in_cidr('10.0.0.9', '10.0.0.0/24junk')
    assert addr_in_cidr('99.1.2.3', '10.0.0.0/junk')


# ---- configuration ----

GOOD = {
    'typename': 'hybrid_net',
    'inners': [
        {'kind': 'udp_net_4', 'match_cidr': '10.0.0.0/24',
         'net_cfg': {'typename': 'network', 'ip4_cidr': '10.0.0.7/24', 'port': 27787}},
        {'kind': 'dtn_bp', 'match_eid': True, 'is_default': True},
    ],
    'is_gateway': True,
    'group_routes': [{'group_uuid': '11223344-5566-7788-99AA-BBCCDDEEFF00', 'leg_index': 1}],
}


def test_reads_cs_shape():
    cfg = hybrid_config_from_json(GOOD)
    assert [i.kind for i in cfg.inners] == ['udp_net_4', 'dtn_bp']
    assert cfg.inners[0].match_cidr == '10.0.0.0/24' and cfg.inners[0].net_cfg['port'] == 27787
    assert cfg.inners[1].match_eid and cfg.inners[1].is_default and cfg.inners[1].net_cfg is None
    assert cfg.is_gateway
    assert group_route_lookup(cfg, '11223344-5566-7788-99aa-bbccddeeff00') == 1
    assert group_route_lookup(cfg, '00000000-0000-0000-0000-000000000000') is None
    assert group_route_lookup(cfg, 'not-a-uuid') is None


@pytest.mark.parametrize('mutate', [
    lambda c: c.pop('inners'),
    lambda c: c.update(inners=[]),
    lambda c: c.update(inners=[{'kind': 'udp_net_4'}] * 5),
    lambda c: c['inners'][0].pop('kind'),
    lambda c: c['inners'][0].update(kind=7),
    lambda c: c.update(group_routes=[{'group_uuid': 'nope', 'leg_index': 0}]),
    lambda c: c.update(group_routes=[{'group_uuid': GOOD['group_routes'][0]['group_uuid'],
                                      'leg_index': 2}]),
    lambda c: c.update(group_routes=[{'group_uuid': GOOD['group_routes'][0]['group_uuid'],
                                      'leg_index': -1}]),
    lambda c: c.update(group_routes=[GOOD['group_routes'][0]] * 9),
])
def test_refuses_what_c_refuses(mutate):
    import copy
    bad = copy.deepcopy(GOOD)
    mutate(bad)
    with pytest.raises(ValueError):
        hybrid_config_from_json(bad)


def test_leg_kinds():
    from autonomous_trust.core.network.udp import UDPNetworkProcess
    from autonomous_trust.core.network.tcp import TCPNetworkProcess
    assert leg_class('udp_net_4') is UDPNetworkProcess
    assert leg_class('tcp_net_4') is TCPNetworkProcess
    with pytest.raises(ValueError, match='only in the C runtime'):
        leg_class('udp_net_6')
    with pytest.raises(ValueError, match='cannot itself be hybrid'):
        leg_class('hybrid_net')
    with pytest.raises(ValueError, match='not registered'):
        leg_class('carrier_pigeon')


def test_extension_supplies_a_leg_kind(monkeypatch):
    monkeypatch.setattr(hybrid, 'transport_class',
                        lambda kind: 'autonomous_trust.core.network.udp.UDPNetworkProcess'
                        if kind == 'dtn_bp' else None)
    assert leg_class('dtn_bp').__name__ == 'UDPNetworkProcess'


# ---- the process and its legs ----

class FakeLeg(object):
    def __init__(self, configurations, subsystems, log_q, acceptance_func=None, **kwargs):
        self.net_cfg = configurations['network']
        self.sent = []
        self.stop = False
        self.fail = False
        self.calls = []

    def send_peer(self, msg, host):
        self.sent.append(('peer', host, msg))

    def send_group(self, msg, host):
        self.sent.append(('group', host, msg))

    def send_any(self, msg):
        if self.fail:
            raise TransmissionError('leg down')
        self.sent.append(('any', None, msg))

    def close_connections(self):
        self.calls.append(('close', self.stop))

    def close_listeners(self):
        self.calls.append('listeners')

    def rebind_socket_timeouts(self):
        self.calls.append('rebind')

    def _init_transport(self):
        self.calls.append('init')

    def reap_idle_conns(self):
        self.calls.append('reap')

    def link_class_ms(self, target=None):
        return 60000


def _proc(monkeypatch, raw=GOOD):
    monkeypatch.setattr(hybrid, 'leg_class', lambda kind: FakeLeg)
    proc = HybridNetworkProcess.__new__(HybridNetworkProcess)
    proc.logger = logging.getLogger('hybrid-test')
    proc.net_cfg = 'node-net-cfg'
    for name in hybrid._SHARED:
        setattr(proc, name, object())
    proc.hybrid_cfg = hybrid_config_from_json(raw)
    proc.legs = proc._open_legs({'network': 'node-net-cfg'}, None, None, None)
    return proc


def test_legs_share_the_process_state(monkeypatch):
    proc = _proc(monkeypatch)
    for leg in proc.legs:
        for name in hybrid._SHARED:
            assert getattr(leg, name) is getattr(proc, name), name
    # A leg with C's serialized net_cfg gets a NetworkConfig from it; one
    # without uses the node's own.
    assert proc.legs[0].net_cfg.ip4 == '10.0.0.7'
    assert proc.legs[0].net_cfg.port == 27787
    assert proc.legs[1].net_cfg == 'node-net-cfg'


def test_unicast_takes_the_routed_leg(monkeypatch):
    proc = _proc(monkeypatch)
    proc.send_peer(b'a', '10.0.0.9')
    proc.send_group(b'b', 'dtn://at-1/peer')
    proc.send_peer(b'c', '192.168.9.9')
    assert proc.legs[0].sent == [('peer', '10.0.0.9', b'a')]
    assert proc.legs[1].sent == [('group', 'dtn://at-1/peer', b'b'), ('peer', '192.168.9.9', b'c')]
    assert proc.link_class_ms('ipn:1.1') == 60000


def test_no_route_is_a_transmission_error(monkeypatch):
    raw = dict(GOOD, inners=[{'kind': 'udp_net_4', 'match_cidr': '10.0.0.0/24'}], group_routes=[])
    proc = _proc(monkeypatch, raw)
    with pytest.raises(TransmissionError, match='no inner matches'):
        proc.send_peer(b'x', '192.168.0.1')
    assert proc.link_class_ms('192.168.0.1') == -1


def test_broadcast_fans_out_and_fails_only_on_every_leg(monkeypatch):
    proc = _proc(monkeypatch)
    proc.send_any(b'hi')
    assert [leg.sent for leg in proc.legs] == [[('any', None, b'hi')]] * 2
    proc.legs[0].fail = True
    proc.send_any(b'still')
    assert proc.legs[1].sent[-1] == ('any', None, b'still')
    proc.legs[1].fail = True
    with pytest.raises(TransmissionError, match='every leg'):
        proc.send_any(b'nobody')
    proc.legs[1].fail = False
    proc.send_on_leg(1, b'one')
    assert proc.legs[1].sent[-1] == ('any', None, b'one')
    with pytest.raises(TransmissionError):
        proc.send_on_leg(2, b'x')


def test_lifecycle_reaches_every_leg(monkeypatch):
    proc = _proc(monkeypatch)
    proc.rebind_socket_timeouts()
    proc._init_transport()
    proc.reap_idle_conns()
    proc.close_connections()
    proc.close_listeners()
    for leg in proc.legs:
        # Every leg is stopped before any is closed.
        assert leg.calls == ['rebind', 'init', 'reap', ('close', True), 'listeners']
    assert proc.unknown_receiver() is None
    assert proc.is_gateway


def test_missing_config_refuses(monkeypatch):
    monkeypatch.setattr(hybrid.NetworkProcess, '__init__', lambda self, *a, **k: None)
    proc = HybridNetworkProcess.__new__(HybridNetworkProcess)
    with pytest.raises(ValueError, match='hybrid_net.cfg.json'):
        HybridNetworkProcess.__init__(proc, {}, None, None)
