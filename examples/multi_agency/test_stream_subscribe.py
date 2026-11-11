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

"""The coordinator's data sink subscribes to the disaster-response streams.

The peers (disaster_response_demo) advertise their role stream, e.g.
``weather_stream``, served by a process named ``weather-stream``; none offers
the generic ``data`` capability. The sink looked only for ``data``, so it never
subscribed and the dashboard's Data Streams panel stayed empty.
"""
import queue
from types import SimpleNamespace

import pytest

from autonomous_trust.core.identity import Identity
from examples.multi_agency import coordinator

pytestmark = pytest.mark.skipif(not coordinator.HAS_DATA,
                                reason="autonomous_trust.services absent")


class _Peers:
    def __init__(self, idents):
        self.all = idents

    def find_by_uuid(self, uuid):
        for i in self.all:
            if str(i.uuid) == str(uuid):
                return i
        return None


def _sink(peer_caps, idents):
    sink = coordinator.DiagDataRcvr.__new__(coordinator.DiagDataRcvr)
    sink.name = 'data-sink'
    sink.q_cadence = 0.01
    sink.servicers = []
    sink.logger = SimpleNamespace(info=lambda *a, **k: None)
    sink.protocol = SimpleNamespace(peer_capabilities=peer_caps,
                                    peers=_Peers(idents))
    return sink


def _ident(nick):
    return Identity.initialize(nick, nick, '10.0.0.1')


def _sent(queues):
    out = []
    q = queues[coordinator._DQ_CfgIds.network]
    while not q.empty():
        out.append(q.get_nowait())
    return out


def test_a_weather_stream_peer_gets_a_subscribe_to_its_stream_process():
    noaa = _ident('noaa-1@tekfive.com')
    sink = _sink({'weather_stream': [noaa.uuid],
                  'sensor_validation': [noaa.uuid]}, [noaa])
    queues = {coordinator._DQ_CfgIds.network: queue.Queue()}
    sink._subscribe_new_streams(queues)
    sent = _sent(queues)
    assert [(m.process, m.function, m.obj) for m in sent] == [
        ('weather-stream', coordinator._DQ_DataProtocol.request, 'data-sink')]
    # Once only.
    sink._subscribe_new_streams(queues)
    assert _sent(queues) == []


def test_every_disaster_stream_and_generic_data_are_covered():
    caps = {'weather_stream': 'weather-stream',
            'seismic_stream': 'seismic-stream',
            'airquality_stream': 'airquality-stream',
            'situation_report': 'situation-report',
            'data_fusion': 'data-fusion'}
    idents = {cap: _ident(cap) for cap in caps}
    data_peer = _ident('dod-like')
    peer_caps = {cap: [i.uuid] for cap, i in idents.items()}
    peer_caps[coordinator._DQ_DataProcess.capability_name] = [data_peer.uuid]
    sink = _sink(peer_caps, list(idents.values()) + [data_peer])
    queues = {coordinator._DQ_CfgIds.network: queue.Queue()}
    sink._subscribe_new_streams(queues)
    got = {m.process for m in _sent(queues)}
    assert got == set(caps.values()) | {coordinator._DQ_DataProcess.name}


def test_a_peer_not_yet_known_is_retried():
    noaa = _ident('noaa-1@tekfive.com')
    sink = _sink({'weather_stream': [noaa.uuid]}, [])
    queues = {coordinator._DQ_CfgIds.network: queue.Queue()}
    sink._subscribe_new_streams(queues)
    assert _sent(queues) == []
    sink.protocol.peers.all.append(noaa)
    sink._subscribe_new_streams(queues)
    assert [m.process for m in _sent(queues)] == ['weather-stream']
