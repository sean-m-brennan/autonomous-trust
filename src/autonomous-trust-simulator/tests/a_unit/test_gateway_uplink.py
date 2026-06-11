# ******************
#  Copyright 2025 Sean M. Brennan and contributors
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

from datetime import datetime, timedelta
from uuid import uuid4

import pytest

try:
    from autonomous_trust.simulator.peer.peer import GatewayUplink, PeerInfo
except ImportError as _e:
    pytestmark = pytest.mark.skip(reason=f"missing dependency: {_e}")
    GatewayUplink = PeerInfo = None

try:
    from autonomous_trust.services.peer.position import GeoPosition, UTMPosition
    from autonomous_trust.simulator.peer.path import PointData, PathData, Variability
    from autonomous_trust.simulator.radio.iface import Antenna, NetInterface
    from autonomous_trust.simulator.sim_data import SimConfig
except ImportError:
    pass


class TestGatewayUplink:
    def test_create_fiber_uplink(self):
        uplink = GatewayUplink('fiber', 1000.0, 1000.0, 0.99)
        assert uplink.technology == 'fiber'
        assert uplink.bandwidth_down_mbps == 1000.0
        assert uplink.bandwidth_up_mbps == 1000.0
        assert uplink.reliability == 0.99

    def test_default_reliability(self):
        uplink = GatewayUplink('cable', 1000.0, 35.0)
        assert uplink.reliability == 0.99

    def test_json_round_trip(self):
        uplink = GatewayUplink('fiber', 1000.0, 1000.0, 0.99)
        json_str = uplink.to_json_string()
        restored = GatewayUplink.from_json_string(json_str)
        assert restored.technology == 'fiber'
        assert restored.bandwidth_down_mbps == 1000.0
        assert restored.bandwidth_up_mbps == 1000.0
        assert restored.reliability == 0.99

    def test_reject_negative_bandwidth(self):
        with pytest.raises(Exception):
            GatewayUplink('fiber', -100.0, 1000.0)

    def test_reject_zero_bandwidth(self):
        with pytest.raises(Exception):
            GatewayUplink('fiber', 0.0, 1000.0)

    def test_reject_reliability_above_one(self):
        with pytest.raises(Exception):
            GatewayUplink('fiber', 1000.0, 1000.0, 1.5)

    def test_reject_reliability_below_zero(self):
        with pytest.raises(Exception):
            GatewayUplink('fiber', 1000.0, 1000.0, -0.1)


class TestPeerInfoUplink:
    def _make_peer(self, uplink=None):
        """Helper: create a minimal PeerInfo."""
        start = datetime(2026, 1, 1)
        end = start + timedelta(hours=1)
        pos = GeoPosition(38.66, -80.71, 670).convert(UTMPosition)
        shape = PointData(pos)
        path = PathData(start, end, shape, Variability.UNIFORM, 0, Variability.UNIFORM)
        return PeerInfo(
            uuid=str(uuid4()), kind='valley_relay', petname='test_node',
            ip4_addr='10.0.0.1', initial_position=pos, signal=20.0,
            antenna=Antenna.DIPOLE, iface=NetInterface.SMALL,
            initial_time=start, last_seen=end, path_list=[path],
            data_streams=[], uplink=uplink,
        )

    def test_peer_without_uplink(self):
        peer = self._make_peer()
        assert peer.uplink is None

    def test_peer_with_uplink(self):
        uplink = GatewayUplink('fiber', 1000.0, 1000.0, 0.99)
        peer = self._make_peer(uplink=uplink)
        assert peer.uplink is not None
        assert peer.uplink.technology == 'fiber'

    def test_peer_uplink_json_round_trip(self):
        uplink = GatewayUplink('fiber', 1000.0, 1000.0, 0.99)
        peer = self._make_peer(uplink=uplink)
        json_str = peer.to_json_string()
        restored = PeerInfo.from_json_string(json_str)
        assert restored.uplink is not None
        assert restored.uplink.technology == 'fiber'
        assert restored.uplink.bandwidth_down_mbps == 1000.0

    def test_peer_without_uplink_json_round_trip(self):
        peer = self._make_peer()
        json_str = peer.to_json_string()
        restored = PeerInfo.from_json_string(json_str)
        assert restored.uplink is None

    def test_simconfig_with_uplink_peers(self):
        """SimConfig serialization handles peers with uplinks."""
        start = datetime(2026, 1, 1)
        end = start + timedelta(hours=1)
        uplink = GatewayUplink('cable', 1000.0, 35.0, 0.97)
        peer1 = self._make_peer(uplink=uplink)
        peer2 = self._make_peer()  # no uplink
        config = SimConfig(start=start, end=end, peers=[peer1, peer2])
        json_str = config.to_json_string()
        restored = SimConfig.load(json_str)
        assert restored.peers[0].uplink is not None
        assert restored.peers[0].uplink.technology == 'cable'
        assert restored.peers[1].uplink is None


try:
    from autonomous_trust.simulator.sim_data import SimState, GatewayMap
except ImportError:
    pass


class TestSimStateGateways:
    def test_simstate_default_gateways_none(self):
        state = SimState()
        assert state.gateways is None or state.gateways == {}
        assert state.gateway_count == 0
        assert state.aggregate_uplink_down_mbps == 0.0
        assert state.aggregate_uplink_up_mbps == 0.0
        assert state.per_node_down_mbps == 0.0

    def test_simstate_with_gateways(self):
        from autonomous_trust.simulator.peer.peer import GatewayUplink
        gw_map: GatewayMap = {
            'uuid-1': GatewayUplink('fiber', 1000.0, 1000.0, 0.99),
            'uuid-2': GatewayUplink('cable', 1000.0, 35.0, 0.97),
        }
        state = SimState(
            gateways=gw_map,
            gateway_count=2,
            aggregate_uplink_down_mbps=2000.0,
            aggregate_uplink_up_mbps=1035.0,
            per_node_down_mbps=0.0,
        )
        assert state.gateway_count == 2
        assert state.aggregate_uplink_down_mbps == 2000.0
        assert state.aggregate_uplink_up_mbps == 1035.0
        assert len(state.gateways) == 2

    def test_simstate_gateway_json_round_trip(self):
        from autonomous_trust.simulator.peer.peer import GatewayUplink
        gw_map: GatewayMap = {
            'uuid-1': GatewayUplink('fiber', 1000.0, 1000.0, 0.99),
        }
        state = SimState(
            gateways=gw_map,
            gateway_count=1,
            aggregate_uplink_down_mbps=1000.0,
            aggregate_uplink_up_mbps=1000.0,
            per_node_down_mbps=50.0,
        )
        json_str = state.to_json_string()
        restored = SimState.from_json_string(json_str)
        assert restored.gateway_count == 1
        assert restored.aggregate_uplink_down_mbps == 1000.0


import random


class TestSimulatorGatewayResolution:
    @staticmethod
    def _build_gateway_map(peers, rand_func=None):
        if rand_func is None:
            rand_func = random.random
        gateways = {}
        for peer in peers:
            if peer.uplink is not None and rand_func() < peer.uplink.reliability:
                gateways[peer.uuid] = peer.uplink
        return gateways

    def _make_peer_with_uplink(self, name, uplink=None):
        from autonomous_trust.simulator.peer.peer import GatewayUplink
        start = datetime(2026, 1, 1)
        end = start + timedelta(hours=1)
        pos = GeoPosition(38.66, -80.71, 670).convert(UTMPosition)
        shape = PointData(pos)
        path = PathData(start, end, shape, Variability.UNIFORM, 0, Variability.UNIFORM)
        from examples.appalachia.scenario import _generate_uuid
        return PeerInfo(
            uuid=_generate_uuid(name), kind='valley_relay', petname=name,
            ip4_addr='10.0.0.1', initial_position=pos, signal=20.0,
            antenna=Antenna.DIPOLE, iface=NetInterface.SMALL,
            initial_time=start, last_seen=end, path_list=[path],
            data_streams=[], uplink=uplink,
        )

    def test_no_uplink_peers_empty_map(self):
        peers = [self._make_peer_with_uplink('node_a'), self._make_peer_with_uplink('node_b')]
        gateways = self._build_gateway_map(peers)
        assert len(gateways) == 0

    def test_uplink_peer_included(self):
        from autonomous_trust.simulator.peer.peer import GatewayUplink
        uplink = GatewayUplink('fiber', 1000.0, 1000.0, 0.99)
        peers = [
            self._make_peer_with_uplink('gateway_node', uplink=uplink),
            self._make_peer_with_uplink('relay_node'),
        ]
        gateways = self._build_gateway_map(peers, rand_func=lambda: 0.0)
        assert len(gateways) == 1

    def test_reliability_zero_excludes_all(self):
        from autonomous_trust.simulator.peer.peer import GatewayUplink
        uplink = GatewayUplink('fiber', 1000.0, 1000.0, reliability=0.0)
        peers = [self._make_peer_with_uplink('gateway_node', uplink=uplink)]
        gateways = self._build_gateway_map(peers, rand_func=lambda: 0.5)
        assert len(gateways) == 0

    def test_reliability_one_includes_all(self):
        from autonomous_trust.simulator.peer.peer import GatewayUplink
        uplink = GatewayUplink('fiber', 1000.0, 1000.0, reliability=1.0)
        peers = [self._make_peer_with_uplink('gateway_node', uplink=uplink)]
        gateways = self._build_gateway_map(peers, rand_func=lambda: 0.999)
        assert len(gateways) == 1

    def test_multiple_gateways(self):
        from autonomous_trust.simulator.peer.peer import GatewayUplink
        fiber = GatewayUplink('fiber', 1000.0, 1000.0, 1.0)
        cable = GatewayUplink('cable', 1000.0, 35.0, 1.0)
        peers = [
            self._make_peer_with_uplink('fiber_gw', uplink=fiber),
            self._make_peer_with_uplink('cable_gw', uplink=cable),
            self._make_peer_with_uplink('relay'),
        ]
        gateways = self._build_gateway_map(peers, rand_func=lambda: 0.0)
        assert len(gateways) == 2


import os
import tempfile


class TestAppalachianGateways:
    def test_full_scenario_has_four_gateways(self):
        from examples.appalachia.scenario import create_appalachian_config
        with tempfile.NamedTemporaryFile(suffix='.cfg', delete=False) as f:
            cfg_path = f.name
        try:
            create_appalachian_config(output_file=cfg_path)
            with open(cfg_path, 'r') as f:
                cfg = SimConfig.load(f.read())
            gateway_peers = [p for p in cfg.peers if p.uplink is not None]
            assert len(gateway_peers) == 4
        finally:
            if os.path.exists(cfg_path):
                os.remove(cfg_path)

    def test_gateway_technologies(self):
        from examples.appalachia.scenario import create_appalachian_config
        with tempfile.NamedTemporaryFile(suffix='.cfg', delete=False) as f:
            cfg_path = f.name
        try:
            create_appalachian_config(output_file=cfg_path)
            with open(cfg_path, 'r') as f:
                cfg = SimConfig.load(f.read())
            gateways = {p.petname: p.uplink for p in cfg.peers if p.uplink is not None}
            assert gateways['sutton_valley_1'].technology == 'fiber'
            assert gateways['burnsville_valley_1'].technology == 'fiber'
            assert gateways['gassaway_valley'].technology == 'fiber'
            assert gateways['flatwoods_valley'].technology == 'cable'
        finally:
            if os.path.exists(cfg_path):
                os.remove(cfg_path)

    def test_fiber_gateways_symmetric_bandwidth(self):
        from examples.appalachia.scenario import create_appalachian_config
        with tempfile.NamedTemporaryFile(suffix='.cfg', delete=False) as f:
            cfg_path = f.name
        try:
            create_appalachian_config(output_file=cfg_path)
            with open(cfg_path, 'r') as f:
                cfg = SimConfig.load(f.read())
            fiber_gws = [p for p in cfg.peers if p.uplink and p.uplink.technology == 'fiber']
            for gw in fiber_gws:
                assert gw.uplink.bandwidth_down_mbps == gw.uplink.bandwidth_up_mbps
        finally:
            if os.path.exists(cfg_path):
                os.remove(cfg_path)

    def test_cable_gateway_asymmetric_bandwidth(self):
        from examples.appalachia.scenario import create_appalachian_config
        with tempfile.NamedTemporaryFile(suffix='.cfg', delete=False) as f:
            cfg_path = f.name
        try:
            create_appalachian_config(output_file=cfg_path)
            with open(cfg_path, 'r') as f:
                cfg = SimConfig.load(f.read())
            cable_gws = [p for p in cfg.peers if p.uplink and p.uplink.technology == 'cable']
            assert len(cable_gws) == 1
            assert cable_gws[0].uplink.bandwidth_down_mbps > cable_gws[0].uplink.bandwidth_up_mbps
        finally:
            if os.path.exists(cfg_path):
                os.remove(cfg_path)

    def test_hilltop_only_no_gateways(self):
        from examples.appalachia.scenario import create_appalachian_config
        with tempfile.NamedTemporaryFile(suffix='.cfg', delete=False) as f:
            cfg_path = f.name
        try:
            create_appalachian_config(output_file=cfg_path, hilltop_only=True)
            with open(cfg_path, 'r') as f:
                cfg = SimConfig.load(f.read())
            gateway_peers = [p for p in cfg.peers if p.uplink is not None]
            assert len(gateway_peers) == 0
        finally:
            if os.path.exists(cfg_path):
                os.remove(cfg_path)
