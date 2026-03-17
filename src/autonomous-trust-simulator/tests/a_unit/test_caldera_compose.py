"""Tests for caldera_compose YAML patching."""

import json
import os
import pytest
import yaml

from autonomous_trust.simulator.redteam.caldera_compose import (
    patch_caldera,
    CALDERA_IP, CALDERA_PORT, CALDERA_IMAGE,
)


SAMPLE_COMPOSE = """
services:
  sutton_hilltop:
    image: autonomous-trust
    container_name: sutton_hilltop
    hostname: sutton_hilltop
    cap_add:
      - NET_ADMIN
    environment:
      ROUTER: "10.27.3.1"
      AUTONOMOUS_TRUST_BACKEND: "native"
    networks:
      at-net:
        ipv4_address: 10.27.3.11
  burnsville_hilltop:
    image: autonomous-trust
    container_name: burnsville_hilltop
    hostname: burnsville_hilltop
    cap_add:
      - NET_ADMIN
    environment:
      ROUTER: "10.27.3.1"
      AUTONOMOUS_TRUST_BACKEND: "native"
    networks:
      at-net:
        ipv4_address: 10.27.3.12
networks:
  at-net:
    driver: bridge
    ipam:
      config:
        - subnet: 10.27.3.0/24
"""


class TestPatchCalderaServer:

    def test_adds_caldera_server_service(self, tmp_path):
        result = yaml.safe_load(patch_caldera(SAMPLE_COMPOSE, [], {}, str(tmp_path)))
        assert 'caldera-server' in result['services']

    def test_caldera_server_ip(self, tmp_path):
        result = yaml.safe_load(patch_caldera(SAMPLE_COMPOSE, [], {}, str(tmp_path)))
        svc = result['services']['caldera-server']
        assert svc['networks']['at-net']['ipv4_address'] == CALDERA_IP

    def test_caldera_server_image_pinned(self, tmp_path):
        result = yaml.safe_load(patch_caldera(SAMPLE_COMPOSE, [], {}, str(tmp_path)))
        assert result['services']['caldera-server']['image'] == CALDERA_IMAGE


class TestPatchSandcat:

    def test_at_services_get_entrypoint_override(self, tmp_path):
        result = yaml.safe_load(patch_caldera(SAMPLE_COMPOSE, [], {}, str(tmp_path)))
        svc = result['services']['sutton_hilltop']
        assert svc['entrypoint'] == ['/usr/local/bin/caldera_sandcat_wrapper.sh']

    def test_at_services_get_volume_mount(self, tmp_path):
        result = yaml.safe_load(patch_caldera(SAMPLE_COMPOSE, [], {}, str(tmp_path)))
        svc = result['services']['sutton_hilltop']
        volumes = svc.get('volumes', [])
        assert any('/tmp/caldera-config' in str(v) for v in volumes)

    def test_at_services_image_upgraded(self, tmp_path):
        result = yaml.safe_load(patch_caldera(SAMPLE_COMPOSE, [], {}, str(tmp_path)))
        for name in ('sutton_hilltop', 'burnsville_hilltop'):
            assert result['services'][name]['image'] == 'autonomous-trust-full-devel'

    def test_wrapper_script_written_to_work_dir(self, tmp_path):
        patch_caldera(SAMPLE_COMPOSE, [], {}, str(tmp_path))
        assert (tmp_path / 'caldera_sandcat_wrapper.sh').exists()


class TestPatchAttackConfig:

    def test_sybil_adds_sybil_services(self, tmp_path):
        config = {'num_sybil_nodes': 2, 'base_ip_offset': 30}
        result = yaml.safe_load(
            patch_caldera(SAMPLE_COMPOSE, ['sybil'], config, str(tmp_path)))
        assert 'sybil-1' in result['services']
        assert 'sybil-2' in result['services']

    def test_byzantine_adds_env_var(self, tmp_path):
        config = {'byzantine_peer_ids': ['sutton_hilltop']}
        result = yaml.safe_load(
            patch_caldera(SAMPLE_COMPOSE, ['byzantine'], config, str(tmp_path)))
        env = result['services']['sutton_hilltop']['environment']
        assert env.get('BYZANTINE_MODE') == 'true'

    def test_gaming_adds_env_vars(self, tmp_path):
        config = {'gaming_peer_ids': ['burnsville_hilltop'], 'defection_time_s': 45.0}
        result = yaml.safe_load(
            patch_caldera(SAMPLE_COMPOSE, ['reputation_gaming'], config, str(tmp_path)))
        env = result['services']['burnsville_hilltop']['environment']
        assert env.get('GAMING_MODE') == 'true'
        assert env.get('DEFECTION_TIME_S') == '45.0'

    def test_config_json_written(self, tmp_path):
        config = {'num_sybil_nodes': 3}
        patch_caldera(SAMPLE_COMPOSE, ['sybil'], config, str(tmp_path))
        cfg_path = tmp_path / 'caldera-config' / 'attack-config.json'
        assert cfg_path.exists()
        assert json.loads(cfg_path.read_text())['num_sybil_nodes'] == 3

    def test_no_attacks_no_extra_services(self, tmp_path):
        result = yaml.safe_load(patch_caldera(SAMPLE_COMPOSE, [], {}, str(tmp_path)))
        service_names = set(result['services'].keys())
        assert service_names == {'caldera-server', 'sutton_hilltop', 'burnsville_hilltop'}
