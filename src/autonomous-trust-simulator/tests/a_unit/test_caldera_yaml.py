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
"""Tests that CALDERA YAML files are valid and reference correct ability IDs."""

import os
import pytest
import yaml

_RT_DIR = os.path.join(os.path.dirname(__file__), '..', '..', '..',
                       'autonomous-trust-evaluation',
                       'autonomous_trust', 'evaluation', 'redteam')
ABILITIES_DIR = os.path.join(_RT_DIR, 'caldera_abilities')
PROFILES_DIR = os.path.join(_RT_DIR, 'adversary_profiles')

ABILITY_FILES = ['sybil_collect.yaml', 'byzantine_collect.yaml', 'gaming_collect.yaml']
PROFILE_FILES = ['sybil.yaml', 'byzantine.yaml', 'reputation_gaming.yaml']


class TestAbilityFiles:

    @pytest.mark.parametrize('filename', ABILITY_FILES)
    def test_ability_is_valid_yaml(self, filename):
        path = os.path.join(ABILITIES_DIR, filename)
        with open(path) as f:
            data = yaml.safe_load(f)
        assert isinstance(data, list) and len(data) == 1
        ability = data[0]
        assert 'id' in ability
        assert 'name' in ability
        assert 'executors' in ability

    @pytest.mark.parametrize('filename', ABILITY_FILES)
    def test_ability_uses_sh_executor(self, filename):
        path = os.path.join(ABILITIES_DIR, filename)
        with open(path) as f:
            ability = yaml.safe_load(f)[0]
        executor = ability['executors'][0]
        assert executor['name'] == 'sh'
        assert executor['platform'] == 'linux'

    @pytest.mark.parametrize('filename', ABILITY_FILES)
    def test_ability_command_invokes_bridge(self, filename):
        path = os.path.join(ABILITIES_DIR, filename)
        with open(path) as f:
            ability = yaml.safe_load(f)[0]
        cmd = ability['executors'][0]['command']
        assert 'caldera_bridge' in cmd
        assert '--action collect' in cmd


class TestProfileFiles:

    @pytest.mark.parametrize('filename', PROFILE_FILES)
    def test_profile_is_valid_yaml(self, filename):
        path = os.path.join(PROFILES_DIR, filename)
        with open(path) as f:
            data = yaml.safe_load(f)
        assert 'id' in data
        assert 'name' in data
        assert 'atomic_ordering' in data

    @pytest.mark.parametrize('filename', PROFILE_FILES)
    def test_profile_references_existing_abilities(self, filename):
        ability_ids = set()
        for af in ABILITY_FILES:
            with open(os.path.join(ABILITIES_DIR, af)) as f:
                ability_ids.add(yaml.safe_load(f)[0]['id'])

        with open(os.path.join(PROFILES_DIR, filename)) as f:
            profile = yaml.safe_load(f)
        for ref in profile['atomic_ordering']:
            assert ref in ability_ids, f'{filename} references unknown ability {ref}'
