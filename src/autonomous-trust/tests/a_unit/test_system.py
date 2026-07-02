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
import pytest
from datetime import datetime

from autonomous_trust.core.system import CfgIds, now, QueueType, encoding, max_concurrency


class TestCfgIds:
    def test_contains(self):
        assert 'network' in CfgIds
        assert 'identity' in CfgIds
        assert 'peers' in CfgIds
        assert 'capabilities' in CfgIds
        assert 'group' in CfgIds
        assert 'negotiation' in CfgIds
        assert 'reputation' in CfgIds
        assert 'main' in CfgIds

    def test_not_contains(self):
        assert 'nonexistent' not in CfgIds

    def test_iter(self):
        attrs = list(CfgIds)
        assert 'network' in attrs
        assert 'identity' in attrs

    def test_values(self):
        assert CfgIds.network == 'network'
        assert CfgIds.identity == 'identity'
        assert CfgIds.main == 'main'


class TestNow:
    def test_returns_datetime(self):
        result = now()
        assert isinstance(result, datetime)

    def test_utc(self):
        result = now()
        assert result.year >= 2025


class TestConstants:
    def test_encoding(self):
        assert encoding == 'utf-8'

    def test_max_concurrency(self):
        assert max_concurrency > 0
        assert isinstance(max_concurrency, int)


def test_package_hash_onerror():
    from autonomous_trust.core.system import PackageHash
    ph = PackageHash()
    ph.debug = True
    ph.onerror('test_module')  # should log error


def test_package_hash_onerror_no_debug():
    from autonomous_trust.core.system import PackageHash
    ph = PackageHash()
    ph.debug = False
    ph.onerror('test_module')  # should not log
