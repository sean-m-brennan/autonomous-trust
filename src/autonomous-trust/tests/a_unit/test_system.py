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


class TestPackageHashPycache:
    """The digest gates peer admission (idprocess rejects a mismatch as a
    counterfeit), so it must depend on the source alone. An ``__init__.py``
    inside a ``__pycache__`` makes that directory an importable package, which
    would otherwise join the walk and perturb the digest. scripts/build-py.sh
    used to seed exactly such files into the generated protobuf tree, one level
    deeper per run.
    """

    pkg_name = 'at_pycache_probe_pkg'

    def _make_tree(self, tmp_path):
        import sys
        root = tmp_path / self.pkg_name
        (root / 'sub').mkdir(parents=True)
        (root / '__init__.py').touch()
        (root / 'sub' / '__init__.py').touch()
        (root / 'sub' / 'thing.py').write_text('VALUE = 1\n')
        sys.path.insert(0, str(tmp_path))
        return root

    def _digest(self, root):
        from autonomous_trust.core.system import PackageHash
        return PackageHash([str(root)], self.pkg_name)

    def teardown_method(self):
        import sys
        sys.path[:] = [p for p in sys.path if self.pkg_name not in p]
        for name in [m for m in sys.modules if m.startswith(self.pkg_name)]:
            del sys.modules[name]

    def test_digest_ignores_pycache_init(self, tmp_path):
        root = self._make_tree(tmp_path)
        before = self._digest(root)
        assert before.digest

        cache = root / 'sub' / '__pycache__'
        cache.mkdir(exist_ok=True)
        (cache / '__init__.py').touch()
        after = self._digest(root)

        assert after.digest == before.digest
        assert not [m for m in after.modules if '__pycache__' in m]

    def test_without_the_exclusion_the_digest_would_move(self, tmp_path, monkeypatch):
        """Mutation check: proves the assertion above is load-bearing."""
        from autonomous_trust.core.system import PackageHash
        root = self._make_tree(tmp_path)
        monkeypatch.setattr(PackageHash, 'excludes', ['viz'])  # pre-fix value
        before = self._digest(root)

        cache = root / 'sub' / '__pycache__'
        cache.mkdir(exist_ok=True)
        (cache / '__init__.py').touch()
        after = self._digest(root)

        assert after.digest != before.digest
        assert [m for m in after.modules if '__pycache__' in m]
