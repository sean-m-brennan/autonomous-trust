"""Tests for PolitePolicy dataclass, factories, and serialization."""

import pytest

try:
    from polite.policy import (
        PolitePolicy, null_policy, permissive_policy, strict_policy,
    )
except ImportError:
    pytest.skip("polite package not on PYTHONPATH", allow_module_level=True)


class TestPolicyDefaults:

    def test_default_is_null(self):
        p = PolitePolicy()
        assert p.min_reputation_to_negotiate is None
        assert p.defection_cooldown_s is None
        assert p.max_group_size is None
        assert p.bandwidth_priority_by_rank is False


class TestFactories:

    def test_null_policy(self):
        p = null_policy()
        assert p.min_reputation_to_negotiate is None

    def test_permissive_policy(self):
        p = permissive_policy()
        assert p.min_reputation_to_negotiate == 0.2
        assert p.defection_cooldown_s == 30.0
        assert p.max_group_size == 50
        assert p.bandwidth_priority_by_rank is False

    def test_strict_policy(self):
        p = strict_policy()
        assert p.min_reputation_to_negotiate == 0.5
        assert p.defection_cooldown_s == 120.0
        assert p.max_group_size == 10
        assert p.bandwidth_priority_by_rank is True


class TestSerialization:

    def test_round_trip(self):
        p = strict_policy()
        d = p.to_dict()
        p2 = PolitePolicy.from_dict(d)
        assert p == p2

    def test_to_dict_keys(self):
        d = null_policy().to_dict()
        assert set(d.keys()) == {
            'min_reputation_to_negotiate', 'defection_cooldown_s',
            'max_group_size', 'bandwidth_priority_by_rank',
        }

    def test_from_dict_ignores_extra_keys(self):
        d = null_policy().to_dict()
        d['future_field'] = 42
        p = PolitePolicy.from_dict(d)
        assert p == null_policy()

    def test_frozen(self):
        p = strict_policy()
        with pytest.raises(AttributeError):
            p.min_reputation_to_negotiate = 0.1
