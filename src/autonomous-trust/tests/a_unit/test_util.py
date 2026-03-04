from autonomous_trust.core.util import ClassEnumMeta


class SampleEnum(metaclass=ClassEnumMeta):
    alpha = 'a'
    beta = 'b'
    gamma = 'c'


class TestClassEnumMeta:
    def test_contains_valid(self):
        assert 'alpha' in SampleEnum
        assert 'beta' in SampleEnum

    def test_contains_invalid(self):
        assert 'nonexistent' not in SampleEnum

    def test_contains_private(self):
        assert '__class__' not in SampleEnum

    def test_iter(self):
        attrs = list(SampleEnum)
        assert 'alpha' in attrs
        assert 'beta' in attrs
        assert 'gamma' in attrs
