from autonomous_trust.core.config.names import random_name


def test_random_name_default():
    name = random_name()
    assert '_' in name
    parts = name.split('_')
    assert len(parts) == 2


def test_random_name_custom_sep():
    name = random_name(sep='-')
    assert '-' in name


def test_random_name_no_sep():
    name = random_name(sep='')
    assert isinstance(name, str)
    assert len(name) > 0


def test_random_name_capitalized():
    name = random_name(sep='_', cap=True)
    parts = name.split('_')
    assert parts[0][0].isupper()
    assert parts[1][0].isupper()
