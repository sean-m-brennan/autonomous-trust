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
"""The `_native` subsystem shims must expose the same import surface as `_python`.

Each `_native/<subsys>/__init__.py` re-exports a hand-written list rather than
mirroring its `_python` twin, so `from autonomous_trust.core.<subsys> import <x>`
-- which resolves `<x>` as an ATTRIBUTE of whichever package the backend
selected -- silently depended on the active backend. Anything unlisted raised
`AttributeError` under the native backend and worked fine under python.

That is a nasty failure mode for two reasons: it is invisible to anyone
developing on the python backend, and at import time in a test module it is a
COLLECTION error, so one missing name takes down the whole suite rather than one
case. It is also exactly the kind of hole no single-backend test run can see,
which is why the comparison is the test.

Measured when this was written: 11 names were reachable under python and not
under native -- `config.atomic_write` (which a project convention *requires*
every `.cfg.json` writer to use), `identity.ZtaStanding`,
`identity.ChildGroupSet`, the five `network.clock` names, and the reputation
channel-weight pair -- plus every `_python.identity` submodule
(`protocol`, `history`, `idprocess`, `zta`, `first_contact`).
"""
import importlib
import pkgutil

import pytest

# Every subsystem that has both a `_python` and a `_native` package.
SUBSYSTEMS = ['config', 'identity', 'negotiation', 'network', 'reputation',
              'structures']


def _native(subsys):
    """The native shim, or skip -- it needs cffi and the built .so."""
    try:
        return importlib.import_module(f'autonomous_trust.core._native.{subsys}')
    except ImportError as err:      # pragma: no cover - env-dependent
        pytest.skip(f'native backend unavailable ({err})')


@pytest.mark.parametrize('subsys', SUBSYSTEMS)
def test_native_shim_exposes_the_python_surface(subsys):
    """Asserted as ATTRIBUTES of the shim, deliberately.

    The dotted spellings (`import autonomous_trust.core.<subsys>.<mod>`) are
    already rescued by the core redirector's `_python` fallback, on both
    backends. The attribute form is the one it never sees, so it is the one
    that has to be checked -- and checking it here, against the shim itself,
    means the result does not depend on which backend the test run happens to
    have selected.
    """
    py = importlib.import_module(f'autonomous_trust.core._python.{subsys}')
    nat = _native(subsys)

    expected = {n for n in dir(py) if not n.startswith('_')}
    expected |= {name for _, name, _ in pkgutil.iter_modules(py.__path__)
                 if not name.startswith('_')}

    missing = sorted(n for n in expected if not hasattr(nat, n))
    assert not missing, (
        f'_native.{subsys} does not expose {missing} — reachable under the '
        f'python backend but not the native one. Every shim ends with '
        f'`__getattr__ = python_fallback(__name__)` for exactly this; if that '
        f'line is missing from _native/{subsys}/__init__.py, add it.')


@pytest.mark.parametrize('subsys', SUBSYSTEMS)
def test_a_nonexistent_name_still_raises(subsys):
    """The delegation must not turn a typo into something importable."""
    nat = _native(subsys)
    with pytest.raises(AttributeError):
        getattr(nat, 'NoSuchAttributeAnywhere')


@pytest.mark.parametrize('subsys,attr', [
    # The shim's OWN C-backed exports must keep winning: a module __getattr__
    # runs only after normal lookup fails, so delegation can never shadow
    # them -- but that is the property the whole design rests on, so it is
    # asserted rather than assumed.
    ('identity', 'NativeIdentity'),
    ('network', 'NetWireMessage'),
    ('network', 'NetworkConfig'),
    ('negotiation', 'NativeJobQueue'),
    ('reputation', 'NativeReputations'),
])
def test_delegation_does_not_shadow_native_exports(subsys, attr):
    nat = _native(subsys)
    impl = getattr(nat, attr)
    module = getattr(impl, '__module__', '')
    assert '_native' in module, (
        f'_native.{subsys}.{attr} resolved to {module!r}; the Python fallback '
        f'has shadowed a native implementation')


@pytest.mark.parametrize('subsys,attr', [
    # A native SUBMODULE that the shim's __init__ does not re-export. These are
    # the subtle ones: `from pkg import x` calls hasattr(), which reaches the
    # delegation BEFORE the interpreter's own submodule-import fallback, so
    # without a native-first step the Python twin would quietly win and the
    # implementation would depend on how the import was spelled. Several of
    # these resolve natively today only because a sibling module imports them,
    # which is luck; this pins it.
    ('identity', 'sign'),
    ('identity', 'encrypt'),
    ('structures', 'array'),
    ('structures', 'map'),
    ('structures', 'data'),
    ('structures', 'datetime'),
])
def test_native_submodules_win_over_the_python_twin(subsys, attr):
    nat = _native(subsys)
    module = getattr(nat, attr)
    assert module.__name__.startswith('autonomous_trust.core._native'), (
        f'_native.{subsys}.{attr} resolved to {module.__name__!r}; a native '
        f'submodule must not be replaced by its Python twin')
