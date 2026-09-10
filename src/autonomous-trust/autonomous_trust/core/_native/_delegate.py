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
"""Make a `_native` subsystem package behave like the `_python` one it stands in
for.

Each `_native/<subsys>/__init__.py` is a re-export SHIM: it names the handful of
things it wants (its own C-backed classes, plus the Python ones it delegates)
rather than mirroring `_python/<subsys>`. That made the public import surface
depend on which backend was active, because
`from autonomous_trust.core.<subsys> import <x>` resolves `<x>` as an
**attribute** of whatever `core.<subsys>` turned out to be:

  * under the python backend `core.<subsys>` IS `_python.<subsys>`, so every
    name its `__init__` exports is present, and importing any real submodule
    binds it on the parent automatically -- so everything works;
  * under the native backend it is the shim, and anything unlisted had no
    attribute at all -- `AttributeError` at import time, which for a test module
    is a COLLECTION error that takes the whole run down with it.

The DOTTED forms (`import autonomous_trust.core.<subsys>.<mod>`) already worked:
the core redirector (`core/__init__.py`) falls back to `_python` for a module it
cannot find under `_native`. This closes the same hole for the attribute form,
and deliberately follows that redirector's policy -- fall back to Python -- so
the two agree.

Lookup order: this shim's own submodule first (so a native implementation is
never replaced by its Python twin), then -- following CPython's own
`from pkg import x` -- a NAME the `_python` package exports, then a `_python`
submodule. Resolution is lazy and cached, so a native node
loads nothing it does not touch; that matters because some of these pull real
dependencies in (`identity.first_contact` reaches `core.contacts`, an opt-in
feature `idprocess` is careful to import lazily for exactly this reason).

Anything the shim imports explicitly still wins outright -- a module's
`__getattr__` runs only when normal attribute lookup has already failed -- so
this never shadows a native implementation. It only fills holes that used to
raise.
"""

import importlib

#: Sentinel: `None` is a legitimate delegated value, so it cannot mark "absent".
_MISSING = object()


def python_fallback(native_module_name):
    """Build the `__getattr__` for a `_native` subsystem shim.

    Usage, at the END of `_native/<subsys>/__init__.py` (after the explicit
    re-exports, so those take precedence)::

        from .._delegate import python_fallback
        __getattr__ = python_fallback(__name__)
    """
    subsys = native_module_name.rsplit('.', 1)[-1]
    python_package = f'autonomous_trust.core._python.{subsys}'

    def __getattr__(name):
        # Leading-underscore lookups are dunder/private probes (__path__,
        # __all__, __wrapped__ ...). Answering those with an import attempt
        # would be both wrong and noisy, and some of them are asked speculatively
        # by pytest, copy and pickle.
        if name.startswith('_'):
            raise AttributeError(name)
        # THIS SHIM'S OWN submodule first. `from pkg import x` calls hasattr(),
        # which reaches this __getattr__ BEFORE the interpreter's own
        # submodule-import fallback -- so without this step a native module
        # that no sibling happens to have imported would be silently replaced
        # by its Python twin, switching implementations on the spelling of the
        # import. (Today `_native.identity.sign` and `_native.structures.array`
        # resolve natively only because a sibling module imports them, which is
        # luck, not a guarantee.)
        try:
            value = importlib.import_module(f'{native_module_name}.{name}')
        except ImportError:
            value = _MISSING
        if value is _MISSING:
            try:
                package = importlib.import_module(python_package)
            except ImportError:                 # no _python twin at all
                raise AttributeError(
                    f'module {native_module_name!r} has no attribute {name!r} '
                    f'(and no {python_package})'
                ) from None
            try:
                value = getattr(package, name)  # a name the package exports
            except AttributeError:
                try:
                    value = importlib.import_module(f'{python_package}.{name}')
                except ImportError:
                    # Neither a name nor a module, on either side: a genuine
                    # typo must still look like one rather than being masked.
                    raise AttributeError(
                        f'module {native_module_name!r} has no attribute '
                        f'{name!r} (and no {python_package}.{name})'
                    ) from None
        # Cache on the shim so this runs once per name, and so the attribute is
        # visible to a later getattr/dir without re-importing.
        setattr(importlib.import_module(native_module_name), name, value)
        return value

    return __getattr__
