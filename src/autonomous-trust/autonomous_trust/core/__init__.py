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

import importlib
import importlib.abc
import importlib.util
import os
import sys

try:
    import importlib.metadata  # noqa
    __version__ = importlib.metadata.version("autonomous_trust")
except ImportError:
    __version__ = '?.?'

_BACKEND = os.environ.get('AUTONOMOUS_TRUST_BACKEND', 'auto')
_CORE_PREFIX = 'autonomous_trust.core.'


class _AliasLoader(importlib.abc.Loader):
    """Loader that aliases one module name to another already-imported module."""

    def __init__(self, real_name: str):
        self._real = real_name

    def create_module(self, spec):
        real_mod = importlib.import_module(self._real)
        sys.modules[spec.name] = real_mod
        return real_mod

    def exec_module(self, module):
        pass


class _BackendRedirector(importlib.abc.MetaPathFinder):
    """Meta-path finder that redirects ``autonomous_trust.core.X`` imports
    to ``autonomous_trust.core.<backend>.X``.

    This allows downstream code to keep using absolute imports like
    ``from autonomous_trust.core.config import Configuration`` while the
    actual implementation lives under ``core._python`` or ``core._native``.
    """

    def __init__(self, backend: str):
        self._backend = backend
        self._resolving: set[str] = set()

    def find_spec(self, fullname, path, target=None):
        # Prevent re-entrancy when we call find_spec for the real module
        if fullname in self._resolving:
            return None
        if not fullname.startswith(_CORE_PREFIX):
            return None
        suffix = fullname[len(_CORE_PREFIX):]
        # Don't intercept _python or _native themselves
        if suffix.startswith('_'):
            return None
        # Already loaded — no need to redirect
        if fullname in sys.modules:
            return None

        self._resolving.add(fullname)
        try:
            # Try the selected backend first
            real_name = f'{_CORE_PREFIX}{self._backend}.{suffix}'
            try:
                real_spec = importlib.util.find_spec(real_name)
            except (ModuleNotFoundError, ValueError):
                real_spec = None

            # Fall back to _python if not found in native backend
            if real_spec is None and self._backend != '_python':
                real_name = f'{_CORE_PREFIX}_python.{suffix}'
                try:
                    real_spec = importlib.util.find_spec(real_name)
                except (ModuleNotFoundError, ValueError):
                    return None
        finally:
            self._resolving.discard(fullname)

        if real_spec is None:
            return None

        is_pkg = real_spec.submodule_search_locations is not None
        return importlib.util.spec_from_loader(
            fullname,
            _AliasLoader(real_name),
            origin=real_spec.origin,
            is_package=is_pkg,
        )


def _install_backend(backend_name: str):
    """Install the import redirector for the given backend."""
    global _active_backend  # noqa: PLW0603
    _active_backend = backend_name
    redirector = _BackendRedirector(backend_name)
    sys.meta_path.insert(0, redirector)


if _BACKEND == 'native':
    _install_backend('_native')
    from ._native import *  # noqa
elif _BACKEND == 'python':
    _install_backend('_python')
    from ._python import *  # noqa
elif _BACKEND == 'auto':
    try:
        _install_backend('_native')
        from ._native import *  # noqa
    except ImportError:
        # Remove the native redirector if it was installed
        sys.meta_path[:] = [f for f in sys.meta_path
                            if not isinstance(f, _BackendRedirector)]
        _install_backend('_python')
        from ._python import *  # noqa
else:
    raise ValueError(f"Unknown AUTONOMOUS_TRUST_BACKEND: {_BACKEND!r} "
                     f"(expected 'python', 'native', or 'auto')")
