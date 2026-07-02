# ******************
#  Copyright 2023 TekFive, Inc., Sean M. Brennan, and contributors
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
import subprocess
import sys
from typing import TYPE_CHECKING

# Static analysis (IDEs, mypy) cannot follow the runtime MetaPathFinder
# that redirects autonomous_trust.core.X → autonomous_trust.core._python.X.
# These explicit imports let type checkers resolve submodules.
if TYPE_CHECKING:
    from ._python import config  # noqa: F401
    from ._python import identity  # noqa: F401
    from ._python import negotiation  # noqa: F401
    from ._python import network  # noqa: F401
    from ._python import reputation  # noqa: F401
    from ._python import structures  # noqa: F401
    from ._python import algorithms  # noqa: F401
    from ._python import protocol  # noqa: F401
    from ._python import processes  # noqa: F401
    from ._python import system  # noqa: F401
    from ._python import automate  # noqa: F401


def _git_describe_version():
    """Derive a PEP 440-ish version from ``git describe --tags``."""
    try:
        desc = subprocess.check_output(
            ['git', 'describe', '--tags', '--always'],
            stderr=subprocess.DEVNULL,
            cwd=os.path.dirname(__file__),
        ).decode().strip()
    except (OSError, subprocess.CalledProcessError):
        return None
    # Strip leading 'v' (e.g. v0.2.1-191-gbe0baef -> 0.2.1-191-gbe0baef)
    if desc.startswith('v'):
        desc = desc[1:]
    # Convert git describe format to PEP 440 local: 0.2.1.dev191+gbe0baef
    parts = desc.split('-', 2)
    if len(parts) == 3:
        base, count, sha = parts
        return f'{base}.dev{count}+{sha}'
    return desc or None


try:
    import importlib.metadata  # noqa
    __version__ = importlib.metadata.version("autonomous_trust")
except (ImportError, importlib.metadata.PackageNotFoundError):
    __version__ = _git_describe_version() or '?.?.?'

_BACKEND = os.environ.get('AUTONOMOUS_TRUST_BACKEND', 'auto')
_CORE_PREFIX = 'autonomous_trust.core.'


class _AliasLoader(importlib.abc.Loader):
    """Loader that aliases one module name to another already-imported module."""

    def __init__(self, real_name: str):
        self._real = real_name

    def create_module(self, spec):
        real_mod = importlib.import_module(self._real)
        # Save original metadata before the import system overwrites it
        # with alias values (_load_unlocked calls _init_module_attrs with
        # override=True), which can cause __package__ != __spec__.parent
        # mismatches that trigger DeprecationWarning on relative imports
        # in Python 3.12+.
        self._orig_spec = real_mod.__spec__
        self._orig_package = getattr(real_mod, '__package__', None)
        self._orig_name = real_mod.__name__
        sys.modules[spec.name] = real_mod
        return real_mod

    def exec_module(self, module):
        # Restore original metadata so relative imports within the real
        # module continue to resolve correctly.
        if self._orig_spec is not None:
            module.__spec__ = self._orig_spec
        if self._orig_package is not None:
            module.__package__ = self._orig_package
        if self._orig_name is not None:
            module.__name__ = self._orig_name


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
        # Don't intercept protobuf — it's generated code shared by all backends
        if suffix == 'protobuf' or suffix.startswith('protobuf.'):
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
