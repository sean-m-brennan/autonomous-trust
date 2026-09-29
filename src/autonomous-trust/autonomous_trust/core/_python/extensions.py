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
"""How an optional feature attaches its handlers to the core processes.

The Python half of ``processes/extension.h``. A feature supplies one
:class:`Extension`; each core process ends its handler registration with
:func:`load_extensions`, which lets every ENABLED extension register its verbs
for that process. The core names no feature, and a node that does not enable
one is unaffected by it.

Extensions come from three places, in this order:

* :data:`_BUILTIN` -- features that ship inside this package (first contact).
  A built-in list, not entry points, because the package is often run from a
  source tree where its own ``pyproject.toml`` entry points are invisible.
* the ``autonomous_trust.extensions`` entry-point group -- features installed
  as separate distributions. Each entry point names an :class:`Extension`.
* a source tree's sibling distributions: a subpackage of the
  ``autonomous_trust`` namespace holding a :data:`MARKER` module
  (``autonomous_trust/<pkg>/_at_extension.py``) whose ``EXTENSION`` is one. The
  scan checks the filesystem and imports only a marker it finds, so a heavy
  sibling without one (``-services``, ``-simulator``) is never imported. The
  verification layers (``autonomous-trust-oracle``) and social
  (``autonomous-trust-social``) are found this way when run from a checkout,
  as an installed copy is through its entry point.

``enabled`` is called on EVERY :func:`load_extensions`, never cached: the
conformance adapter flips feature flags between scenarios.

Only extension NAMES are kept on the process, so a process that loaded one
still pickles for multiproc mode; :func:`run_post_fork` looks them up again.

See doc/architecture/extensions.md.
"""
import importlib
import importlib.metadata
import logging
import os
from dataclasses import dataclass
from typing import Any, Callable, Optional

_logger = logging.getLogger(__name__)

#: Entry-point group a separately installed feature registers under.
ENTRY_POINT_GROUP = 'autonomous_trust.extensions'

#: Module a sibling distribution's subpackage holds to be found in a source
#: tree, and whose ``EXTENSION`` it reads.
MARKER = '_at_extension'


@dataclass(frozen=True)
class IdentityHooks:
    """How a feature follows the identity process's own events (FEATURE_SPLIT_PLAN
    Phase 5): the Python half of identity/id_ext.h, with the hooks Python has a
    use for. Every member may be None.

    ``on_start(proc, queues)`` runs once, as the identity process starts taking
    traffic: restore persisted state here (C's ``run_start``).
    ``on_peer_confirmed(proc, queues, peer)`` runs after a peer is confirmed
    into the group and ``periodic_resync(proc, queues)`` inside the caps-resync
    sweep's ``try``; neither holds ``proc.lock``. ``is_blocked_locked(proc,
    uuid_str)`` is asked by ``get_peer_tier`` WITH ``proc.lock`` held, so it
    must not take it. C's ``group_update_seen``, ``peer_in_group`` and
    ``roster_replay`` feed its app-event carrier, which Python does not have,
    so they have no Python slot."""
    on_start: Optional[Callable[[Any, Any], None]] = None
    on_peer_confirmed: Optional[Callable[[Any, Any, Any], None]] = None
    periodic_resync: Optional[Callable[[Any, Any], None]] = None
    is_blocked_locked: Optional[Callable[[Any, str], bool]] = None


@dataclass(frozen=True)
class Extension:
    """One optional feature, as the core processes see it.

    ``register_handlers(proc, proc_name)`` is given every core process's name
    ('identity', 'network', 'reputation', 'negotiation') and registers only
    where it belongs. Handlers it stores on ``proc`` must pickle -- a bound
    method or ``functools.partial`` of a module function, never a lambda.
    ``post_fork(proc)`` runs at the top of the process's ``process()``, in the
    child. ``reset()`` drops process-global state between test scenarios.
    ``app_verbs`` is ``((verb, process_name), ...)``: the verbs an application
    may send this feature (:mod:`.app_verbs`), each forwarded only to the one
    process named -- the Python half of ``AT_APP_VERB_REGISTER``. Honored only
    while ``enabled()``."""
    name: str
    enabled: Callable[[], bool]
    register_handlers: Callable[[Any, str], None]
    post_fork: Optional[Callable[[Any], None]] = None
    reset: Optional[Callable[[], None]] = None
    identity: Optional[IdentityHooks] = None
    app_verbs: tuple = ()


def _builtin() -> list[Extension]:
    # Imported here, not at module level: identity imports this module, and
    # first contact imports identity.
    from .identity import first_contact
    return [first_contact.EXTENSION]


def _installed() -> list[Extension]:
    found = []
    for ep in importlib.metadata.entry_points(group=ENTRY_POINT_GROUP):
        try:
            ext = ep.load()
        except Exception as err:  # a broken add-on must not stop the node
            _logger.warning('extension %s failed to load: %s', ep.name, err)
            continue
        if not isinstance(ext, Extension):
            _logger.warning('extension %s is not an Extension (%r); ignored',
                            ep.name, type(ext).__name__)
            continue
        found.append(ext)
    return found


def _source_tree() -> list[Extension]:
    try:
        import autonomous_trust
    except ImportError:  # pragma: no cover - this module lives inside it
        return []
    found = []
    for root in list(getattr(autonomous_trust, '__path__', ())):
        try:
            names = sorted(os.listdir(root))
        except OSError:
            continue
        for pkg in names:
            if (pkg.startswith(('_', '.')) or not os.path.isfile(
                    os.path.join(root, pkg, MARKER + '.py'))):
                continue
            where = f'autonomous_trust.{pkg}.{MARKER}'
            try:
                ext = getattr(importlib.import_module(where), 'EXTENSION', None)
            except Exception as err:  # a broken add-on must not stop the node
                _logger.warning('extension %s failed to load: %s', where, err)
                continue
            if not isinstance(ext, Extension):
                _logger.warning('%s.EXTENSION is not an Extension (%r); '
                                'ignored', where, type(ext).__name__)
                continue
            found.append(ext)
    return found


def all_extensions() -> list[Extension]:
    """Every known extension, enabled or not; a duplicate name is refused.

    The same extension found twice -- installed, and on a source path too -- is
    one extension, not a duplicate."""
    seen: dict[str, Extension] = {}
    for ext in _builtin() + _installed() + _source_tree():
        if seen.get(ext.name) is ext:
            continue
        if ext.name in seen:
            _logger.warning('extension %s already registered; ignoring the '
                            'second', ext.name)
            continue
        seen[ext.name] = ext
    return list(seen.values())


def load_extensions(proc, proc_name: str) -> list[str]:
    """Let every enabled extension register its handlers on ``proc``.

    Records the loaded names on ``proc._extensions`` (for
    :func:`run_post_fork`) and returns them."""
    loaded = list(getattr(proc, '_extensions', ()))
    for ext in all_extensions():
        if ext.name in loaded or not ext.enabled():
            continue
        ext.register_handlers(proc, proc_name)
        loaded.append(ext.name)
    proc._extensions = loaded
    return loaded


def run_post_fork(proc) -> None:
    """Run the ``post_fork`` of each extension ``proc`` loaded."""
    names = getattr(proc, '_extensions', ())
    if not names:
        return
    for ext in all_extensions():
        if ext.name in names and ext.post_fork is not None:
            ext.post_fork(proc)


#: identity_hooks' answers, keyed by the extension names a process loaded.
_identity_hooks_cache: dict = {}


def identity_hooks(proc) -> tuple:
    """The IdentityHooks of the extensions ``proc`` loaded, in load order.

    Cached by ``proc._extensions`` (names), because ``get_peer_tier`` asks on
    every post and ``all_extensions`` lists directories and imports."""
    names = tuple(getattr(proc, '_extensions', ()))
    hooks = _identity_hooks_cache.get(names)
    if hooks is None:
        hooks = tuple(ext.identity for ext in all_extensions()
                      if ext.name in names and ext.identity is not None)
        _identity_hooks_cache[names] = hooks
    return hooks


#: The declarations a node's environment can make about a feature, and the
#: extension that must be present to honour each. Names only, as oracles.py's
#: table and C's identity/id_ext.c: an absent feature cannot declare its own
#: variables. A node told to publish its position or profile with no social
#: extension would silently publish nothing.
DECLARATIONS: tuple = (
    ('AT_OWN_GEOHASH', 'social'),
    ('AT_OWN_EXACT', 'social'),
    ('AT_OWN_PROFILE', 'social'),
)


class ExtensionMissingError(RuntimeError):
    """The environment declares a feature this node does not have."""


def check_env(logger=None) -> None:
    """Refuse a node whose environment declares a feature it lacks: logs an
    ERROR per variable, then raises :class:`ExtensionMissingError`."""
    log = logger if logger is not None else _logger
    present = {ext.name for ext in all_extensions()}
    missing = []
    for env, name in DECLARATIONS:
        if os.environ.get(env) and name not in present:
            log.error('$%s is set, but the %s extension is not loaded; refusing '
                      'to start rather than ignore it', env, name)
            missing.append(env)
    if missing:
        raise ExtensionMissingError(
            'declared but not loaded: ' + ', '.join(missing))


def reset_extensions() -> None:
    """Drop every extension's process-global state (conformance/tests)."""
    _identity_hooks_cache.clear()
    for ext in all_extensions():
        if ext.reset is not None:
            ext.reset()
