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

* :data:`_BUILTIN` -- features that ship inside this package (rendezvous and
  first contact).
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
    so they have no Python slot.

    An admission authority (ZTA, FEATURE_SPLIT_PLAN Phase 6) uses the rest, each
    phrased so that None -- and no extension at all -- is a node with no such
    authority: everyone admitted, nothing refused, nothing proved. None of them
    holds ``proc.lock``.

    ``admission_gate(proc, queues, new_id)`` runs before the welcoming
    committee votes on ``new_id`` and answers ``'admit'``, ``'admit_capped'`` or
    ``'reject'``; it may write what it proves onto ``new_id`` and publishes any
    standing it decides itself. ``join_refused(proc, new_id)`` and
    ``gateway_refused(proc, uuid_str)`` say whether to refuse a join request,
    or federation through a member. ``operator_credential(proc, claim, cred)``
    says whether ``cred`` is operator-class (an attestation re-verify).
    ``credential_anchored(proc, signer)`` is asked by REPUTATION about an
    evidence co-signer it never admitted (``signer`` is the carried identity
    dict). ``on_tick(proc, queues, tick)`` runs once per identity loop
    iteration (C's zta_verify process has its own loop)."""
    on_start: Optional[Callable[[Any, Any], None]] = None
    on_peer_confirmed: Optional[Callable[[Any, Any, Any], None]] = None
    periodic_resync: Optional[Callable[[Any, Any], None]] = None
    is_blocked_locked: Optional[Callable[[Any, str], bool]] = None
    admission_gate: Optional[Callable[[Any, Any, Any], str]] = None
    join_refused: Optional[Callable[[Any, Any], bool]] = None
    gateway_refused: Optional[Callable[[Any, str], bool]] = None
    operator_credential: Optional[Callable[[Any, Any, bytes], bool]] = None
    credential_anchored: Optional[Callable[[Any, dict], bool]] = None
    on_tick: Optional[Callable[[Any, Any, Any], None]] = None


@dataclass(frozen=True)
class NetworkHooks:
    """How a feature follows the network process (FEATURE_SPLIT_PLAN Phase 7,
    C3/C4): the Python half of network/net_ext.h. Rendezvous attaches here.
    Every member may be None; with none, the network process is the core
    alone: no relay, every unicast to the peer's address.

    ``on_start(proc, queues)`` runs in the network process, after the
    receivers start. ``periodic(proc, queues)`` runs at the top of each pass
    of the loop, and ``drain_inbound(proc, queues, budget)`` beside the core's
    own receive queues, returning how many frames it handled (at most
    ``budget``). ``reaches(proc, peer_uuid)`` says the feature carries the
    unicast to that peer, which ``unicast(proc, peer_uuid, frame)`` then
    sends (``frame`` is already sealed for the peer), raising
    ``ConnectionError`` / ``OSError`` when it cannot. ``on_exclusion(proc,
    uuid_str, excluded)`` runs after the core recorded that reputation cut a
    peer off or readmitted it (:meth:`NetworkProcess.is_excluded`). Local
    verbs addressed to the network process register through
    ``Extension.register_handlers`` as any other handler."""
    on_start: Optional[Callable[[Any, Any], None]] = None
    periodic: Optional[Callable[[Any, Any], None]] = None
    drain_inbound: Optional[Callable[[Any, Any, int], int]] = None
    reaches: Optional[Callable[[Any, Any], bool]] = None
    unicast: Optional[Callable[[Any, Any, bytes], None]] = None
    on_exclusion: Optional[Callable[[Any, str, bool], None]] = None


@dataclass(frozen=True)
class NegotiationHooks:
    """How a feature follows the negotiation process (FEATURE_SPLIT_PLAN
    Phase 7, C1): the Python half of negotiation/neg_ext.h.

    ``capped_tier(proc, peer_uuid, tier)`` returns the trust tier ``peer_uuid``
    may USE when it asks this node to run a capability, given the ``tier`` it
    earned. Asked after the earned tier is read and before it is compared with
    the capability's ``required_tier``. A cap may only LOWER the tier
    (:func:`capped_tier` ignores a higher answer), and decides its own gate:
    it is asked whenever the extension is PRESENT, enabled or not, as C's
    constructor-registered cap is."""
    capped_tier: Optional[Callable[[Any, Any, int], int]] = None


@dataclass(frozen=True)
class ReputationHooks:
    """How a feature hands the reputation process cold-start priors
    (FEATURE_SPLIT_PLAN Phase 7, C2): the Python half of reputation/rep_ext.h.

    ``trust_seeds(proc)`` returns ``(peer_uuid, seed, what)`` triples that are
    new since its last call; it is asked at startup and on every pass of the
    loop, so the usual call must be cheap. ``label`` prefixes the log line
    (``'first contact'``), ``what`` names the peer in it (``'verified
    contact'``). The policy stays the core's: a seed is written only where
    the node holds no reputation for the peer, and one outside (0, 1] is
    refused. Asked whenever the extension is PRESENT, as C's provider is."""
    trust_seeds: Optional[Callable[[Any], Any]] = None
    label: str = ''


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
    while ``enabled()``.

    ``check_config(cfg_dir, logger)`` runs as the node starts
    (:func:`check_config`) and raises to refuse a configuration the extension
    cannot honour -- ZTA's loads its policy, so an enabled policy naming an
    unknown verifier or factor stops the node instead of failing open.

    ``plaintext_verbs`` are the wire verbs this feature may receive
    UNENCRYPTED from a known peer. Declaring them grants nothing: the
    operator's ``unencrypted_verbs.cfg.json`` must name them, and an enabled
    extension whose verbs it does not name refuses the start
    (:mod:`.plaintext_verbs`).

    ``transports`` is ``((kind, class path), ...)``: network transports this
    feature supplies, under the name C registers them by (``dtn_bp``), so the
    hybrid transport can open one as a leg (:func:`transport_class`). A node
    can also name the class path as its transport directly."""
    name: str
    enabled: Callable[[], bool]
    register_handlers: Callable[[Any, str], None]
    post_fork: Optional[Callable[[Any], None]] = None
    reset: Optional[Callable[[], None]] = None
    identity: Optional[IdentityHooks] = None
    app_verbs: tuple = ()
    check_config: Optional[Callable[[Optional[str], Any], None]] = None
    negotiation: Optional[NegotiationHooks] = None
    reputation: Optional[ReputationHooks] = None
    network: Optional[NetworkHooks] = None
    plaintext_verbs: tuple = ()
    transports: tuple = ()


def _builtin() -> list[Extension]:
    """None: every feature is its own distribution now, rendezvous
    (``autonomous_trust.rendezvous``) and first contact
    (``autonomous_trust.first_contact``) included (FEATURE_SPLIT_PLAN Phase 7).
    Kept as the first of the three sources, and the one tests replace."""
    return []


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
                marker = importlib.import_module(where)
            except Exception as err:  # a broken add-on must not stop the node
                _logger.warning('extension %s failed to load: %s', where, err)
                continue
            # One EXTENSION, or EXTENSIONS when a feature brings several (first
            # contact's handshake and its network half).
            exts = getattr(marker, 'EXTENSIONS', None)
            if exts is None:
                exts = (getattr(marker, 'EXTENSION', None),)
            for ext in exts:
                if not isinstance(ext, Extension):
                    _logger.warning('%s: %r is not an Extension; ignored', where,
                                    type(ext).__name__)
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


def transport_class(kind: str):
    """The class path an extension registers for transport ``kind``, or None.
    Looked up among the extensions present, enabled or not: a transport is
    chosen by configuration, not switched by a feature flag."""
    for ext in all_extensions():
        for name, path in ext.transports:
            if name == kind:
                return path
    return None


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


#: network_hooks' answers, keyed by the extension names a process loaded.
_network_hooks_cache: dict = {}


def network_hooks(proc) -> tuple:
    """The NetworkHooks of the extensions ``proc`` loaded, in load order.
    Cached by ``proc._extensions`` (names): the loop asks on every pass."""
    names = tuple(getattr(proc, '_extensions', ()))
    hooks = _network_hooks_cache.get(names)
    if hooks is None:
        hooks = tuple(ext.network for ext in all_extensions()
                      if ext.name in names and ext.network is not None)
        _network_hooks_cache[names] = hooks
    return hooks


#: negotiation_hooks' / reputation_hooks' answers (present extensions do not
#: change while a process runs); dropped by reset_extensions.
_present_hooks_cache: dict = {}


def _present_hooks(attr: str) -> tuple:
    hooks = _present_hooks_cache.get(attr)
    if hooks is None:
        hooks = tuple(getattr(ext, attr) for ext in all_extensions()
                      if getattr(ext, attr, None) is not None)
        _present_hooks_cache[attr] = hooks
    return hooks


def negotiation_hooks() -> tuple:
    """The NegotiationHooks of every PRESENT extension, in discovery order."""
    return _present_hooks('negotiation')


def reputation_hooks() -> tuple:
    """The ReputationHooks of every PRESENT extension, in discovery order."""
    return _present_hooks('reputation')


def capped_tier(proc, peer_uuid, tier: int) -> int:
    """``tier`` after every extension's cap, each given the previous answer.
    Never above ``tier``: a cap only lowers."""
    for hooks in negotiation_hooks():
        if hooks.capped_tier is None:
            continue
        capped = hooks.capped_tier(proc, peer_uuid, tier)
        if capped < tier:
            tier = capped
    return tier


#: The declarations a node's environment can make about a feature, and the
#: extension that must be present to honour each. Names only, as oracles.py's
#: table and C's identity/id_ext.c: an absent feature cannot declare its own
#: variables. A node told to publish its position or profile with no social
#: extension would silently publish nothing.
DECLARATIONS: tuple = (
    ('AT_OWN_GEOHASH', 'social'),
    ('AT_OWN_EXACT', 'social'),
    ('AT_OWN_PROFILE', 'social'),
    ('AT_FIRST_CONTACT', 'first_contact'),
    # Rendezvous (FEATURE_SPLIT_PLAN Phase 7b): use a relay, serve as one, or
    # fall back on the rosters and the seed list.
    ('AT_USE_RELAY', 'rendezvous'),
    ('AT_RELAY', 'rendezvous'),
    ('AT_RELAY_SEED_FALLBACK', 'rendezvous'),
)

#: The declarations that are switches: they declare only when on, as the
#: feature reads them (``AT_FIRST_CONTACT=0`` asks for nothing). Same as C's
#: identity/id_ext.c.
SWITCHES = frozenset({'AT_FIRST_CONTACT', 'AT_RELAY', 'AT_RELAY_SEED_FALLBACK'})


def _declares(env: str) -> bool:
    value = os.environ.get(env, '')
    if env in SWITCHES:
        return value.strip().lower() in ('1', 'true', 'yes', 'on')
    return bool(value)


class ExtensionMissingError(RuntimeError):
    """The environment declares a feature this node does not have."""


def check_env(logger=None) -> None:
    """Refuse a node whose environment declares a feature it lacks: logs an
    ERROR per variable, then raises :class:`ExtensionMissingError`."""
    log = logger if logger is not None else _logger
    present = {ext.name for ext in all_extensions()}
    missing = []
    for env, name in DECLARATIONS:
        if _declares(env) and name not in present:
            log.error('$%s is set, but the %s extension is not loaded; refusing '
                      'to start rather than ignore it', env, name)
            missing.append(env)
    if missing:
        raise ExtensionMissingError(
            'declared but not loaded: ' + ', '.join(missing))


#: Configuration a node can carry that only an extension acts on: (section,
#: key that turns it on, extension, distribution). Names only, as above. Without
#: the extension the section's class is not even importable, so the config
#: loader skips the file and the node would start enforcing nothing.
CONFIG_DECLARATIONS: tuple = (
    ('zta_policy', 'enabled', 'zta', 'autonomous-trust-zta'),
)


def check_config(cfg_dir=None, logger=None) -> None:
    """Refuse a node whose configuration turns on a feature it lacks
    (:data:`CONFIG_DECLARATIONS`), then let every present extension check the
    configuration it owns (``Extension.check_config``). Logs an ERROR and raises
    :class:`ExtensionMissingError` (or the extension's own error)."""
    import json
    log = logger if logger is not None else _logger
    if cfg_dir is None:
        from .config import Configuration
        cfg_dir = Configuration.get_cfg_dir()
    present = {ext.name: ext for ext in all_extensions()}
    missing = []
    for section, key, name, dist in CONFIG_DECLARATIONS:
        if name in present:
            continue
        path = os.path.join(cfg_dir, section + '.cfg.json')
        try:
            with open(path) as fh:
                on = json.load(fh).get(key) is True
        except (OSError, ValueError, AttributeError):
            on = False
        if on:
            log.error('%s enables %s, but the %s extension (%s) is not loaded; '
                      'refusing to start rather than ignore it', path, section,
                      name, dist)
            missing.append(section)
    if missing:
        raise ExtensionMissingError('enabled but not loaded: ' + ', '.join(missing))
    for ext in present.values():
        if ext.check_config is not None:
            ext.check_config(cfg_dir, log)
    configure_plaintext_verbs(cfg_dir, log)


def enabled_extensions() -> list[Extension]:
    """Every present extension whose ``enabled()`` says it is on now."""
    return [ext for ext in all_extensions() if ext.enabled()]


def configure_plaintext_verbs(cfg_dir=None, logger=None) -> frozenset:
    """Apply ``<cfg_dir>/unencrypted_verbs.cfg.json`` for the enabled
    extensions (:mod:`.plaintext_verbs`): logs an ERROR and re-raises its
    :class:`~.plaintext_verbs.PlaintextVerbsError` on a refusal. Returns the
    optional verbs granted."""
    from . import plaintext_verbs
    log = logger if logger is not None else _logger
    if cfg_dir is None:
        from .config import Configuration
        cfg_dir = Configuration.get_cfg_dir()
    try:
        return plaintext_verbs.configure(cfg_dir, enabled_extensions())
    except plaintext_verbs.PlaintextVerbsError as err:
        log.error('%s; refusing to start', err)
        raise


def reset_extensions() -> None:
    """Drop every extension's process-global state (conformance/tests)."""
    _identity_hooks_cache.clear()
    _network_hooks_cache.clear()
    _present_hooks_cache.clear()
    for ext in all_extensions():
        if ext.reset is not None:
            ext.reset()
