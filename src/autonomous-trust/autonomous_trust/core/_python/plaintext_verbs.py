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
"""Which verbs a receiver accepts in PLAINTEXT from a peer it already knows.

FEATURE_SPLIT_PLAN Phase 7, hook C5 (decision D8). Two halves:

* The core's own plaintext verbs (:data:`..identity.protocol.CORE_UNENCRYPTED_VERBS`,
  the pre-key handshake, identity backfill, the partition pair, ...) are
  compiled in. No configuration can add to or remove from them, so no
  configuration can downgrade the core.
* An optional feature's plaintext verbs come from a file read at startup,
  ``<cfg_dir>/unencrypted_verbs.cfg.json``, of the form
  ``{"verbs": ["first_contact_hello", ...]}``. A feature only DECLARES which
  of its verbs may arrive in the clear (``Extension.plaintext_verbs``); the
  operator's file is what GRANTS them.

The rules, decided 2026-10-02 and mirrored by C's processes/plaintext_verbs.c:

* no file: the core verbs only;
* a malformed file: refuse to start;
* a verb that no loaded extension declares eligible -- a core verb such as
  ``group_key_update``, or a feature's verb with that feature off -- refuses
  to start;
* a loaded extension whose declared verbs are not all in the file refuses to
  start, naming the file and the missing verbs.

:func:`configure` applies them (raising :class:`PlaintextVerbsError`);
:func:`is_unencrypted` is the receive policy the network process consults.
"""
import json
import os
from typing import Iterable, Optional

#: The file, in the node's configuration directory.
FILENAME = 'unencrypted_verbs.cfg.json'

#: The one key the file holds.
KEY = 'verbs'

#: Most verbs the file may name, and the longest name, so C can hold the set
#: in fixed storage; a file past either is malformed, in both runtimes.
MAX_VERBS = 32
MAX_VERB_LEN = 64


class PlaintextVerbsError(RuntimeError):
    """The plaintext-verbs file cannot be honoured; the node must not start."""


#: The optional verbs granted by the last successful :func:`configure`.
_configured: frozenset = frozenset()


def _core() -> frozenset:
    # Imported here: identity.protocol is heavier than this module, and the
    # extension machinery imports this one.
    from .identity.protocol import CORE_UNENCRYPTED_VERBS
    return CORE_UNENCRYPTED_VERBS


def path_for(cfg_dir: str) -> str:
    return os.path.join(cfg_dir, FILENAME)


def read(path: str) -> Optional[frozenset]:
    """The verbs ``path`` names, or None when there is no file. Raises
    :class:`PlaintextVerbsError` on a malformed one: not a JSON object
    holding exactly ``verbs``, a list of at most :data:`MAX_VERBS` distinct
    non-empty strings of at most :data:`MAX_VERB_LEN` characters."""
    try:
        with open(path) as fh:
            raw = fh.read()
    except FileNotFoundError:
        return None
    except OSError as err:
        raise PlaintextVerbsError('%s: unreadable (%s)' % (path, err)) from err
    try:
        doc = json.loads(raw)
    except ValueError as err:
        raise PlaintextVerbsError('%s: not JSON (%s)' % (path, err)) from err
    if not isinstance(doc, dict) or set(doc) != {KEY}:
        raise PlaintextVerbsError('%s: must be an object holding only "%s"'
                                  % (path, KEY))
    verbs = doc[KEY]
    if not isinstance(verbs, list) or not all(
            isinstance(v, str) and v for v in verbs):
        raise PlaintextVerbsError('%s: "%s" must be a list of verb names'
                                  % (path, KEY))
    if len(verbs) > MAX_VERBS or any(len(v) > MAX_VERB_LEN for v in verbs):
        raise PlaintextVerbsError('%s: more than %d verbs, or a name longer '
                                  'than %d' % (path, MAX_VERBS, MAX_VERB_LEN))
    if len(set(verbs)) != len(verbs):
        raise PlaintextVerbsError('%s: "%s" names a verb twice' % (path, KEY))
    return frozenset(verbs)


def resolve(path: str, extensions: Iterable) -> frozenset:
    """The optional verbs ``path`` grants to the loaded ``extensions`` (each
    with ``name`` and ``plaintext_verbs``), after every rule above. Raises
    :class:`PlaintextVerbsError` naming the file and what is wrong."""
    named = read(path)
    granted = named if named is not None else frozenset()
    eligible = {}
    for ext in extensions:
        for verb in getattr(ext, 'plaintext_verbs', ()) or ():
            eligible.setdefault(verb, ext.name)
    ineligible = sorted(v for v in granted if v not in eligible)
    if ineligible:
        raise PlaintextVerbsError(
            '%s names %s, which no loaded extension may receive in plaintext'
            % (path, ', '.join(ineligible)))
    for ext in extensions:
        missing = [v for v in getattr(ext, 'plaintext_verbs', ()) or ()
                   if v not in granted]
        if missing:
            raise PlaintextVerbsError(
                'the %s extension needs %s in %s%s' % (
                    ext.name, ', '.join(missing), path,
                    '' if named is not None else ' (no such file)'))
    return granted


def configure(cfg_dir: str, extensions: Iterable) -> frozenset:
    """Apply ``<cfg_dir>/unencrypted_verbs.cfg.json`` for the loaded
    ``extensions`` and return the optional verbs it grants. On a refusal the
    previous set stays in force and :class:`PlaintextVerbsError` is raised."""
    global _configured
    granted = resolve(path_for(cfg_dir), list(extensions))
    _configured = granted
    return granted


def write(cfg_dir: str, verbs: Iterable[str]) -> str:
    """Write ``verbs`` as ``cfg_dir``'s plaintext-verbs file (atomically) and
    return its path: how a deployment or a test grants an extension's verbs,
    for example ``write(cfg_dir, first_contact.EXTENSION.plaintext_verbs)``."""
    from .config.configuration import atomic_write
    path = path_for(cfg_dir)
    with atomic_write(path) as fh:
        json.dump({KEY: sorted(set(verbs))}, fh, indent=2)
        fh.write('\n')
    return path


def reset() -> None:
    """Back to the core verbs only (tests, conformance)."""
    global _configured
    _configured = frozenset()


def active() -> frozenset:
    """Every verb accepted in plaintext now: the core's and the granted."""
    return _core() | _configured


def is_unencrypted(verb) -> bool:
    """Whether ``verb`` may arrive unencrypted from a peer we already know."""
    if not isinstance(verb, str) or not verb:
        return False
    return verb in _core() or verb in _configured
