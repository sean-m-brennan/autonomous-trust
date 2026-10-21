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
"""How an application reaches the node, and how the node answers it.

The Python half of the app-verb allowlist in ``utilities/msg_registry.h`` and
``at_route_extern_msg`` (``autonomous_trust.c``). Two directions:

* **app -> node.** The app puts an :class:`AppRequest` on the node's
  ``external_control`` queue. The main loop forwards it ONLY when its
  ``function`` is a verb some enabled extension declared (``Extension.app_verbs``),
  and only to the one process that extension named. Forwarding a request to
  whatever process it names would hand an app AT's whole internal verb surface.
  The forwarded :class:`..network.Message` carries NO ``from_whom`` -- that is
  what marks it local (see :func:`is_local_app_verb`).
* **node -> app.** A process puts an :class:`AppEvent` on ``CfgIds.main``; the
  main loop forwards every ``AppEvent`` to ``external_feedback``. The C twin's
  equivalent is a registered message type with ``app_bound = true``.

The core's own ``app_roster_request`` predates this module and stays hard-wired
in ``automate.py`` (it fans out to more than one process, which a registered
verb does not).

See doc/architecture/extensions.md.
"""
from dataclasses import dataclass
from typing import Any, Optional

#: What a refused remote app verb logs. One spelling, shared with the C twin's
#: identity_refuse_remote_app_verb, so the refusal reads the same in either
#: runtime's log.
_REMOTE_REFUSAL = ('refusing %s from the wire (peer %s) -- app verbs are '
                   'local-only')


@dataclass
class AppRequest:
    """An application's request to the node: a verb and its payload.

    ``payload`` is whatever the verb documents -- a JSON string for the verbs
    shipped so far, so a request means the same thing in both runtimes. There
    is deliberately no sender and no target field: the app is not a peer, and
    it does not choose which process answers."""
    function: str
    payload: Any = ''


class AppEvent:
    """Marker base for anything a process sends toward the app.

    Subclass it (a dataclass is simplest -- it must pickle, because multiproc
    mode moves it across a queue) and put an instance on ``CfgIds.main``. The
    main loop forwards it to ``external_feedback`` unchanged."""


def app_verb_target(verb: str) -> Optional[str]:
    """The process ``verb`` is forwarded to, or None if no ENABLED extension
    declared it.

    Asked on every request rather than cached, for the reason
    :func:`..extensions.load_extensions` re-asks ``enabled``: a feature flag can
    flip between conformance scenarios. App verbs are rare, so the cost is
    immaterial."""
    if not verb:
        return None
    from .extensions import all_extensions   # extensions imports identity
    for ext in all_extensions():
        verbs = dict(ext.app_verbs or ())
        if verb in verbs and ext.enabled():
            return verbs[verb]
    return None


def is_local_app_verb(proc, message) -> bool:
    """True iff ``message`` came from this node's own app, not from the wire.

    An app verb and a peer's message are the same kind of object -- both are
    Messages dispatched on ``function`` -- so a handler that does not check
    would let an admitted peer make this node act on its behalf
    (doc/architecture/extensions.md). The main loop builds a forwarded request
    with no ``from_whom``;
    anything off the wire carries the sender's identity. Self is accepted, for
    a loopback path. Mirrors C's identity_is_local_app_verb."""
    sender = getattr(message, 'from_whom', None)
    if sender is None:
        return True
    me = getattr(proc, 'identity', None)
    try:
        return me is not None and str(sender.uuid) == str(me.uuid)
    except AttributeError:
        return False


def refuse_remote_app_verb(proc, message, verb: str) -> bool:
    """Log and refuse an app verb that arrived from the wire. Returns True
    (handled), so the caller can ``return refuse_remote_app_verb(...)``."""
    sender = getattr(message, 'from_whom', None)
    who = getattr(sender, 'uuid', sender)
    proc.logger.warning(_REMOTE_REFUSAL, verb, who)
    return True
