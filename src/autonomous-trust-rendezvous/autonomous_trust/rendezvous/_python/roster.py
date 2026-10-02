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
"""The roster app verbs: the app's choice to trust a community's relay roster
(:mod:`.relay_rosters`), and to stop.

FEATURE_SPLIT_PLAN Phase 7b, D10: rendezvous's, moved from first contact's
area_contact with the logic unchanged. They are identity handlers, as every app
verb targets identity, registered whenever rendezvous is present, because the
roster files are rendezvous's own configuration. The events keep their kind
names. Mirrors C's rdv_roster.c and at_rendezvous.h.
"""
import functools
import json
from dataclasses import dataclass
from queue import Full

from autonomous_trust.core.app_verbs import AppEvent, is_local_app_verb, refuse_remote_app_verb
from autonomous_trust.core.system import CfgIds
from . import relay_rosters as _rosters

#: The app's verbs. Same strings as C's AT_APP_ROSTER_*.
APP_ROSTER_INSTALL = 'app_relay_roster_install'
APP_ROSTER_REMOVE = 'app_relay_roster_remove'
APP_VERBS = (APP_ROSTER_INSTALL, APP_ROSTER_REMOVE)

#: RosterEvent.kind values. C's AT_APP_EVENT_ROSTER_* carry the same outcomes.
EVENT_ROSTER_INSTALLED = 'roster_installed'  # ``issuer``, ``seq``
EVENT_ROSTER_REFUSED = 'roster_refused'      # ``reason``: 'bad_request' | 'invalid' | 'stale'
EVENT_ROSTER_REMOVED = 'roster_removed'      # ``issuer``; ``count`` 1 if one was there

#: The longest ``ref`` echoed intact. Same as C's AT_RDV_REF_LEN - 1.
REF_MAX = 63


@dataclass
class RosterEvent(AppEvent):
    """One roster outcome, reported to the app. ``ref`` echoes the app's
    request."""
    kind: str
    ref: str = ''
    issuer: str = ''
    reason: str = ''
    seq: int = 0
    count: int = 0


def register(proc) -> None:
    """Wire the two handlers into an IdentityProcess."""
    for verb, handler in ((APP_ROSTER_INSTALL, handle_app_roster_install),
                          (APP_ROSTER_REMOVE, handle_app_roster_remove)):
        proc.protocol.register_handler(verb, functools.partial(handler, proc))


def _emit(proc, queues, event) -> None:
    """Hand ``event`` to the main loop, which owns the hop to the app."""
    try:
        queues[CfgIds.main].put(event, block=True, timeout=proc.q_cadence)
    except KeyError:
        pass        # no main queue (unit tests, embedded use): nobody listens
    except Full:
        proc.logger.warning('roster: main queue full; %s event for the app '
                            'dropped', event.kind)


def _payload(message) -> dict:
    """The request's JSON object, or {} if it is not one."""
    obj = message.obj
    if isinstance(obj, dict):
        return obj
    try:
        data = json.loads(obj) if isinstance(obj, (str, bytes)) else None
    except (ValueError, TypeError):
        return {}
    return data if isinstance(data, dict) else {}


def _ref(req):
    """The request's ``ref``, or None if it is too long to echo intact."""
    ref = str(req.get('ref', '') or '')
    return ref if len(ref) <= REF_MAX else None


def handle_app_roster_install(proc, queues, message) -> bool:
    """Payload: ``roster`` (the roster file's text, {body, sig}), ``ref``.
    Pins the roster's issuer and files the roster, where the network process
    reads it (relay.own_relay_hints) as it reads any roster."""
    if not is_local_app_verb(proc, message):
        return refuse_remote_app_verb(proc, message, APP_ROSTER_INSTALL)
    req = _payload(message)
    ref = _ref(req)
    text = req.get('roster')
    if isinstance(text, dict):
        text = json.dumps(text, separators=(',', ':'))
    if ref is None or not isinstance(text, str):
        _emit(proc, queues, RosterEvent(EVENT_ROSTER_REFUSED, ref=ref or '',
                                        reason='bad_request'))
        return True
    try:
        issuer = _rosters.install(text)
        seq = int(json.loads(json.loads(text)['body'])['seq'])
    except _rosters.InvalidRoster as err:
        reason = 'stale' if 'older' in str(err) else 'invalid'
        proc.logger.warning('roster: refused (%s)', err)
        _emit(proc, queues, RosterEvent(EVENT_ROSTER_REFUSED, ref=ref, reason=reason))
        return True
    except OSError as err:
        proc.logger.warning('roster: cannot file it (%s)', err)
        _emit(proc, queues, RosterEvent(EVENT_ROSTER_REFUSED, ref=ref, reason='invalid'))
        return True
    proc.logger.info('roster: installed the relay roster of %s... (seq %d)', issuer[:16], seq)
    _emit(proc, queues, RosterEvent(EVENT_ROSTER_INSTALLED, ref=ref, issuer=issuer, seq=seq))
    return True


def handle_app_roster_remove(proc, queues, message) -> bool:
    """Payload: ``issuer`` (hex key), ``ref``."""
    if not is_local_app_verb(proc, message):
        return refuse_remote_app_verb(proc, message, APP_ROSTER_REMOVE)
    req = _payload(message)
    ref = _ref(req)
    issuer = str(req.get('issuer', '')).lower()
    if ref is None or not _rosters._is_key_hex(issuer):
        _emit(proc, queues, RosterEvent(EVENT_ROSTER_REFUSED, ref=ref or '',
                                        reason='bad_request'))
        return True
    had = _rosters.remove(issuer)
    _emit(proc, queues, RosterEvent(EVENT_ROSTER_REMOVED, ref=ref, issuer=issuer,
                                    count=1 if had else 0))
    return True
