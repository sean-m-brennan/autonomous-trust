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
"""How the core finds the verification layers (see
``autonomous_trust.core.extensions``).

Named by the ``autonomous_trust.extensions`` entry point when installed, and
found by file name in a source tree. Importing the five packages is what
registers them with ``autonomous_trust.core.oracles``. Live replication
(RD_12.6_LIVE_REPLICATION_PLAN.md §3.7) is the one layer that also works in
the negotiation process: its hooks there, and the `replay response` verb.
"""
from functools import partial

from autonomous_trust.core import oracles
from autonomous_trust.core.extensions import Extension, NegotiationHooks
from autonomous_trust.core._python.negotiation.protocol import NegotiationProtocol

from autonomous_trust.oracle import (calibration, certificates,  # noqa: F401
                                     physics, prequential, replication,
                                     selection)
from autonomous_trust.oracle._python.replication import live
from autonomous_trust.oracle._python.replication.model import (
    ReplicationDeclarationError, load_replication_env)
from autonomous_trust.oracle._python.selection import hooks as selection_hooks
from autonomous_trust.oracle._python.selection.model import (
    SelectionDeclarationError, load_selection_env)


def _enabled() -> bool:
    # Always: each layer speaks only once its declaration names a model.
    return True


def _register_handlers(proc, proc_name: str) -> None:
    # The layers score in the main process, through the registry. Live
    # replication answers its executors in the negotiation process.
    if proc_name == 'negotiation':
        proc.protocol.register_handler(NegotiationProtocol.replay_response,
                                       partial(live.handle_replay_response, proc))
        # Selective assignment's audit (RD_12.7 plan §0.1).
        proc.protocol.register_handler(selection_hooks.AUDIT_QUERY,
                                       partial(selection_hooks.handle_audit_query, proc))
        proc.protocol.register_handler(selection_hooks.AUDIT_REPLY,
                                       partial(selection_hooks.handle_audit_reply, proc))


def _on_result(proc, queues, task, tracker):
    # Selection only marks the result for a score echo and never decides,
    # so it runs first and live replication gives the answer.
    selection_hooks.on_result(proc, queues, task, tracker)
    return live.on_result(proc, queues, task, tracker)


def _periodic(proc, queues) -> None:
    live.periodic(proc, queues)
    selection_hooks.periodic(proc, queues)


def _check_config(cfg_dir, logger) -> None:
    """A declaration the node cannot honour stops it at start, rather than
    leaving live replication silently off (RD_12.6 plan §3.1)."""
    try:
        load_replication_env()
    except (OSError, ValueError, ReplicationDeclarationError) as err:
        raise RuntimeError('$AT_REPLICATION: %s' % err) from err
    try:
        load_selection_env()
    except (OSError, ValueError, SelectionDeclarationError) as err:
        raise RuntimeError('$AT_SELECTION: %s' % err) from err


EXTENSION = Extension(name='oracle', enabled=_enabled,
                      register_handlers=_register_handlers,
                      reset=oracles.reset, check_config=_check_config,
                      negotiation=NegotiationHooks(
                          on_result=_on_result, periodic=_periodic,
                          select_participants=selection_hooks.select_participants,
                          on_decline=selection_hooks.on_decline,
                          on_invitation=selection_hooks.on_invitation,
                          on_score=selection_hooks.on_score))
