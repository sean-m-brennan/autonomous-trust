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
"""How the core finds ZTA (see ``autonomous_trust.core.extensions``): named by
the ``autonomous_trust.extensions`` entry point when installed, found by file
name in a source tree.

Present means available, not on: every hook answers as a node without ZTA would
until the node's zta_policy.cfg.json enables it. What the extension adds to a
process is its state (``admission.init_state``, on identity and reputation) and
the identity hooks below; the core names none of it.
"""
from autonomous_trust.core.extensions import Extension, IdentityHooks

from autonomous_trust.zta.admission import (admission_gate, credential_anchored, gateway_refused,
                        init_state, join_refused, on_tick, operator_credential)
from autonomous_trust.zta.zta_policy import ZtaPolicy


def _enabled() -> bool:
    # Always: the policy, not the presence of this package, turns ZTA on.
    return True


def _register_handlers(proc, proc_name: str) -> None:
    # No verbs (re-verification and revocation ride the identity loop in Python;
    # C has its own zta_verify process). Identity and reputation keep state.
    if proc_name in ('identity', 'reputation'):
        init_state(proc)


def _check_config(cfg_dir, logger) -> None:
    """Load the policy as the node starts, so one this node cannot honour (an
    unknown verifier type, a factor nothing provides) refuses the start rather
    than failing open on the first announce. Raises ZtaPolicyError."""
    try:
        ZtaPolicy.load(cfg_dir)
    except Exception as err:
        logger.error('zta_policy refused: %s', err)
        raise


EXTENSION = Extension(
    name='zta', enabled=_enabled, register_handlers=_register_handlers,
    check_config=_check_config,
    identity=IdentityHooks(admission_gate=admission_gate, join_refused=join_refused,
                           gateway_refused=gateway_refused,
                           operator_credential=operator_credential,
                           credential_anchored=credential_anchored, on_tick=on_tick))
