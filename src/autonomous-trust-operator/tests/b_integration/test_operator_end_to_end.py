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
"""b_integration: operator console end-to-end — activate → discover → submit →
result (PIV_MFA_OPERATOR_ACCESS_PLAN.md §7 "Integration").

Unlike the a_unit Pilot tests (which feed a hand-built directory and a
``_Result('VERIFIED')`` lambda activator) and unlike ``--demo`` (which ignores
MFA), this drives the **real** components across the package boundary:

  * REAL activation crypto — ``operator.activate.activate`` via ``SoftwareToken``
    runs the actual PIV challenge-response AND a real RFC-6238 TOTP second
    factor through the real ``MfaChain`` (full two-factor, not single-factor).
  * REAL discovery — the directory is assembled by the real
    ``directory_from_state`` adapter over real ``Capabilities`` /
    ``PeerCapabilities`` (incl. the real ``register_descriptor`` sanitize path)
    seeded to mirror the dod_mission cohort shape (canonical bootstrap caps +
    tier-gated providers), then delivered through the real
    ``OperatorNodeBridge`` thread + node seam.
  * REAL request/result — submit builds a real ``negotiation.Task`` DTO onto the
    node control queue; the node answers with a real ``TaskResult`` the Activity
    view records (with its real ``verify_proof`` badge).

The one boundary not crossed is a live multi-process network *join* (the node
seam is exercised via ``DemoNode`` rather than a real cohort socket mesh — that
remains a host/program-environment step, like the live-card step in §7.1).
"""
import asyncio
from types import SimpleNamespace

import pyotp
from textual.widgets import Input

from autonomous_trust.core.capabilities import Capabilities, PeerCapabilities
from autonomous_trust.core.operator.operator_node import directory_from_state
from autonomous_trust.core.operator.activate import enroll_totp
from autonomous_trust.operator.app import OperatorApp
from autonomous_trust.operator.bridge import OperatorNodeBridge
from autonomous_trust.operator.screens import ActivateView, ActivityView, RequestView
from autonomous_trust.operator import demo as opdemo


# -- a seeded cohort, mirroring the dod_mission seed shape -----------------
# Canonical bootstrap capability set every AT peer advertises (see
# tools/seed_dod_cohort.SEEDED_PEER_CAPABILITIES); here each is given a
# tier-gated wire descriptor so the operator (my_tier=2) sees a mix of
# invokable and tier-locked resources.

class _PeerRec:
    def __init__(self, uuid, petname, tier):
        self.uuid = uuid
        self.petname = petname
        self.nickname = petname
        self.tier = tier


class _Roster:
    """Minimal Peers stand-in (find_by_uuid is all directory_from_state needs;
    the adapter's roster handling is exhaustively covered in a_unit
    test_operator_node — here it just supplies a realistic cohort)."""
    def __init__(self, peers):
        self._by = {str(p.uuid): p for p in peers}
        self.all = list(peers)

    def find_by_uuid(self, uuid):
        return self._by.get(str(uuid))


def _seeded_cohort_directory(my_tier=2):
    caps = Capabilities()  # request-only operator: registers no serving caps
    pc = PeerCapabilities()
    pc.register('sensor-1', ['telemetry.report'])
    pc.register('command-1', ['data.publish', 'fires.coordinate'])
    # wire descriptors (the real sanitize/last-writer path) carry required_tier
    pc.register_descriptor('telemetry.report', {
        'required_tier': 1, 'description': 'live telemetry',
        'kind': 'data_stream', 'arg_schema': {'rate_hz': 'int'}})
    pc.register_descriptor('data.publish', {
        'required_tier': 2, 'description': 'publish a data product',
        'kind': 'service', 'arg_schema': {'topic': 'str'}})
    pc.register_descriptor('fires.coordinate', {
        'required_tier': 4, 'description': 'privileged origination',
        'kind': 'service'})
    peers = _Roster([_PeerRec('sensor-1', 'alpha', 3),
                     _PeerRec('command-1', 'cmd', 5)])
    reps = {'sensor-1': SimpleNamespace(score=0.8),
            'command-1': SimpleNamespace(score=0.9)}
    return directory_from_state(caps, pc, peers, my_tier=my_tier, reputations=reps)


def _reach(directory):
    return {r.name: getattr(r.my_reach, 'value', r.my_reach)
            for r in directory.resources}


def _run(scenario):
    asyncio.run(scenario())


async def _await_directory(app, pilot):
    for _ in range(80):
        await pilot.pause(0.05)
        if app.bridge.latest_directory is not None:
            return True
    return app.bridge.latest_directory is not None


async def _await_result(activity, uuid, pilot):
    def answered():
        e = activity._tasks.get(str(uuid))
        return e is not None and e.get('result') is not None
    for _ in range(80):
        await pilot.pause(0.05)
        if answered():
            return True
    return False


def test_operator_activate_discover_submit_result(tmp_path):
    token, ca_bundle = opdemo.mint_demo_pki(str(tmp_path))
    secret, _uri = enroll_totp('operator')                       # real TOTP secret
    activator = opdemo.software_activator(token, ca_bundle, totp_secret=secret)
    directory = _seeded_cohort_directory(my_tier=2)
    bridge = OperatorNodeBridge(node_factory=lambda: opdemo.DemoNode(directory))
    app = OperatorApp(bridge=bridge, activator=activator,
                      token_provider=lambda: False, auto_start=True,
                      poll_interval=0.05)

    async def scenario():
        async with app.run_test() as pilot:
            # DISCOVER: the real-assembled cohort directory lands via the bridge
            assert await _await_directory(app, pilot)
            reach = _reach(app.bridge.latest_directory)
            assert reach['telemetry.report'] == 'invokable'       # tier 1 <= 2
            assert reach['data.publish'] == 'invokable'           # tier 2 <= 2
            assert reach['fires.coordinate'] == 'locked_by_tier'  # tier 4 > 2
            # the Request view received the same directory
            assert app.query_one('#view-request', RequestView)._directory is not None

            # ACTIVATE: real PIV challenge-response + real TOTP second factor
            await pilot.press('a')
            app.query_one('#pin', Input).value = ''               # sw token: no PIN
            app.query_one('#mfa', Input).value = pyotp.TOTP(secret).now()
            app.query_one('#view-activate', ActivateView).activate()
            await pilot.pause()
            assert app.activated is True

            # SUBMIT (in-tier, tier 1 -> no step-up): real Task DTO out, real
            # TaskResult back through the node seam, recorded in Activity.
            outcome = app.submit_request('telemetry.report', {'rate_hz': 5}, 5)
            assert outcome.status == 'SUBMITTED'
            activity = app.query_one('#view-activity', ActivityView)
            assert await _await_result(activity, outcome.uuid, pilot)
    _run(scenario)


def test_operator_high_tier_request_steps_up_then_resubmits(tmp_path):
    # data.publish is tier 2 == the session's default step_up_tier, so the first
    # submit forces a fresh MFA challenge; a real re-auth then auto-resubmits.
    token, ca_bundle = opdemo.mint_demo_pki(str(tmp_path))
    secret, _uri = enroll_totp('operator')
    activator = opdemo.software_activator(token, ca_bundle, totp_secret=secret)
    directory = _seeded_cohort_directory(my_tier=2)
    bridge = OperatorNodeBridge(node_factory=lambda: opdemo.DemoNode(directory))
    app = OperatorApp(bridge=bridge, activator=activator,
                      token_provider=lambda: False, auto_start=True,
                      poll_interval=0.05)

    async def scenario():
        async with app.run_test() as pilot:
            assert await _await_directory(app, pilot)

            first = app.submit_request('data.publish', {'topic': 'isr'}, 5)
            assert first.status == 'STEP_UP_REQUIRED'
            assert app.bridge.control_queue.empty()              # nothing sent yet

            # real re-auth (PIV + TOTP) -> pending request auto-dispatches
            app.do_activate('', pyotp.TOTP(secret).now())
            await pilot.pause()
            assert app.activated is True
            assert app._pending_request is None
            activity = app.query_one('#view-activity', ActivityView)
            # the resubmitted task's result comes back through the node
            uuid = next(iter(activity._tasks))
            assert await _await_result(activity, uuid, pilot)
    _run(scenario)


def test_real_activation_rejects_wrong_second_factor(tmp_path):
    # The real two-factor path must reject a bad TOTP code end-to-end (no fake
    # _Result here — this is the actual MfaChain AND-combine rejecting).
    token, ca_bundle = opdemo.mint_demo_pki(str(tmp_path))
    secret, _uri = enroll_totp('operator')
    activator = opdemo.software_activator(token, ca_bundle, totp_secret=secret)
    bridge = OperatorNodeBridge(node_factory=lambda: opdemo.DemoNode(
        _seeded_cohort_directory()))
    app = OperatorApp(bridge=bridge, activator=activator,
                      token_provider=lambda: False, auto_start=True,
                      poll_interval=0.05)

    async def scenario():
        async with app.run_test() as pilot:
            await pilot.press('a')
            app.query_one('#pin', Input).value = ''
            app.query_one('#mfa', Input).value = '000000'        # wrong code
            result = app.query_one('#view-activate', ActivateView).activate()
            await pilot.pause()
            assert app.activated is False
            assert str(getattr(result.status, 'value', result.status)).upper() \
                != 'VERIFIED'
    _run(scenario)
