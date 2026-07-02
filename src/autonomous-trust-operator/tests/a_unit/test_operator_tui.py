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
"""Headless Textual Pilot tests for the operator console (P4): directory
browsing, tab navigation, and activation result handling -- all with a fake
bridge + activator, no node/card/network."""
import asyncio
import threading
import time
from queue import Queue

from textual.widgets import Button, DataTable, Input, Select, Static, TabbedContent

from autonomous_trust.core.operator.resource_directory import (
    build_directory, CapabilityDescriptor, PeerInfo)
from autonomous_trust.operator.app import OperatorApp
from autonomous_trust.operator.bridge import OperatorNodeBridge
from autonomous_trust.operator.screens import (
    ActivateView, ActivityView, DirectoryView, RequestView, StatusView)
from autonomous_trust.operator import __main__ as entry


def _sample_directory(my_tier=2):
    descriptors = {
        'analyze': CapabilityDescriptor(
            'analyze', kind='service', description='analyze a blob',
            required_tier=1, arg_schema={'blob': 'str'}),
        'strike': CapabilityDescriptor(
            'strike', kind='service', description='privileged', required_tier=4),
    }
    providers = {'analyze': ['drone-1'], 'strike': ['command-1']}
    peers = {'drone-1': PeerInfo('drone-1', name='alpha', tier=3, reputation=0.8),
             'command-1': PeerInfo('command-1', name='cmd', tier=5, reputation=0.9)}
    return build_directory(descriptors, providers, peers, my_tier=my_tier)


def _request_directory(my_tier=2):
    """Directory for request/step-up tests: an invokable resource with args
    (analyze, tier 1), a high-tier-but-invokable one that forces step-up
    (airquality_stream, tier 2), and a tier-locked one (strike, tier 4)."""
    descriptors = {
        'analyze': CapabilityDescriptor(
            'analyze', kind='service', description='analyze a blob',
            required_tier=1, arg_schema={'blob': 'str', 'mode': 'str'}),
        'airquality_stream': CapabilityDescriptor(
            'airquality_stream', kind='data_stream', description='live telemetry',
            required_tier=2, arg_schema={'rate_hz': 'int'}),
        'strike': CapabilityDescriptor(
            'strike', kind='service', description='privileged', required_tier=4),
    }
    providers = {'analyze': ['drone-1'], 'airquality_stream': ['drone-1'],
                 'strike': ['command-1']}
    peers = {'drone-1': PeerInfo('drone-1', name='alpha', tier=3, reputation=0.8),
             'command-1': PeerInfo('command-1', name='cmd', tier=5, reputation=0.9)}
    return build_directory(descriptors, providers, peers, my_tier=my_tier)


class _FakeTask:
    """DTO-shaped stand-in for negotiation.Task (UI only reads .uuid)."""
    def __init__(self, capability, uuid):
        self.capability = capability
        self.uuid = uuid


class _FakeResult:
    """DTO-shaped stand-in for negotiation.TaskResult."""
    def __init__(self, uuid, result='ok', verdict=True, status=None):
        self.uuid = uuid
        self.result = result
        self._verdict = verdict
        self.status = status

    def verify_proof(self):
        return self._verdict


def _fake_task_builder(capability, kwargs, timeout_sec, requestor):
    # deterministic uuid keyed on capability so results can be matched
    return _FakeTask(capability, uuid=f'uuid-{capability}')


def _app_with_directory(activator=None, directory=None, poll_interval=0.05,
                        task_builder=None, session=None):
    feedback: Queue = Queue()
    feedback.put(directory if directory is not None else _sample_directory())
    bridge = OperatorNodeBridge(node_factory=lambda: None, feedback_queue=feedback)
    return OperatorApp(bridge=bridge, activator=activator,
                       token_provider=lambda: False, task_builder=task_builder,
                       session=session, auto_start=False,
                       poll_interval=poll_interval)


class _FakeNode:
    """Stand-in AT node: emits one directory snapshot on ``run_forever`` then
    blocks until ``stop()``, so the bridge's real thread lifecycle is exercised
    without a multiprocessing pool, identity, or network."""

    def __init__(self, snapshot):
        self._snapshot = snapshot
        self._stop = threading.Event()
        self.stopped = False

    def run_forever(self, q_in, q_out):
        q_out.put(self._snapshot)
        self._stop.wait(timeout=5.0)

    def stop(self):
        self.stopped = True
        self._stop.set()


def _wait_until(predicate, timeout=2.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return predicate()


class _Result:
    def __init__(self, status, reason=''):
        self.status = status
        self.reason = reason


def _run(scenario):
    asyncio.run(scenario())


def test_directory_populates_from_snapshot():
    async def scenario():
        app = _app_with_directory()
        async with app.run_test() as pilot:
            await pilot.pause(0.15)  # let the drain interval fire
            table = app.query_one('#dir-table', DataTable)
            assert table.row_count == 2  # analyze, strike
            # reach: my_tier=2 -> analyze (req 1) invokable, strike (req 4) locked
            names = {app.query_one('#view-directory', DirectoryView)
                     ._resources()[i].name for i in range(2)}
            assert names == {'analyze', 'strike'}
    _run(scenario)


def test_directory_filter():
    async def scenario():
        app = _app_with_directory()
        async with app.run_test() as pilot:
            await pilot.pause(0.15)
            app.query_one('#dir-filter', Input).value = 'strike'
            await pilot.pause()
            assert app.query_one('#dir-table', DataTable).row_count == 1
    _run(scenario)


def test_tab_navigation():
    async def scenario():
        app = _app_with_directory()
        async with app.run_test() as pilot:
            # every tab must show without a reflow crash (P4 regression guard,
            # now including the Request/Activity screens)
            for key, tab in (('d', 'directory'), ('b', 'request'),
                             ('v', 'activity'), ('s', 'status'), ('a', 'activate')):
                await pilot.press(key)
                assert app.query_one('#tabs', TabbedContent).active == tab
    _run(scenario)


def test_activate_success_sets_activated():
    async def scenario():
        app = _app_with_directory(activator=lambda pin, mfa: _Result('VERIFIED'))
        async with app.run_test() as pilot:
            await pilot.press('a')
            view = app.query_one('#view-activate', ActivateView)
            app.query_one('#pin', Input).value = '1234'
            app.query_one('#mfa', Input).value = '000000'
            view.activate()
            await pilot.pause()
            assert app.activated is True
            # PIN is cleared after activation (never persisted)
            assert app.query_one('#pin', Input).value == ''
    _run(scenario)


def test_activate_failure_shows_reason():
    async def scenario():
        app = _app_with_directory(
            activator=lambda pin, mfa: _Result('REJECTED', 'no credential data'))
        async with app.run_test() as pilot:
            await pilot.press('a')
            view = app.query_one('#view-activate', ActivateView)
            result = view.activate()
            await pilot.pause()
            assert app.activated is False
            assert str(result.status) == 'REJECTED'
    _run(scenario)


def test_status_reflects_directory_and_session():
    async def scenario():
        app = _app_with_directory()
        async with app.run_test() as pilot:
            await pilot.pause(0.15)
            info = app.status_info()
            assert info['resource_count'] == 2
            assert info['provider_count'] == 2
            assert info['my_tier'] == 2
            assert info['activated'] is False
            # StatusView renders without error
            assert isinstance(app.query_one('#view-status', StatusView), StatusView)
    _run(scenario)


def test_demo_entrypoint_builds_browsable_console():
    # `python -m autonomous_trust.operator --demo` must build a node-less app
    # whose seeded directory is browsable across all tabs (the P4 exit demo).
    args = entry.parse_args(['--demo'])
    assert args.demo is True
    app = entry.build_app(args)
    assert isinstance(app, OperatorApp)
    assert app._auto_start is True         # the DemoNode runs in demo mode

    async def scenario():
        async with app.run_test() as pilot:
            # the DemoNode emits the directory; wait for the drain to land it
            table = app.query_one('#dir-table', DataTable)
            ok = False
            for _ in range(40):
                app.action_refresh()
                await pilot.pause()
                if table.row_count == 3:
                    ok = True
                    break
            assert ok  # analyze, airquality_stream, strike
            # every tab renders without a reflow crash
            tabs = app.query_one('#tabs', TabbedContent)
            for tab in ('directory', 'request', 'activity', 'status', 'activate'):
                tabs.active = tab
                await pilot.pause()
                assert tabs.active == tab
            assert app.status_info()['resource_count'] == 3
    _run(scenario)


def test_main_no_args_builds_real_bridge():
    # Default (no --demo) wires a real OperatorNodeBridge and auto-starts it.
    app = entry.build_app(entry.parse_args([]))
    assert isinstance(app.bridge, OperatorNodeBridge)
    assert app._auto_start is True


# -- bridge lifecycle (the node-thread seam) ------------------------------

def test_bridge_start_drain_submit_stop():
    snapshot = _sample_directory()
    node = _FakeNode(snapshot)
    bridge = OperatorNodeBridge(node_factory=lambda: node)
    assert bridge.running is False

    bridge.start()
    bridge.start()  # idempotent — must not spawn a second thread
    try:
        assert _wait_until(lambda: not bridge.feedback_queue.empty())
        assert bridge.running is True

        drained = bridge.poll_feedback()
        assert snapshot in drained
        assert bridge.latest_directory is snapshot       # classified as a directory
        assert bridge.poll_feedback() == []              # queue now empty

        assert bridge.submit('task-1') is True           # control path
        assert bridge.control_queue.get_nowait() == 'task-1'
    finally:
        bridge.stop(timeout=2.0)
    assert node.stopped is True                          # stop() reached the node
    assert _wait_until(lambda: bridge.running is False)


def test_bridge_captures_node_error():
    def _boom():
        raise RuntimeError('node failed to start')
    bridge = OperatorNodeBridge(node_factory=_boom)
    bridge.start()
    try:
        assert _wait_until(lambda: bridge.node_error is not None)
        assert isinstance(bridge.node_error, RuntimeError)
    finally:
        bridge.stop(timeout=1.0)


def test_bridge_submit_returns_false_when_control_queue_full():
    full_q: Queue = Queue(maxsize=1)
    full_q.put('occupied')
    bridge = OperatorNodeBridge(node_factory=lambda: None, control_queue=full_q)
    assert bridge.submit('rejected') is False


# -- directory drill-down (row selection -> provider detail) --------------

def test_directory_row_selection_shows_provider_detail():
    descriptors = {
        'analyze': CapabilityDescriptor(
            'analyze', kind='service', description='analyze a blob',
            required_tier=1, arg_schema={'blob': 'str'}),
        'orphan': CapabilityDescriptor(
            'orphan', kind='service', required_tier=None),  # no desc/args/providers
    }
    providers = {'analyze': ['drone-1'], 'orphan': []}
    peers = {'drone-1': PeerInfo('drone-1', name='alpha', tier=3, reputation=0.8)}
    directory = build_directory(descriptors, providers, peers, my_tier=2)

    async def scenario():
        app = _app_with_directory(directory=directory)
        async with app.run_test() as pilot:
            await pilot.pause(0.15)
            table = app.query_one('#dir-table', DataTable)
            assert table.row_count == 2  # sorted: analyze, orphan
            detail = app.query_one('#dir-detail', Static)

            # select 'analyze' (row 0): name, description, args, and provider standing
            app.set_focus(table)
            table.move_cursor(row=0)
            await pilot.press('enter')
            await pilot.pause()
            text = str(detail.content)
            assert 'analyze' in text
            assert 'analyze a blob' in text
            assert 'blob:str' in text
            assert 'providers' in text
            assert 'alpha' in text and 'tier 3' in text and 'rep 0.80' in text

            # the drill-down survives a re-render driven by a fresh drain
            app.action_refresh()
            await pilot.pause()
            assert 'alpha' in str(detail.content)

            # select 'orphan' (row 1): exercises the no-providers branch. Drive
            # it by posting the row's RowSelected message rather than moving the
            # cursor + pressing enter: DataTable.move_cursor is a no-op in some
            # headless Textual versions (e.g. 7.0.0 pins the cursor to row 0
            # regardless of row_count), which would silently re-select row 0.
            # The (data_table, cursor_row, row_key) RowSelected signature is
            # stable across versions, so this drives the real handler reliably.
            orphan_key = table.ordered_rows[1].key  # sorted: analyze, orphan
            table.post_message(DataTable.RowSelected(table, 1, orphan_key))
            await pilot.pause()
            text = str(detail.content)
            assert 'orphan' in text
            assert 'no providers' in text
    _run(scenario)


# -- P5: request builder ---------------------------------------------------

def test_request_form_renders_args_from_schema():
    async def scenario():
        app = _app_with_directory(directory=_request_directory(),
                                  task_builder=_fake_task_builder)
        async with app.run_test() as pilot:
            await pilot.pause(0.15)  # drain -> request view gets the directory
            view = app.query_one('#view-request', RequestView)
            view._select_resource('analyze')
            await pilot.pause()
            # one Input per arg_schema key
            assert app.query_one('#arg-blob', Input) is not None
            assert app.query_one('#arg-mode', Input) is not None
            assert app.query_one('#req-submit', Button).disabled is False
    _run(scenario)


def test_request_submits_invokable_resource():
    async def scenario():
        app = _app_with_directory(directory=_request_directory(),
                                  task_builder=_fake_task_builder)
        async with app.run_test() as pilot:
            await pilot.pause(0.15)
            view = app.query_one('#view-request', RequestView)
            view._select_resource('analyze')
            await pilot.pause()
            app.query_one('#arg-blob', Input).value = 'payload'
            outcome = view.submit()
            await pilot.pause()
            assert outcome.status == 'SUBMITTED'
            # the Task DTO landed on external_control with coerced args
            task = app.bridge.control_queue.get_nowait()
            assert task.capability == 'analyze'
            # and it shows up pending in Activity
            rows = app.query_one('#activity-table', DataTable).row_count
            assert rows == 1
    _run(scenario)


def test_request_locked_resource_is_not_submittable():
    async def scenario():
        app = _app_with_directory(directory=_request_directory(),
                                  task_builder=_fake_task_builder)
        async with app.run_test() as pilot:
            await pilot.pause(0.15)
            view = app.query_one('#view-request', RequestView)
            view._select_resource('strike')  # tier 4, my_tier 2 -> locked
            await pilot.pause()
            # submit disabled in the UI...
            assert app.query_one('#req-submit', Button).disabled is True
            # ...and the app refuses it even if called directly
            outcome = app.submit_request('strike', {}, 30)
            assert outcome.status == 'LOCKED_BY_TIER'
            assert app.bridge.control_queue.empty()
    _run(scenario)


def test_request_step_up_required_then_resubmits_after_reauth():
    # airquality_stream is tier 2 == default step_up_tier -> first request steps up
    sent = []

    def activator(pin, mfa):
        return _Result('VERIFIED')

    async def scenario():
        app = _app_with_directory(directory=_request_directory(),
                                  task_builder=_fake_task_builder,
                                  activator=activator)
        async with app.run_test() as pilot:
            await pilot.pause(0.15)
            first = app.submit_request('airquality_stream', {'rate_hz': 5}, 30)
            assert first.status == 'STEP_UP_REQUIRED'
            assert app.bridge.control_queue.empty()          # nothing sent yet
            assert app.query_one('#tabs', TabbedContent).active == 'activate'

            # operator re-authenticates; the pending request auto-dispatches
            app.do_activate('1234', '000000')
            await pilot.pause()
            task = app.bridge.control_queue.get_nowait()
            assert task.capability == 'airquality_stream'
            assert app._pending_request is None
    _run(scenario)


# -- P5: activity / results ------------------------------------------------

def test_activity_records_result_with_proof_badge():
    async def scenario():
        app = _app_with_directory(directory=_request_directory(),
                                  task_builder=_fake_task_builder)
        async with app.run_test() as pilot:
            await pilot.pause(0.15)
            view = app.query_one('#view-request', RequestView)
            view._select_resource('analyze')
            await pilot.pause()
            outcome = view.submit()
            assert outcome.status == 'SUBMITTED'

            # a verified TaskResult arrives on external_feedback
            app.bridge.feedback_queue.put(
                _FakeResult(uuid=outcome.uuid, result='42', verdict=True))
            app.action_refresh()  # drain -> routed to ActivityView
            await pilot.pause()

            activity = app.query_one('#view-activity', ActivityView)
            entry = activity._tasks[str(outcome.uuid)]
            assert entry['result'] is not None
            # drill into the row -> verified badge + result shown
            table = app.query_one('#activity-table', DataTable)
            app.set_focus(table)
            table.move_cursor(row=0)
            await pilot.press('enter')
            await pilot.pause()
            detail = str(app.query_one('#activity-detail', Static).content)
            assert 'verified' in detail
            assert '42' in detail
    _run(scenario)


def test_activity_unverified_and_unmatched_results():
    async def scenario():
        app = _app_with_directory(directory=_request_directory(),
                                  task_builder=_fake_task_builder)
        async with app.run_test() as pilot:
            await pilot.pause(0.15)
            activity = app.query_one('#view-activity', ActivityView)
            # a result for a task we never saw submitted -> its own row, no drop
            activity.record_result(_FakeResult(uuid='orphan-result', verdict=False))
            await pilot.pause()
            assert 'orphan-result' in activity._tasks
            assert app.query_one('#activity-table', DataTable).row_count == 1
    _run(scenario)


# -- §7.1 mock: software-token PIV activation ------------------------------

def test_software_token_activation_verifies(tmp_path):
    # Self-minted test PKI + SoftwareToken stands in for a PKCS#11 card; the
    # activator runs the REAL operator-core activate() (plan §7.1 stage 1-2).
    from autonomous_trust.operator import demo as opdemo
    token, ca_bundle = opdemo.mint_demo_pki(str(tmp_path))
    activator = opdemo.software_activator(token, ca_bundle)

    async def scenario():
        app = _app_with_directory(activator=activator)
        async with app.run_test() as pilot:
            await pilot.press('a')
            view = app.query_one('#view-activate', ActivateView)
            app.query_one('#pin', Input).value = '123456'  # ignored by sw token
            result = view.activate()                        # real challenge-response
            await pilot.pause()
            status = str(getattr(result.status, 'value', result.status)).upper()
            assert status == 'VERIFIED'
            assert app.activated is True
    _run(scenario)


def test_software_activator_from_files_verifies(tmp_path):
    # The --software-cert/-key/--ca-bundle dev path: SoftwareToken.from_files
    # loads the minted leaf cert + key off disk and activates.
    from autonomous_trust.operator import demo as opdemo
    _, ca_bundle = opdemo.mint_demo_pki(str(tmp_path))
    cert_path = str(tmp_path / opdemo.DEMO_LEAF_CERT)
    key_path = str(tmp_path / opdemo.DEMO_LEAF_KEY)
    activator = opdemo.software_activator_from_files(cert_path, key_path, ca_bundle)

    async def scenario():
        app = _app_with_directory(activator=activator)
        async with app.run_test() as pilot:
            await pilot.press('a')
            result = app.query_one('#view-activate', ActivateView).activate()
            await pilot.pause()
            status = str(getattr(result.status, 'value', result.status)).upper()
            assert status == 'VERIFIED'
            assert app.activated is True
    _run(scenario)


def test_software_token_activation_rejects_wrong_ca(tmp_path):
    # A token from one PKI presented against a *different* CA bundle must fail:
    # the verifier can't build a chain to a trusted issuer.
    from autonomous_trust.operator import demo as opdemo
    dir_a = tmp_path / 'a'
    dir_b = tmp_path / 'b'
    dir_a.mkdir()
    dir_b.mkdir()
    token, _ = opdemo.mint_demo_pki(str(dir_a))
    _, other_ca = opdemo.mint_demo_pki(str(dir_b))
    activator = opdemo.software_activator(token, other_ca)

    async def scenario():
        app = _app_with_directory(activator=activator)
        async with app.run_test() as pilot:
            await pilot.press('a')
            result = app.query_one('#view-activate', ActivateView).activate()
            await pilot.pause()
            status = str(getattr(result.status, 'value', result.status)).upper()
            assert status != 'VERIFIED'
            assert app.activated is False
    _run(scenario)


# -- demo mock: node answers requests end-to-end --------------------------

# -- P6: request.py edge branches -----------------------------------------

class _FakeRes:
    def __init__(self, name, reach='invokable', required_tier=1, arg_schema=None):
        self.name = name
        self.my_reach = reach
        self.required_tier = required_tier
        self.arg_schema = arg_schema or {}


class _FakeDir:
    def __init__(self, resources):
        self.resources = resources


def test_request_coerce_types():
    from autonomous_trust.operator.screens.request import _coerce
    assert _coerce('5', 'int') == 5
    assert _coerce('x', 'int') == 'x'          # non-numeric falls back to text
    assert _coerce('1.5', 'float') == 1.5
    assert _coerce('x', 'number') == 'x'
    assert _coerce('yes', 'bool') is True
    assert _coerce('off', 'boolean') is False
    assert _coerce('hi', None) == 'hi'         # default str passthrough


def test_request_resource_lookup_guards():
    view = RequestView()
    assert view._resource(None) is None        # no name
    assert view._resource('analyze') is None   # no directory yet
    view._directory = _FakeDir([_FakeRes('analyze')])
    assert view._resource('analyze').name == 'analyze'
    assert view._resource('missing') is None


def test_request_gather_args_skips_unmounted_inputs():
    # _gather_args must not raise when an arg Input isn't mounted: the
    # query_one miss is swallowed and that key is skipped.
    view = RequestView()
    view._directory = _FakeDir([_FakeRes('analyze', arg_schema={'blob': 'str'})])
    view._current = 'analyze'
    assert view._gather_args() == {}           # no Inputs mounted -> empty


def test_request_select_changed_ignores_other_ids():
    view = RequestView()

    class _Evt:
        class _Sel:
            id = 'not-req-resource'
        select = _Sel()
        value = 'whatever'
    # wrong id -> early return, no _current change, no query (would raise if hit)
    view.on_select_changed(_Evt())
    assert view._current is None


def test_request_submit_and_status_branches():
    async def scenario():
        app = _app_with_directory(directory=_request_directory(),
                                  task_builder=_fake_task_builder)
        async with app.run_test() as pilot:
            await pilot.pause(0.15)
            view = app.query_one('#view-request', RequestView)

            # submit with nothing selected -> "no resource selected"
            view._current = None
            assert view.submit() is None
            assert 'no resource selected' in str(
                app.query_one('#req-status', Static).content)

            # select via the dropdown event path (covers on_select_changed +
            # _select_resource + the value-set branch of update_directory)
            view._select_resource('analyze')
            await pilot.pause()
            # bad timeout string -> coerced to the 30s default, submit still works
            app.query_one('#req-timeout', Input).value = 'not-a-number'
            outcome = view.submit()
            await pilot.pause()
            assert outcome.status == 'SUBMITTED'

            # show_outcome renders status + reason (the reason-append branch)
            view.show_outcome(_Result('NO_DIRECTORY', 'node not connected'))
            assert 'node not connected' in str(
                app.query_one('#req-status', Static).content)

            # selecting BLANK clears the current resource and disables submit
            view._select_resource(None)
            await pilot.pause()
            assert app.query_one('#req-submit', Button).disabled is True
    _run(scenario)


def test_request_submit_button_press_dispatches():
    async def scenario():
        app = _app_with_directory(directory=_request_directory(),
                                  task_builder=_fake_task_builder)
        async with app.run_test() as pilot:
            await pilot.pause(0.15)
            view = app.query_one('#view-request', RequestView)
            view._select_resource('analyze')
            await pilot.pause()
            app.set_focus(app.query_one('#req-submit', Button))
            await pilot.press('enter')          # on_button_pressed -> submit()
            await pilot.pause()
            assert app.bridge.control_queue.get_nowait().capability == 'analyze'
    _run(scenario)


def test_request_on_select_changed_event_path():
    # The real dropdown path: on_select_changed -> _select_resource. Use a
    # no-arg resource ('strike') so no arg Inputs are (re)mounted -- this
    # isolates the event handler from the async arg-form mount.
    async def scenario():
        app = _app_with_directory(directory=_request_directory(),
                                  task_builder=_fake_task_builder)
        async with app.run_test() as pilot:
            await pilot.pause(0.15)
            view = app.query_one('#view-request', RequestView)

            class _Evt:
                class _Sel:
                    id = 'req-resource'
                select = _Sel()
                value = 'strike'
            view.on_select_changed(_Evt())
            await pilot.pause()
            assert view._current == 'strike'
            # tier-locked -> submit disabled via the reach hint
            assert app.query_one('#req-submit', Button).disabled is True
    _run(scenario)


def test_request_selection_survives_changed_option_set():
    # update_directory with a DIFFERENT option set that still contains the
    # current selection must re-pin the Select value (not drop it). The new
    # 'analyze' carries no arg_schema so the value re-pin doesn't race an
    # arg-form remount.
    async def scenario():
        app = _app_with_directory(directory=_request_directory(),
                                  task_builder=_fake_task_builder)
        async with app.run_test() as pilot:
            await pilot.pause(0.15)
            view = app.query_one('#view-request', RequestView)
            view._select_resource('strike')   # no-arg resource, no Inputs mounted
            await pilot.pause()
            # new option set: 'strike' still present, others swapped out
            view.update_directory(_FakeDir([_FakeRes('strike', reach='locked_by_tier',
                                                      required_tier=4),
                                            _FakeRes('extra')]))
            # update_directory re-pins the Select value to the surviving
            # selection synchronously (the branch under test); assert that
            # directly rather than _current, which depends on the order in
            # which the set_options BLANK + re-pin Changed events drain.
            assert app.query_one('#req-resource', Select).value == 'strike'
    _run(scenario)


def test_request_directory_update_drops_vanished_selection():
    async def scenario():
        app = _app_with_directory(directory=_request_directory(),
                                  task_builder=_fake_task_builder)
        async with app.run_test() as pilot:
            await pilot.pause(0.15)
            view = app.query_one('#view-request', RequestView)
            view._select_resource('analyze')
            await pilot.pause()
            # a fresh directory that no longer contains 'analyze' -> _current
            # is cleared and the reach hint resets (update_directory drop branch)
            view.update_directory(_FakeDir([_FakeRes('other')]))
            await pilot.pause()
            assert view._current is None
    _run(scenario)


# -- P6: activity.py edge branches ----------------------------------------

def test_activity_status_text_variants():
    av = ActivityView()
    assert 'done' in av._status_text(_FakeResult(uuid='x', status=None))
    assert 'red' in av._status_text(_FakeResult(uuid='x', status='rejected'))
    assert 'green' in av._status_text(_FakeResult(uuid='x', status='running'))


def test_activity_proof_badge():
    from autonomous_trust.operator.screens.activity import _proof_badge
    assert 'verified' in _proof_badge(True)
    assert 'invalid' in _proof_badge(False)
    assert 'none' in _proof_badge(None)


def test_activity_record_submitted_dedup_and_unmounted():
    # On an unmounted view query_one raises; record_submitted swallows it after
    # recording the entry, and a duplicate uuid returns early without a second row.
    av = ActivityView()
    av.record_submitted('u1', 'analyze')
    assert 'u1' in av._tasks
    av.record_submitted('u1', 'analyze')        # dedup early-return
    assert len(av._tasks) == 1


def test_activity_record_result_empty_uuid_is_dropped_safely():
    av = ActivityView()
    # empty uuid -> record_submitted stashes under 'unknown', the '' key stays
    # absent, so record_result returns without raising.
    av.record_result(_FakeResult(uuid='', verdict=True))
    assert '' not in av._tasks


class _RaisingResult:
    uuid = 'r1'
    status = None
    result = 'data'

    def verify_proof(self):
        raise RuntimeError('proof backend down')


def test_activity_record_result_verify_proof_raises():
    av = ActivityView()
    av.record_submitted('r1', 'analyze')        # entry exists (table unmounted)
    av.record_result(_RaisingResult())          # verify_proof raises -> verdict None
    assert av._tasks['r1']['result'] is not None


def test_activity_drill_in_awaiting_and_proof_error():
    async def scenario():
        app = _app_with_directory(directory=_request_directory(),
                                  task_builder=_fake_task_builder)
        async with app.run_test() as pilot:
            await pilot.pause(0.15)
            activity = app.query_one('#view-activity', ActivityView)
            # a submitted-but-unanswered row -> drill in shows "Awaiting result"
            activity.record_submitted('pending-1', 'analyze')
            await pilot.pause()
            table = app.query_one('#activity-table', DataTable)
            app.set_focus(table)
            table.move_cursor(row=0)
            await pilot.press('enter')
            await pilot.pause()
            assert 'Awaiting' in str(
                app.query_one('#activity-detail', Static).content)

            # a result whose verify_proof raises -> drill-in swallows it
            activity.record_result(_RaisingResult())
            await pilot.pause()
            table.move_cursor(row=activity_row_for(activity, 'r1'))
            await pilot.press('enter')
            await pilot.pause()
            assert 'data' in str(app.query_one('#activity-detail', Static).content)
    _run(scenario)


def activity_row_for(activity, key):
    # row index of a given task key in insertion order
    return list(activity._tasks.keys()).index(key)


def test_demo_node_answers_submitted_task():
    # Full path with the real bridge thread + real Task/TaskResult DTOs: submit
    # an invokable request, the DemoNode echoes a TaskResult, Activity records it.
    from autonomous_trust.operator import demo as opdemo
    directory = opdemo.demo_directory()
    bridge = OperatorNodeBridge(node_factory=lambda: opdemo.DemoNode(directory))
    app = OperatorApp(bridge=bridge, token_provider=lambda: False,
                      auto_start=True, poll_interval=0.05)

    async def scenario():
        async with app.run_test() as pilot:
            # the DemoNode (real thread) emits the directory; let the drain land it
            seen = False
            for _ in range(60):
                await pilot.pause(0.05)
                if app.bridge.latest_directory is not None:
                    seen = True
                    break
            assert seen
            outcome = app.submit_request('analyze', {'blob': 'x', 'mode': 'fast'}, 5)
            assert outcome.status == 'SUBMITTED'
            activity = app.query_one('#view-activity', ActivityView)

            def answered():
                e = activity._tasks.get(str(outcome.uuid))
                return e is not None and e.get('result') is not None
            got = False
            for _ in range(60):
                await pilot.pause(0.05)
                if answered():
                    got = True
                    break
            assert got  # DemoNode produced a TaskResult routed into Activity
    _run(scenario)
