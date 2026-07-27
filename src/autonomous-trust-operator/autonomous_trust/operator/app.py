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
"""OperatorApp — the Textual console (PIV_MFA_OPERATOR_ACCESS_PLAN.md §3.7, P4).

Three tabbed views (Activate / Resource Directory / Status) over a single node
bridge. A timer drains the bridge's feedback (``ResourceDirectory`` snapshots)
into the directory + status views. Everything the UI needs from the node flows
through ``OperatorNodeBridge`` and a small set of injectable callables
(activator, token-presence), so the whole app runs headless under Textual's
Pilot with a fake bridge — no card, no node, no network. Request Builder +
Activity (task submit / results) land in P5.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional

from textual.app import App, ComposeResult
from textual.widgets import Footer, Header, TabbedContent, TabPane

from .bridge import OperatorNodeBridge
from .screens import (ActivateView, ActivityView, DirectoryView, RequestView,
                      StatusView)


class _StubResult:
    """Returned by the default activator when no real PIV token is wired."""
    status = 'UNAVAILABLE'
    reason = ('no PIV token configured — run with a PKCS#11 module + CA bundle, '
              'or inject an activator (see __main__)')


def _default_activator(pin: str, mfa: str) -> Any:  # noqa: ARG001
    return _StubResult()


@dataclass
class RequestOutcome:
    """Result of ``OperatorApp.submit_request`` — what the Request view shows.

    ``status`` ∈ {SUBMITTED, LOCKED_BY_TIER, STEP_UP_REQUIRED, LOCKED,
    NO_DIRECTORY, UNKNOWN_RESOURCE}. ``uuid`` is set when SUBMITTED."""
    status: str
    reason: str = ''
    uuid: Any = None


def _default_task_builder(capability: str, kwargs: Dict[str, Any],
                          timeout_sec: int, requestor: Any) -> Any:
    """Build a real AT ``Task`` DTO. Lazy import keeps core off the UI's import
    path (and tests inject a fake builder, never reaching this)."""
    from datetime import timedelta
    from autonomous_trust.core.negotiation.negotiation import (
        Task, TaskParameters)
    params = TaskParameters(capability, kwargs=kwargs,
                            timeout=timedelta(seconds=timeout_sec))
    return Task(params, requestor=requestor)


class OperatorApp(App):
    """Operator terminal console.

    :param bridge: node seam; defaults to a real ``OperatorNodeBridge``.
    :param session: an ``OperatorSession`` (optional; lazily created).
    :param activator: ``callable(pin, mfa) -> result`` with ``.status``/``.reason``
        (e.g. operator-core ``activate`` bound to a token). Defaults to a stub.
    :param token_provider: ``callable() -> bool`` for card-present status.
    :param auto_start: start the node bridge on mount (off for tests).
    :param poll_interval: feedback-drain cadence in seconds.
    """

    CSS = """
    DirectoryView #dir-detail { height: auto; padding: 1 0; }
    ActivateView Input { width: 40; margin: 1 0; }
    ActivateView #activate-result { padding: 1 0; }
    RequestView Input { width: 40; margin: 1 0; }
    RequestView #req-status { padding: 1 0; }
    StatusView #status-body { padding: 1; }
    """

    BINDINGS = [
        ('a', "show_tab('activate')", 'Activate'),
        ('d', "show_tab('directory')", 'Directory'),
        ('b', "show_tab('request')", 'Request'),
        ('v', "show_tab('activity')", 'Activity'),
        ('s', "show_tab('status')", 'Status'),
        ('r', 'refresh', 'Refresh'),
        ('q', 'quit', 'Quit'),
    ]

    def __init__(self,
                 bridge: Optional[OperatorNodeBridge] = None,
                 session: Any = None,
                 activator: Optional[Callable[[str, str], Any]] = None,
                 token_provider: Optional[Callable[[], bool]] = None,
                 task_builder: Optional[Callable[..., Any]] = None,
                 requestor_provider: Optional[Callable[[], Any]] = None,
                 auto_start: bool = True,
                 poll_interval: float = 1.0,
                 **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.bridge = bridge or OperatorNodeBridge()
        self._session = session
        self.activator = activator or _default_activator
        self._token_provider = token_provider or (lambda: False)
        self._task_builder = task_builder or _default_task_builder
        self._requestor_provider = requestor_provider or (lambda: 'operator')
        self._auto_start = auto_start
        self._poll_interval = poll_interval
        self.activated: bool = False
        #: a request deferred pending step-up re-auth: (resource, args, timeout)
        self._pending_request: Optional[tuple] = None

    # -- session (lazy so tests need not supply one) ----------------------

    @property
    def session(self) -> Any:
        if self._session is None:
            from autonomous_trust.core.operator.session import OperatorSession
            self._session = OperatorSession()
        return self._session

    def token_present(self) -> bool:
        try:
            return bool(self._token_provider())
        except Exception:
            return False

    # -- layout -----------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with TabbedContent(initial='activate', id='tabs'):
            with TabPane('Activate', id='activate'):
                yield ActivateView(id='view-activate')
            with TabPane('Directory', id='directory'):
                yield DirectoryView(id='view-directory')
            with TabPane('Request', id='request'):
                yield RequestView(id='view-request')
            with TabPane('Activity', id='activity'):
                yield ActivityView(id='view-activity')
            with TabPane('Status', id='status'):
                yield StatusView(id='view-status')
        yield Footer()

    def on_mount(self) -> None:
        self.title = 'AutonomousTrust Operator'
        # Let the node answer attended-now pulls from our live session (ethne
        # D8). A provider, not the session: `self.session` builds it lazily.
        attach = getattr(self.bridge, 'attach_session_provider', None)
        if callable(attach):
            attach(lambda: self.session)
        if self._auto_start:
            self.bridge.start()
        self.set_interval(self._poll_interval, self._drain)
        self._refresh_status()

    # -- actions ----------------------------------------------------------

    def action_show_tab(self, tab: str) -> None:
        self.query_one('#tabs', TabbedContent).active = tab

    def action_refresh(self) -> None:
        self._drain()

    # -- node feedback ----------------------------------------------------

    def _drain(self) -> None:
        try:
            drained = self.bridge.poll_feedback()
        except Exception:
            drained = []
        directory = self.bridge.latest_directory
        if directory is not None:
            for view_id, view_cls in (('#view-directory', DirectoryView),
                                      ('#view-request', RequestView)):
                try:
                    self.query_one(view_id, view_cls).update_directory(directory)
                except Exception:
                    pass
        # Route TaskResults (DTO-duck-typed: has verify_proof) to Activity.
        for item in drained:
            if hasattr(item, 'verify_proof') and hasattr(item, 'result'):
                try:
                    self.query_one('#view-activity', ActivityView)\
                        .record_result(item)
                except Exception:
                    pass
        self._refresh_status()

    def _refresh_status(self) -> None:
        try:
            self.query_one('#view-status', StatusView)\
                .update_status(self.status_info())
        except Exception:
            pass

    def status_info(self) -> dict:
        d = self.bridge.latest_directory
        resources = list(getattr(d, 'resources', [])) if d is not None else []
        try:
            sess_state = self.session.poll().value
        except Exception:
            sess_state = 'n/a'
        try:
            card = self.session.card_present()
        except Exception:
            card = None
        return {
            'activated': self.activated,
            'session_state': sess_state,
            'card_present': card,
            'my_tier': getattr(d, 'my_tier', '—') if d is not None else '—',
            'resource_count': len(resources),
            'provider_count': sum(len(r.providers) for r in resources),
            'node_running': self.bridge.running,
            'node_error': (repr(self.bridge.node_error)
                           if self.bridge.node_error else None),
        }

    # -- activation (called by ActivateView) ------------------------------

    def do_activate(self, pin: str, mfa: str) -> Any:
        """Run the injected activator and reflect success into session state. If
        a request is pending step-up re-auth, record the step-up and resubmit."""
        result = self.activator(pin, mfa)
        status = getattr(result, 'status', result)
        status = str(getattr(status, 'value', status)).upper()
        if status == 'VERIFIED':
            self.activated = True
            try:
                self.session.mark_verified()
            except Exception:
                pass
            if self._pending_request is not None:
                try:
                    self.session.complete_step_up()
                except Exception:
                    pass
                pending, self._pending_request = self._pending_request, None
                # Already authorized by this step-up — dispatch without
                # re-authorizing (re-calling authorize() with step_up_grace=0
                # would immediately demand another step-up).
                name, args, timeout_sec = pending
                res = self._lookup_resource(name)
                if res is not None and self._reach_ok(res):
                    self._dispatch(res, args, timeout_sec)
        self._refresh_status()
        return result

    # -- request submission (called by RequestView) -----------------------

    def submit_request(self, resource_name: str,
                       args: Optional[Dict[str, Any]] = None,
                       timeout_sec: int = 30) -> RequestOutcome:
        """Authorize (tier-lock + step-up), build a Task, and submit it on the
        node's control queue, recording it in the Activity view."""
        args = args or {}
        if self.bridge.latest_directory is None:
            return RequestOutcome('NO_DIRECTORY', 'no directory snapshot yet')
        res = self._lookup_resource(resource_name)
        if res is None:
            return RequestOutcome('UNKNOWN_RESOURCE',
                                  f'{resource_name!r} not in directory')

        required_tier = res.required_tier or 0
        if not self._reach_ok(res):
            tier = '?' if res.required_tier is None else res.required_tier
            return RequestOutcome('LOCKED_BY_TIER', f'needs tier {tier}')

        decision = self._authorize(required_tier)
        if decision == 'LOCKED':
            return RequestOutcome('LOCKED', 'session locked — re-activate')
        if decision == 'STEP_UP_REQUIRED':
            # Stash the request; do_activate resubmits after a fresh MFA challenge.
            self._pending_request = (resource_name, args, timeout_sec)
            self.action_show_tab('activate')
            return RequestOutcome('STEP_UP_REQUIRED',
                                  f'high tier ({required_tier}) — re-authenticate')
        return self._dispatch(res, args, timeout_sec)

    def _dispatch(self, res: Any, args: Dict[str, Any],
                  timeout_sec: int) -> RequestOutcome:
        """Build the Task DTO, put it on external_control, and log it to
        Activity. Assumes authorization already passed."""
        task = self._task_builder(res.name, args, timeout_sec,
                                  self._requestor_provider())
        if not self.bridge.submit(task):
            return RequestOutcome('LOCKED', 'control queue full')
        try:
            self.query_one('#view-activity', ActivityView)\
                .record_submitted(getattr(task, 'uuid', res.name), res.name)
        except Exception:
            pass
        return RequestOutcome('SUBMITTED', uuid=getattr(task, 'uuid', None))

    def _lookup_resource(self, name: str) -> Any:
        directory = self.bridge.latest_directory
        return next((r for r in getattr(directory, 'resources', [])
                     if r.name == name), None)

    @staticmethod
    def _reach_ok(res: Any) -> bool:
        return getattr(res.my_reach, 'value', res.my_reach) == 'invokable'

    def _authorize(self, required_tier: int) -> str:
        """Session authorization as a plain string (decouples the UI from the
        core RequestDecision enum); ALLOW if no session can be consulted."""
        try:
            decision = self.session.authorize(required_tier)
        except Exception:
            return 'ALLOW'
        return str(getattr(decision, 'value', decision)).upper()

    def on_unmount(self) -> None:
        try:
            self.bridge.stop(timeout=1.0)
        except Exception:
            pass
