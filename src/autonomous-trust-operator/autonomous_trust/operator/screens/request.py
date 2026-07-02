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
"""Request Builder view (PIV_MFA_OPERATOR_ACCESS_PLAN.md §3.7 #3): pick a
resource, auto-render an arg form from its ``arg_schema``, set a timeout, and
submit. Tier-locked resources are visible but **non-submittable** (submit
disabled with a "needs tier N" hint); submission itself is gated by the app's
session (step-up re-auth for high-tier requests). The view delegates the actual
``Task`` build + queue submit to ``app.submit_request`` so it stays decoupled."""
from __future__ import annotations

from typing import Any, Dict, Optional

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.widgets import Button, Input, Select, Static


def _coerce(text: str, type_str: Optional[str]) -> Any:
    """Best-effort coerce a form string to the arg_schema type (text on fail)."""
    t = (type_str or 'str').lower()
    if t in ('int', 'integer'):
        try:
            return int(text)
        except ValueError:
            return text
    if t in ('float', 'number'):
        try:
            return float(text)
        except ValueError:
            return text
    if t in ('bool', 'boolean'):
        return text.strip().lower() in ('1', 'true', 'yes', 'on')
    return text


_OUTCOME_STYLE = {
    'SUBMITTED': 'green',
    'LOCKED_BY_TIER': 'yellow',
    'STEP_UP_REQUIRED': 'yellow',
    'LOCKED': 'yellow',
    'NO_DIRECTORY': 'red',
    'UNKNOWN_RESOURCE': 'red',
    'NO_RESOURCE': 'red',
}


class RequestView(Vertical):
    """Resource picker + dynamic arg form + submit. Fed by
    :meth:`update_directory`; submits through ``self.app.submit_request``."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._directory: Any = None
        self._current: Optional[str] = None
        self._option_names: list = []

    def compose(self) -> ComposeResult:
        yield Select([], prompt='select a resource', id='req-resource')
        yield Vertical(id='req-args')
        yield Input(value='30', placeholder='timeout (s)', id='req-timeout')
        yield Button('Submit request', id='req-submit', variant='primary')
        yield Static('[dim]select a resource to build a request[/]', id='req-status')

    def on_mount(self) -> None:
        self.query_one('#req-submit', Button).disabled = True

    # -- data -------------------------------------------------------------

    def update_directory(self, directory: Any) -> None:
        self._directory = directory
        resources = list(getattr(directory, 'resources', [])) if directory else []
        names = sorted(r.name for r in resources)
        # Only rebuild the Select when the option set actually changes:
        # set_options resets the value and would otherwise fire a Changed storm
        # (and re-mount the arg form) on every periodic drain.
        if names != self._option_names:
            self._option_names = names
            select = self.query_one('#req-resource', Select)
            select.set_options((n, n) for n in names)
            if self._current in names:
                select.value = self._current
            elif self._current is not None:
                self._current = None
        # keep the reach/submit hint fresh for the current selection WITHOUT
        # rebuilding the arg form (a periodic drain must not race the async
        # mount of the arg Inputs).
        if self._current is not None:
            self._refresh_reach()

    def _resource(self, name: Optional[str]) -> Any:
        if not name or self._directory is None:
            return None
        return next((r for r in getattr(self._directory, 'resources', [])
                     if r.name == name), None)

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id != 'req-resource':
            return
        value = event.value
        self._select_resource(None if value is Select.BLANK else value)

    def _select_resource(self, name: Optional[str]) -> None:
        """Switch to a resource: (re)build its arg form, then refresh the reach
        hint. Called on a real Select change, not on every drain."""
        self._current = name
        args_box = self.query_one('#req-args', Vertical)
        res = self._resource(name)
        schema: Dict[str, Any] = (res.arg_schema or {}) if res else {}
        # Idempotent rebuild: only remount when the arg set differs (re-rendering
        # the same inputs would collide on their IDs before removal completes).
        wanted = [f'arg-{k}' for k in schema]
        existing = [w.id for w in args_box.children]
        if existing != wanted:
            args_box.remove_children()
            if schema:
                args_box.mount(*(Input(placeholder=f'{k} ({v})', id=f'arg-{k}')
                                 for k, v in schema.items()))
        self._refresh_reach()

    def _refresh_reach(self) -> None:
        """Set submit-enabled + the status hint from the current selection's
        reach. Does not touch the arg form, so it is safe to call on every
        drain."""
        submit = self.query_one('#req-submit', Button)
        status = self.query_one('#req-status', Static)
        res = self._resource(self._current)
        if res is None:
            submit.disabled = True
            status.update('[dim]select a resource to build a request[/]')
            return
        schema: Dict[str, Any] = res.arg_schema or {}
        reach = getattr(res.my_reach, 'value', res.my_reach)
        if reach != 'invokable':
            submit.disabled = True
            tier = '?' if res.required_tier is None else res.required_tier
            status.update(f'[yellow]🔒 needs tier {tier} — earn standing or '
                          f'request elevation[/]')
        else:
            submit.disabled = False
            status.update(f'[green]ready[/] — {len(schema)} arg(s)')

    # -- submit -----------------------------------------------------------

    def _gather_args(self) -> Dict[str, Any]:
        res = self._resource(self._current)
        schema: Dict[str, Any] = (res.arg_schema or {}) if res else {}
        out: Dict[str, Any] = {}
        for key, typ in schema.items():
            try:
                inp = self.query_one(f'#arg-{key}', Input)
            except Exception:
                continue
            out[key] = _coerce(inp.value, typ)
        return out

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == 'req-submit':
            self.submit()

    def submit(self) -> Any:
        status = self.query_one('#req-status', Static)
        if not self._current:
            status.update('[red]no resource selected[/]')
            return None
        try:
            timeout = int(self.query_one('#req-timeout', Input).value or 30)
        except ValueError:
            timeout = 30
        outcome = self.app.submit_request(self._current, self._gather_args(), timeout)
        self.show_outcome(outcome)
        return outcome

    def show_outcome(self, outcome: Any) -> None:
        status = str(getattr(outcome, 'status', outcome) or 'NO_RESOURCE')
        reason = getattr(outcome, 'reason', '') or ''
        color = _OUTCOME_STYLE.get(status, 'white')
        msg = f'[{color}]{status}[/]'
        if reason:
            msg += f' — {reason}'
        self.query_one('#req-status', Static).update(msg)
