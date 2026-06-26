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
"""Status view: operator identity, current tier + reputation, credential /
issuer + session/credential TTL, card-present indicator, and network/cohort
health. Driven by :meth:`update_status` with a plain dict the app assembles, so
the view stays decoupled from AT internals."""
from __future__ import annotations

from typing import Any, Dict

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.widgets import Static


class StatusView(Vertical):
    """Read-only operator/session/cohort status panel: a ``Vertical`` wrapping a
    single body ``Static`` the app drives via :meth:`update_status`.

    Note the render helper is ``_render_status`` -- NOT ``_render``: ``_render``
    is a reserved ``textual.widget.Widget`` method that the framework calls to
    produce this widget's ``Visual``. Overriding it with a content-updating
    method that returns ``None`` makes Textual render ``None`` and crash
    (``AttributeError: 'NoneType' object has no attribute 'render_strips'``)."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._info: Dict[str, Any] = {}

    def compose(self) -> ComposeResult:
        yield Static('Loading status…', id='status-body')

    def on_mount(self) -> None:
        self._render_status()

    def update_status(self, info: Dict[str, Any]) -> None:
        self._info = dict(info or {})
        self._render_status()

    def _render_status(self) -> None:
        try:
            body = self.query_one('#status-body', Static)
        except Exception:
            return  # not mounted yet
        i = self._info
        activated = i.get('activated', False)
        sess = i.get('session_state', 'unauthenticated')
        card = i.get('card_present')
        node_ok = i.get('node_running', False)
        err = i.get('node_error')

        def yn(v):
            return '[green]yes[/]' if v else '[red]no[/]'

        lines = ['[bold]Operator[/]',
                 f'  identity   : {i.get("identity", "—")}',
                 f'  tier       : {i.get("my_tier", "—")}',
                 f'  reputation : {i.get("reputation", "—")}',
                 f'  issuer     : {i.get("issuer", "—")}',
                 f'  cred TTL   : {i.get("credential_ttl", "—")}',
                 '',
                 '[bold]Session[/]',
                 f'  activated    : {yn(activated)}',
                 f'  state        : {sess}',
                 f'  card present : {"—" if card is None else yn(card)}',
                 f'  session TTL  : {i.get("session_ttl", "—")}',
                 '',
                 '[bold]Network / cohort[/]',
                 f'  node running : {yn(node_ok)}',
                 f'  resources    : {i.get("resource_count", 0)}',
                 f'  providers    : {i.get("provider_count", 0)}']
        if err:
            lines += ['', f'[red]node error: {err}[/]']
        body.update('\n'.join(lines))
