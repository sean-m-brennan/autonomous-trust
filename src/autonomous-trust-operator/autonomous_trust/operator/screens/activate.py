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
"""Activate view: token status, masked PIN entry, MFA (TOTP) code entry, and a
clear pass/fail readout (VERIFIED / REJECTED / EXPIRED / REVOKED / UNAVAILABLE).
The actual PIV challenge-response + MFA verification runs in the operator core
(``activate``); this view only collects input and renders the result via
``app.do_activate(pin, mfa)`` so it stays decoupled and headless-testable."""
from __future__ import annotations

from typing import Any

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.widgets import Button, Input, Static

_STATUS_STYLE = {
    'VERIFIED': 'green',
    'REJECTED': 'red',
    'EXPIRED': 'red',
    'REVOKED': 'red',
    'DEFERRED': 'yellow',
    'UNAVAILABLE': 'yellow',
}


class ActivateView(Vertical):
    """PIN + MFA entry and activation result. Emits no AT calls itself —
    delegates to ``self.app.do_activate``."""

    def compose(self) -> ComposeResult:
        # Seed the Statics with placeholder text (token status is set in
        # on_mount; the result line shows a hint until an activation runs).
        yield Static('Token: …', id='token-status')
        yield Input(placeholder='PIV PIN', password=True, id='pin')
        yield Input(placeholder='MFA code (TOTP)', id='mfa')
        yield Button('Activate', id='activate-btn', variant='primary')
        yield Static('[dim]enter PIN + MFA, then Activate[/]', id='activate-result')

    def on_mount(self) -> None:
        self.refresh_token_status()

    def refresh_token_status(self) -> None:
        present = bool(getattr(self.app, 'token_present', lambda: False)())
        label = ('[green]token present[/]' if present
                 else '[yellow]no token detected — insert PIV card[/]')
        self.query_one('#token-status', Static).update(f'Token: {label}')

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id != 'activate-btn':
            return
        self.activate()

    def activate(self) -> Any:
        pin = self.query_one('#pin', Input).value
        mfa = self.query_one('#mfa', Input).value
        result = self.app.do_activate(pin, mfa)
        self.show_result(result)
        # PIN is held only long enough to open the session; never persist it.
        self.query_one('#pin', Input).value = ''
        return result

    def show_result(self, result: Any) -> None:
        status = str(getattr(result, 'status', result) or 'UNAVAILABLE')
        status = getattr(status, 'value', status)
        reason = getattr(result, 'reason', '') or ''
        color = _STATUS_STYLE.get(str(status).upper(), 'white')
        msg = f'[{color}]{status}[/]'
        if reason:
            msg += f' — {reason}'
        self.query_one('#activate-result', Static).update(msg)
        self.refresh_token_status()
