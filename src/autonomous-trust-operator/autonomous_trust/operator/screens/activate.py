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
        # Don't invite a futile PIN entry: if no activator is wired, say so up
        # front instead of leaving the "enter PIN + MFA" prompt standing.
        hint = str(getattr(self.app, 'activation_hint', '') or '')
        if hint:
            self.query_one('#activate-result', Static).update(
                f'[yellow]{hint}[/] [dim]— see run-operator.sh --help[/]')

    def refresh_token_status(self, state: Any = None) -> None:
        """Repaint the token line.

        :param state: a pre-computed ``(present, detail)``. The background poller
            passes the result of its **threaded** probe so this never runs a
            blocking PKCS#11 call on the UI thread; user-driven refreshes (mount,
            post-activation) omit it and probe inline.
        """
        if state is not None:
            present, detail = state
        else:
            status = getattr(self.app, 'token_status', None)
            if callable(status):
                present, detail = status()
            else:  # older/stubbed app seam: bool only
                present = bool(getattr(self.app, 'token_present', lambda: False)())
                detail = ''
        hint = str(getattr(self.app, 'activation_hint', '') or '')
        # Three distinct states, because a detected card that *cannot* activate is
        # neither "token present" (implies ready) nor "no token" (plainly wrong):
        # claiming either one is what sends operators chasing the reader.
        if present and hint:
            label = '[yellow]card detected, cannot activate[/]'
            detail = f'{detail}; {hint}' if detail else hint
        elif present:
            label = '[green]token present[/]'
        else:
            label = '[yellow]no token detected — insert PIV card[/]'
            if hint:
                detail = f'{detail}; {hint}' if detail else hint
        # The reason matters when absent (no middleware vs. empty reader) and
        # identifies the token when present (real slot vs. software dev token).
        if detail:
            label += f' [dim]({detail})[/]'
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
        # Unwrap the enum BEFORE stringifying: core `activate` returns a
        # `ZtaStatus`, and str()-first rendered it as "ZtaStatus.VERIFIED", which
        # also missed the _STATUS_STYLE lookup and so lost the green. Mirrors the
        # order in `OperatorApp.do_activate`.
        status = getattr(result, 'status', result)
        status = getattr(status, 'value', status) or 'UNAVAILABLE'
        status = str(status)
        reason = getattr(result, 'reason', '') or ''
        color = _STATUS_STYLE.get(str(status).upper(), 'white')
        msg = f'[{color}]{status}[/]'
        if reason:
            msg += f' — {reason}'
        self.query_one('#activate-result', Static).update(msg)
        self.refresh_token_status()
