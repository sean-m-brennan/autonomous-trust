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
"""Live-card activation (plan §7.1 stage 3): ``--ca-bundle`` with no software
cert/key opens the card in the reader with the entered PIN, has it sign the
challenge, and verifies its chain against the bundle.

The PKCS#11 layer is injected (``token_factory``), so these run with no card and
no PyKCS11 binding. What they cannot cover is the real middleware -- opening an
actual card is hardware-only."""
import asyncio
import os
import tempfile

import pytest
from textual.widgets import Button, Input, Static

from autonomous_trust.core.identity.zta.piv.pkcs11 import PivTokenError
from autonomous_trust.operator import __main__ as entry
from autonomous_trust.operator import demo as opdemo
from autonomous_trust.operator.app import OperatorApp
from autonomous_trust.operator.screens import ActivateView


def _run(scenario):
    asyncio.run(scenario())


@pytest.fixture(scope='module')
def pki():
    """A real software token + CA bundle, standing in for the card's key/chain."""
    cfg = tempfile.mkdtemp()
    token, ca_bundle = opdemo.mint_demo_pki(cfg)
    return {'token': token, 'ca_bundle': ca_bundle, 'cfg': cfg}


class _FakeCard:
    """A PivToken whose key/cert come from a software token, recording the PIN it
    was opened with and whether it was closed."""

    opened: list = []

    def __init__(self, module_path, pin, slot, inner):
        self._inner = inner
        self.closed = False
        _FakeCard.opened.append({'module': module_path, 'pin': pin, 'slot': slot})

    def certificate_der(self):
        return self._inner.certificate_der()

    def sign(self, data):
        return self._inner.sign(data)

    def is_present(self):
        return True

    def close(self):
        self.closed = True


def _factory(pki, cards=None, raises=None):
    """Build a token_factory that mints _FakeCards backed by the demo token."""
    def make(module_path, pin, slot):
        if raises is not None:
            raise raises
        card = _FakeCard(module_path, pin, slot, pki['token'])
        if cards is not None:
            cards.append(card)
        return card
    return make


class TestLiveCardActivator:
    def test_real_challenge_response_verifies(self, pki):
        # the card signs a server-issued nonce; the chain verifies against the p7b
        act = entry.live_card_activator(pki['ca_bundle'],
                                        token_factory=_factory(pki))
        result = act('123456', '')
        assert getattr(result.status, 'value', result.status) == 'VERIFIED', result.reason

    def test_each_activation_uses_the_pin_just_entered(self, pki):
        # the PIN is a call argument, never cached in the activator: a second
        # activation must open the card with the *new* PIN
        _FakeCard.opened.clear()
        act = entry.live_card_activator(pki['ca_bundle'],
                                        token_factory=_factory(pki))
        act('87654321', '')
        act('11112222', '')
        assert [o['pin'] for o in _FakeCard.opened[-2:]] == ['87654321', '11112222']

    def test_token_is_closed_after_activation(self, pki):
        # no PKCS#11 session outlives the call, so the status-line probe's
        # process-global C_Finalize cannot tear a live session down
        cards = []
        act = entry.live_card_activator(pki['ca_bundle'],
                                        token_factory=_factory(pki, cards))
        act('123456', '')
        assert cards and cards[0].closed is True

    def test_token_closed_even_when_signing_raises(self, pki):
        # a card yanked mid-activation still must not leak a logged-in session
        cards = []

        class _Yanked(_FakeCard):
            def sign(self, data):
                raise PivTokenError('card removed')

        def make(module_path, pin, slot):
            card = _Yanked(module_path, pin, slot, pki['token'])
            cards.append(card)
            return card
        act = entry.live_card_activator(pki['ca_bundle'], token_factory=make)
        with pytest.raises(PivTokenError):
            act('123456', '')
        assert cards and cards[0].closed is True

    def test_wrong_ca_bundle_rejects(self, pki, tmp_path):
        # a bundle that is not the card's issuer must not verify
        other = tempfile.mkdtemp()
        _t, other_bundle = opdemo.mint_demo_pki(other)
        act = entry.live_card_activator(other_bundle,
                                        token_factory=_factory(pki))
        result = act('123456', '')
        assert getattr(result.status, 'value', result.status) != 'VERIFIED'

    def test_bad_pin_is_rejected_not_unavailable(self, pki):
        act = entry.live_card_activator(
            pki['ca_bundle'],
            token_factory=_factory(pki, raises=PivTokenError('PIN login failed: CKR_PIN_INCORRECT')))
        result = act('0000', '')
        assert result.status == 'REJECTED'
        assert 'PIN' in result.reason

    def test_no_card_is_unavailable(self, pki):
        act = entry.live_card_activator(
            pki['ca_bundle'],
            token_factory=_factory(pki, raises=PivTokenError('no PKCS#11 token present')))
        result = act('123456', '')
        assert result.status == 'UNAVAILABLE'
        assert 'token present' in result.reason

    def test_missing_binding_is_unavailable(self, pki):
        act = entry.live_card_activator(
            pki['ca_bundle'],
            token_factory=_factory(pki, raises=PivTokenError('PyKCS11 not installed')))
        assert act('123456', '').status == 'UNAVAILABLE'

    def test_middleware_crash_does_not_escape(self, pki):
        # a segfault-adjacent middleware error must not kill the console
        act = entry.live_card_activator(
            pki['ca_bundle'],
            token_factory=_factory(pki, raises=RuntimeError('middleware exploded')))
        result = act('123456', '')
        assert result.status == 'UNAVAILABLE'
        assert 'middleware exploded' in result.reason

    def test_module_and_slot_are_forwarded(self, pki):
        _FakeCard.opened.clear()
        act = entry.live_card_activator(pki['ca_bundle'],
                                        module_path='/opt/vendor/cackey.so', slot=3,
                                        token_factory=_factory(pki))
        act('123456', '')
        assert _FakeCard.opened[-1]['module'] == '/opt/vendor/cackey.so'
        assert _FakeCard.opened[-1]['slot'] == 3

    def test_module_autodetects_when_unset(self, pki):
        # empty --pkcs11-module becomes None so PyKcs11Token autodetects
        _FakeCard.opened.clear()
        entry.live_card_activator(pki['ca_bundle'],
                                  token_factory=_factory(pki))('123456', '')
        assert _FakeCard.opened[-1]['module'] is None

    def test_totp_enforced_when_secret_set(self, pki):
        from autonomous_trust.core.identity.zta.totp import (generate_totp_secret,
                                                             totp_now)
        secret = generate_totp_secret()
        act = entry.live_card_activator(pki['ca_bundle'], totp_secret=secret,
                                        token_factory=_factory(pki))
        assert getattr(act('123456', '').status, 'value', '') != 'VERIFIED'  # no code
        good = act('123456', totp_now(secret))
        assert getattr(good.status, 'value', good.status) == 'VERIFIED', good.reason


class TestEntryPointWiring:
    def test_ca_bundle_alone_builds_live_activator(self, pki):
        app = entry.build_app(entry.parse_args(['--ca-bundle', pki['ca_bundle']]))
        assert app.activation_configured is True
        # no `.token` attribute -> presence stays the live probe, not a software token
        assert getattr(app.activator, 'token', None) is None

    def test_software_flags_still_take_precedence(self, pki):
        args = entry.parse_args([
            '--software-cert', os.path.join(pki['cfg'], opdemo.DEMO_LEAF_CERT),
            '--software-key', os.path.join(pki['cfg'], opdemo.DEMO_LEAF_KEY),
            '--ca-bundle', pki['ca_bundle']])
        app = entry.build_app(args)
        assert getattr(app.activator, 'token', None) is not None  # software path

    def test_demo_ignores_ca_bundle(self, pki):
        app = entry.build_app(entry.parse_args(
            ['--demo', '--ca-bundle', pki['ca_bundle']]))
        assert getattr(app.activator, 'token', None) is not None  # demo software token

    def test_no_flags_stays_unconfigured(self):
        assert entry.build_app(entry.parse_args([])).activation_configured is False

    def test_new_flags_parse(self):
        args = entry.parse_args(['--ca-bundle', 'c.p7b', '--pkcs11-module', '/m.so',
                                 '--slot', '2', '--crl-path', 'x.crl'])
        assert args.pkcs11_module == '/m.so'
        assert args.slot == 2
        assert args.crl_path == 'x.crl'

    def test_flags_reach_the_core_activate_call(self, pki, monkeypatch):
        # --crl-path / --totp-secret must actually arrive at core activate(),
        # not just parse
        seen = {}
        import autonomous_trust.core.operator.activate as core_act

        def fake_activate(token, ca_bundle_path, **kw):
            seen.update({'bundle': ca_bundle_path, **kw})
            class _R:
                status, reason = 'VERIFIED', 'stub'
            return _R()
        monkeypatch.setattr(core_act, 'activate', fake_activate)
        app = entry.build_app(entry.parse_args(
            ['--ca-bundle', pki['ca_bundle'], '--crl-path', '/tmp/x.crl',
             '--totp-secret', 'ABCDEFGHIJKLMNOP']))
        # drive the wired activator with an injected card
        monkeypatch.setattr(
            'autonomous_trust.core.identity.zta.piv.pkcs11.PyKcs11Token',
            lambda module_path, pin, slot: _FakeCard(module_path, pin, slot,
                                                    pki['token']))
        app.activator('123456', '000000')
        assert seen['bundle'] == pki['ca_bundle']
        assert seen['crl_path'] == '/tmp/x.crl'
        assert seen['totp_secret'] == 'ABCDEFGHIJKLMNOP'
        assert seen['totp_code'] == '000000'


class TestResultRendering:
    """`show_result` must unwrap a `ZtaStatus` enum, not print its repr."""

    def _shown(self, result):
        view = ActivateView()
        rendered = {}

        class _Fake:
            def update(self, text):
                rendered['text'] = str(text)
        view.query_one = lambda *a, **kw: _Fake()  # type: ignore[method-assign]
        view.refresh_token_status = lambda: None   # type: ignore[method-assign]
        view.show_result(result)
        return rendered['text']

    def test_zta_enum_status_renders_bare_and_green(self):
        from autonomous_trust.core.identity.zta import ZtaStatus

        class _R:
            status, reason = ZtaStatus.VERIFIED, 'operator activated'
        shown = self._shown(_R())
        assert '[green]VERIFIED[/]' in shown
        assert 'ZtaStatus' not in shown  # the regression this pins
        assert 'operator activated' in shown

    def test_enum_reject_gets_red(self):
        from autonomous_trust.core.identity.zta import ZtaStatus

        class _R:
            status, reason = ZtaStatus.REJECTED, 'chain error'
        assert '[red]REJECTED[/]' in self._shown(_R())

    def test_plain_string_status_still_works(self):
        class _R:
            status, reason = 'UNAVAILABLE', 'no card'
        assert '[yellow]UNAVAILABLE[/]' in self._shown(_R())

    def test_none_status_falls_back(self):
        class _R:
            status, reason = None, ''
        assert 'UNAVAILABLE' in self._shown(_R())

    def test_every_zta_status_maps_to_a_style(self):
        # no status may silently render unstyled (white) as VERIFIED did
        from autonomous_trust.core.identity.zta import ZtaStatus
        from autonomous_trust.operator.screens.activate import _STATUS_STYLE
        for st in ZtaStatus:
            assert st.value in _STATUS_STYLE, st


class TestConsoleFlow:
    def test_status_line_reads_token_present(self, pki):
        # with a live activator wired, a detected card is plainly ready
        from autonomous_trust.core.identity.zta.piv.pkcs11 import TokenProbe
        app = OperatorApp(auto_start=False, poll_interval=0.05,
                          activator=entry.live_card_activator(
                              pki['ca_bundle'], token_factory=_factory(pki)),
                          token_provider=lambda: TokenProbe(True, '/m.so', 'slot 0'))

        async def scenario():
            async with app.run_test() as pilot:
                await pilot.pause()
                text = str(app.query_one('#token-status', Static).content)
                assert 'token present' in text
                assert 'cannot activate' not in text
                assert '--ca-bundle' not in text
        _run(scenario)

    def test_pin_entry_activates_and_is_cleared(self, pki):
        from autonomous_trust.core.identity.zta.piv.pkcs11 import TokenProbe
        app = OperatorApp(auto_start=False, poll_interval=0.05,
                          activator=entry.live_card_activator(
                              pki['ca_bundle'], token_factory=_factory(pki)),
                          token_provider=lambda: TokenProbe(True, '/m.so', 'slot 0'))

        async def scenario():
            async with app.run_test() as pilot:
                await pilot.pause()
                app.query_one('#pin', Input).value = '123456'
                app.query_one('#activate-btn', Button).press()
                await pilot.pause()
                shown = str(app.query_one('#activate-result', Static).content)
                # the enum must be unwrapped, not rendered as its repr, and the
                # style lookup must land (green) rather than falling back to white
                assert 'ZtaStatus' not in shown
                assert '[green]VERIFIED[/]' in shown
                assert 'operator activated' in shown
                assert app.activated is True
                # PIN must never linger in the widget after activation
                assert app.query_one('#pin', Input).value == ''
        _run(scenario)

    def test_bad_pin_shows_rejected(self, pki):
        from autonomous_trust.core.identity.zta.piv.pkcs11 import TokenProbe
        act = entry.live_card_activator(
            pki['ca_bundle'],
            token_factory=_factory(pki, raises=PivTokenError('PIN login failed')))
        app = OperatorApp(auto_start=False, poll_interval=0.05, activator=act,
                          token_provider=lambda: TokenProbe(True, '/m.so', 'slot 0'))

        async def scenario():
            async with app.run_test() as pilot:
                await pilot.pause()
                view = app.query_one('#view-activate', ActivateView)
                app.query_one('#pin', Input).value = '0000'
                view.activate()
                await pilot.pause()
                result = str(app.query_one('#activate-result', Static).content)
                assert 'REJECTED' in result and 'PIN' in result
        _run(scenario)
