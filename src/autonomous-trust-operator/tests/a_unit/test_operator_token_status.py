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
"""Card-present status on the Activate view: the entry point must wire a real
token provider (live PKCS#11 probe, or the software token when one is in play),
and the status line must render the probe's reason.

Regression guard: `build_app` once left `token_provider` unset, so the console
defaulted to ``lambda: False`` and always claimed "no token detected" with a card
in the reader."""
import asyncio
import tempfile

from textual.widgets import Static, TabbedContent

from autonomous_trust.core.identity.zta.piv.pkcs11 import TokenProbe
from autonomous_trust.operator import __main__ as entry
from autonomous_trust.operator.app import (ACTIVATION_SETUP_HINT,
                                           ACTIVATION_SETUP_SHORT, OperatorApp)
from autonomous_trust.operator.screens import ActivateView


def _run(scenario):
    asyncio.run(scenario())


def _status_text(app):
    return str(app.query_one('#token-status', Static).content)


# -- app seam --------------------------------------------------------------

class TestTokenStatusSeam:
    def test_bool_provider_still_supported(self):
        app = OperatorApp(token_provider=lambda: True, auto_start=False)
        assert app.token_status() == (True, '')
        assert app.token_present() is True

    def test_probe_provider_carries_detail(self):
        probe = TokenProbe(True, '/usr/lib/opensc-pkcs11.so', 'slot 0')
        app = OperatorApp(token_provider=lambda: probe, auto_start=False)
        assert app.token_status() == (True, 'slot 0')
        assert app.token_present() is True

    def test_absent_probe_detail_explains_why(self):
        probe = TokenProbe(False, None, 'no PKCS#11 module found; set X')
        app = OperatorApp(token_provider=lambda: probe, auto_start=False)
        present, detail = app.token_status()
        assert present is False
        assert 'no PKCS#11 module found' in detail

    def test_raising_provider_is_contained(self):
        def boom():
            raise RuntimeError('reader on fire')
        app = OperatorApp(token_provider=boom, auto_start=False)
        present, detail = app.token_status()
        assert present is False
        assert 'reader on fire' in detail   # surfaced, not swallowed silently
        assert app.token_present() is False

    def test_default_provider_reports_no_token(self):
        # constructing the app directly (tests, embedders) keeps the safe default
        app = OperatorApp(auto_start=False)
        assert app.token_status() == (False, '')


# -- insertion polling -----------------------------------------------------

class TestInsertionPolling:
    """A card inserted *after* startup must be picked up on its own: PKCS#11 has
    no insertion event to subscribe to, and the status line was otherwise only
    refreshed at mount and after an activation."""

    def _flipping_app(self, state, interval=0.05):
        return OperatorApp(
            auto_start=False, poll_interval=0.05, token_poll_interval=interval,
            activator=lambda pin, mfa: None,
            token_provider=lambda: TokenProbe(state['in'], '/m.so',
                                              'slot 0' if state['in'] else 'no card'))

    def test_insertion_after_start_is_detected(self):
        state = {'in': False}
        app = self._flipping_app(state)

        async def scenario():
            async with app.run_test() as pilot:
                await pilot.pause()
                assert 'no token detected' in _status_text(app)
                state['in'] = True          # operator inserts the card
                for _ in range(40):         # no manual refresh, no keypress
                    await pilot.pause(0.05)
                    if 'token present' in _status_text(app):
                        break
                assert 'token present' in _status_text(app)
                assert 'slot 0' in _status_text(app)
        _run(scenario)

    def test_removal_after_start_is_detected(self):
        state = {'in': True}
        app = self._flipping_app(state)

        async def scenario():
            async with app.run_test() as pilot:
                await pilot.pause()
                for _ in range(40):
                    await pilot.pause(0.05)
                    if 'token present' in _status_text(app):
                        break
                state['in'] = False         # card yanked
                for _ in range(40):
                    await pilot.pause(0.05)
                    if 'no token detected' in _status_text(app):
                        break
                assert 'no token detected' in _status_text(app)
        _run(scenario)

    def test_unchanged_state_does_not_repaint(self):
        # each probe is a dlopen + C_Initialize; an idle console must not churn
        state = {'in': True}
        app = self._flipping_app(state)
        repaints = []

        async def scenario():
            async with app.run_test() as pilot:
                await pilot.pause(0.2)
                view = app.query_one('#view-activate', ActivateView)
                real = view.refresh_token_status
                view.refresh_token_status = (
                    lambda state=None: (repaints.append(1), real(state))[1])
                await pilot.pause(0.4)      # several poll ticks, no state change
                assert repaints == []
                state['in'] = False
                for _ in range(40):
                    await pilot.pause(0.05)
                    if repaints:
                        break
                assert len(repaints) >= 1   # ...but a change does repaint
        _run(scenario)

    def test_probe_failure_does_not_kill_the_console(self):
        # a raising probe inside a timer callback must not tear the app down
        calls = {'n': 0}

        def flaky():
            calls['n'] += 1
            raise RuntimeError('pcscd went away')
        app = OperatorApp(auto_start=False, poll_interval=0.05,
                          token_poll_interval=0.05, token_provider=flaky)

        async def scenario():
            async with app.run_test() as pilot:
                await pilot.pause(0.3)
                assert calls['n'] >= 1
                assert app.is_running
                assert 'no token detected' in _status_text(app)
        _run(scenario)

    def test_polling_can_be_disabled(self):
        state = {'in': False}
        app = self._flipping_app(state, interval=0)

        async def scenario():
            async with app.run_test() as pilot:
                await pilot.pause(0.3)
                state['in'] = True
                await pilot.pause(0.3)
                # no poller: the line stays as it was at mount
                assert 'no token detected' in _status_text(app)
        _run(scenario)

    def test_default_interval_is_slower_than_feedback_drain(self):
        # the probe is heavier than a queue poll, so it must not share that cadence
        app = OperatorApp(auto_start=False)
        assert app._token_poll_interval >= app._poll_interval
        assert app._token_poll_interval > 0

    def test_probe_runs_off_the_event_loop(self):
        # the probe must not execute on the UI thread: slow middleware would
        # otherwise stutter the console every tick
        import threading
        threads = []
        state = {'in': False}

        def probe():
            threads.append(threading.current_thread().name)
            return TokenProbe(state['in'], '/m.so', 'slot 0' if state['in'] else 'no')
        app = OperatorApp(auto_start=False, poll_interval=0.05,
                          token_poll_interval=0.05,
                          activator=lambda pin, mfa: None, token_provider=probe)

        async def scenario():
            async with app.run_test() as pilot:
                ui_thread = threading.current_thread().name
                await pilot.pause(0.3)
                polled = [t for t in threads if t != ui_thread]
                assert polled, f'probe never left the UI thread {ui_thread}: {threads}'
        _run(scenario)

    def test_polling_never_calls_the_provider_on_the_ui_thread(self):
        # The invariant that matters: the blocking PKCS#11 call is *never* made
        # from the event loop during background polling. (Asserted structurally
        # rather than by wall clock -- Pilot.pause() waits on worker message
        # flush, so timings measure the harness, not UI responsiveness.)
        import threading
        import time
        seen = []

        def slow_probe():
            seen.append(threading.current_thread().name)
            time.sleep(0.15)
            return TokenProbe(False, '/m.so', 'no card')
        app = OperatorApp(auto_start=False, poll_interval=0.05,
                          token_poll_interval=0.05,
                          activator=lambda pin, mfa: None,
                          token_provider=slow_probe)

        async def scenario():
            async with app.run_test() as pilot:
                ui_thread = threading.current_thread().name
                await pilot.pause(0.1)
                seen.clear()      # drop the deliberate mount-time inline probe
                await pilot.pause(0.4)
                assert seen, 'never probed'
                assert ui_thread not in seen, (
                    f'poll probe ran on the UI thread {ui_thread}: {seen}')
        _run(scenario)

    def test_mount_probe_is_inline_by_design(self):
        # The first probe runs on the UI thread so the line is correct as soon as
        # the console appears, rather than flashing an "unknown" state. It is one
        # probe at startup, not a recurring cost.
        import threading
        seen = []

        def probe():
            seen.append(threading.current_thread().name)
            return TokenProbe(True, '/m.so', 'slot 0')
        app = OperatorApp(auto_start=False, poll_interval=0.05,
                          token_poll_interval=0,  # no poller: mount probe only
                          activator=lambda pin, mfa: None, token_provider=probe)

        async def scenario():
            async with app.run_test() as pilot:
                ui_thread = threading.current_thread().name
                await pilot.pause()
                assert seen == [ui_thread]
                assert 'token present' in _status_text(app)
        _run(scenario)

    def test_ui_stays_live_while_a_probe_is_in_flight(self):
        # liveness, not latency: the loop keeps processing actions mid-probe
        import threading
        import time
        gate = threading.Event()

        def blocking_probe():
            gate.set()          # signal that a probe is running
            time.sleep(0.3)     # ...and hold the worker thread for a while
            return TokenProbe(False, '/m.so', 'no card')
        app = OperatorApp(auto_start=False, poll_interval=0.05,
                          token_poll_interval=0.05,
                          activator=lambda pin, mfa: None,
                          token_provider=blocking_probe)

        async def scenario():
            async with app.run_test() as pilot:
                for _ in range(40):          # wait until a probe is mid-flight
                    await pilot.pause(0.02)
                    if gate.is_set():
                        break
                assert gate.is_set()
                app.action_show_tab('directory')   # act while it is still running
                await pilot.pause()
                assert app.query_one('#tabs', TabbedContent).active == 'directory'
        _run(scenario)

    def test_overlapping_probes_are_skipped_not_queued(self):
        # with a probe slower than the interval, ticks must not pile up threads
        import time
        calls = {'n': 0}

        def slow_probe():
            calls['n'] += 1
            time.sleep(0.2)
            return TokenProbe(False, '/m.so', 'no card')
        app = OperatorApp(auto_start=False, poll_interval=0.05,
                          token_poll_interval=0.02, token_provider=slow_probe)

        async def scenario():
            async with app.run_test() as pilot:
                await pilot.pause(0.5)   # ~25 ticks, but each probe takes 0.2s
                assert calls['n'] <= 5, f'probes piled up: {calls["n"]}'
                assert calls['n'] >= 1
        _run(scenario)

    def test_threaded_probe_result_reaches_the_line(self):
        state = {'in': False}
        app = self._flipping_app(state)

        async def scenario():
            async with app.run_test() as pilot:
                await pilot.pause(0.15)
                state['in'] = True
                for _ in range(60):
                    await pilot.pause(0.05)
                    if 'token present' in _status_text(app):
                        break
                # rendered from the worker's state, via call_from_thread
                assert 'token present' in _status_text(app)
                assert 'slot 0' in _status_text(app)
        _run(scenario)

    def test_view_renders_passed_state_without_probing(self):
        # the poller's repaint path must not re-invoke the provider
        calls = {'n': 0}

        def counting():
            calls['n'] += 1
            return TokenProbe(True, '/m.so', 'slot 0')
        app = OperatorApp(auto_start=False, poll_interval=0.05,
                          token_poll_interval=0, activator=lambda p, m: None,
                          token_provider=counting)

        async def scenario():
            async with app.run_test() as pilot:
                await pilot.pause()
                before = calls['n']
                view = app.query_one('#view-activate', ActivateView)
                view.refresh_token_status((True, 'slot 7'))
                await pilot.pause()
                assert calls['n'] == before      # no probe on this path
                assert 'slot 7' in _status_text(app)
        _run(scenario)


# -- activation-setup instructions -----------------------------------------

class TestActivationHint:
    def test_stub_reason_names_the_full_invocation(self):
        # --ca-bundle alone does NOT build an activator (build_app requires the
        # cert+key too), so the instruction must not imply it is sufficient
        from autonomous_trust.operator.app import _default_activator
        reason = _default_activator('1234', '').reason
        assert '--ca-bundle' in reason
        assert '--software-cert' in reason and '--software-key' in reason
        assert 'CA' in reason  # says what the bundle is

    def test_stub_reason_is_honest_about_live_cards(self):
        # the operator's actual situation: card inserted, PIN entered, refused
        assert 'not wired' in ACTIVATION_SETUP_HINT
        assert 'detected' in ACTIVATION_SETUP_HINT

    def test_short_hint_fits_a_status_line(self):
        assert '\n' not in ACTIVATION_SETUP_SHORT
        assert len(ACTIVATION_SETUP_SHORT) < 60
        assert '--ca-bundle' in ACTIVATION_SETUP_SHORT

    def test_hint_empty_once_configured(self):
        app = OperatorApp(auto_start=False, activator=lambda pin, mfa: None)
        assert app.activation_hint == ''

    def test_hint_set_for_stub(self):
        assert OperatorApp(auto_start=False).activation_hint == ACTIVATION_SETUP_SHORT

    def test_demo_is_configured(self):
        app = entry.build_app(entry.parse_args(['--demo']))
        assert app.activation_configured is True
        assert app.activation_hint == ''

    def test_no_args_is_unconfigured(self):
        # the live-card run: presence works, activation does not
        app = entry.build_app(entry.parse_args([]))
        assert app.activation_configured is False

    def test_software_cert_run_is_configured(self):
        import os
        from autonomous_trust.operator import demo as opdemo
        cfg = tempfile.mkdtemp()
        _token, ca_bundle = opdemo.mint_demo_pki(cfg)
        app = entry.build_app(entry.parse_args([
            '--software-cert', os.path.join(cfg, opdemo.DEMO_LEAF_CERT),
            '--software-key', os.path.join(cfg, opdemo.DEMO_LEAF_KEY),
            '--ca-bundle', ca_bundle]))
        assert app.activation_configured is True

    def test_ca_bundle_alone_now_wires_the_live_card(self):
        # A bundle with no software cert/key means "the token is the card in the
        # reader" -- everything activation needs is present, so it is configured.
        app = entry.build_app(entry.parse_args(['--ca-bundle', '/some/ca.p7b']))
        assert app.activation_configured is True
        assert app.activation_hint == ''


# -- entry-point wiring (the actual bug) -----------------------------------

class TestEntryPointWiring:
    def test_no_args_wires_live_probe(self, monkeypatch):
        # A card in the reader must read as present, driven by the live probe.
        import autonomous_trust.core.identity.zta.piv.pkcs11 as pk
        monkeypatch.setattr(
            pk, 'probe_token',
            lambda *a, **kw: TokenProbe(True, '/usr/lib/opensc-pkcs11.so', 'slot 0'))
        app = entry.build_app(entry.parse_args([]))
        assert app.token_status() == (True, 'slot 0')

    def test_no_args_reports_empty_reader(self, monkeypatch):
        import autonomous_trust.core.identity.zta.piv.pkcs11 as pk
        monkeypatch.setattr(
            pk, 'probe_token',
            lambda *a, **kw: TokenProbe(False, '/m.so', 'module loaded, no card'))
        app = entry.build_app(entry.parse_args([]))
        assert app.token_status() == (False, 'module loaded, no card')

    def test_provider_is_not_the_false_stub(self):
        # the regression itself: default construction vs. entry-point construction
        stub = OperatorApp(auto_start=False)._token_provider
        wired = entry.build_app(entry.parse_args([]))._token_provider
        assert wired is not stub
        assert callable(wired)

    def test_probe_is_lazy_not_called_at_build(self, monkeypatch):
        # building the app must not touch PKCS#11 (headless/CI safety); the probe
        # runs when the view mounts
        import autonomous_trust.core.identity.zta.piv.pkcs11 as pk
        calls = []

        def counting(*a, **kw):
            calls.append(1)
            return TokenProbe(False, None, 'nope')
        monkeypatch.setattr(pk, 'probe_token', counting)
        entry.build_app(entry.parse_args([]))
        assert calls == []

    def test_demo_uses_software_token(self):
        # --demo has no card; presence follows the minted software token and is
        # labeled so nobody mistakes it for real hardware
        app = entry.build_app(entry.parse_args(['--demo']))
        present, detail = app.token_status()
        assert present is True
        assert 'software' in detail.lower()

    def test_software_cert_files_use_software_token(self):
        from autonomous_trust.operator import demo as opdemo
        cfg = tempfile.mkdtemp()
        _token, ca_bundle = opdemo.mint_demo_pki(cfg)
        import os
        args = entry.parse_args([
            '--software-cert', os.path.join(cfg, opdemo.DEMO_LEAF_CERT),
            '--software-key', os.path.join(cfg, opdemo.DEMO_LEAF_KEY),
            '--ca-bundle', ca_bundle])
        app = entry.build_app(args)
        present, detail = app.token_status()
        assert present is True
        assert 'software' in detail.lower()

    def test_software_activator_exposes_its_token(self):
        # the seam _token_provider_for keys on
        from autonomous_trust.operator import demo as opdemo
        token, ca_bundle = opdemo.mint_demo_pki(tempfile.mkdtemp())
        activator = opdemo.software_activator(token, ca_bundle)
        assert getattr(activator, 'token', None) is token

    def test_software_token_removal_flips_status(self):
        from autonomous_trust.operator import demo as opdemo
        token, ca_bundle = opdemo.mint_demo_pki(tempfile.mkdtemp())
        provider = entry.software_token_provider(token)
        assert provider().present is True
        token.remove()
        assert provider().present is False

    def test_live_provider_degrades_without_pkcs11(self, monkeypatch):
        # a box with no binding at all must still start the console
        import builtins
        real_import = builtins.__import__

        def no_pykcs11(name, *a, **kw):
            if name == 'PyKCS11':
                raise ImportError('nope')
            return real_import(name, *a, **kw)
        monkeypatch.setattr(builtins, '__import__', no_pykcs11)
        app = OperatorApp(token_provider=entry.live_token_provider(),
                          auto_start=False)
        present, detail = app.token_status()
        assert present is False
        assert detail  # says something actionable rather than nothing


# -- rendering -------------------------------------------------------------

class TestStatusLineRender:
    def test_present_renders_with_slot(self):
        app = OperatorApp(auto_start=False, poll_interval=0.05,
                          activator=lambda pin, mfa: None,
                          token_provider=lambda: TokenProbe(True, '/m.so', 'slot 0'))

        async def scenario():
            async with app.run_test() as pilot:
                await pilot.pause()
                text = _status_text(app)
                assert 'token present' in text
                assert 'slot 0' in text
        _run(scenario)

    def test_absent_renders_reason(self):
        probe = TokenProbe(False, None, 'no PKCS#11 module found; set FOO')
        app = OperatorApp(auto_start=False, poll_interval=0.05,
                          token_provider=lambda: probe)

        async def scenario():
            async with app.run_test() as pilot:
                await pilot.pause()
                text = _status_text(app)
                assert 'no token detected' in text
                assert 'no PKCS#11 module found' in text
        _run(scenario)

    def test_bool_provider_renders_without_detail(self):
        app = OperatorApp(auto_start=False, poll_interval=0.05,
                          token_provider=lambda: False)

        async def scenario():
            async with app.run_test() as pilot:
                await pilot.pause()
                assert 'no token detected' in _status_text(app)
        _run(scenario)

    def test_status_refreshes_on_reinsert(self):
        # probe is re-run per refresh, so inserting a card updates the line
        state = {'in': False}
        app = OperatorApp(
            auto_start=False, poll_interval=0.05,
            activator=lambda pin, mfa: None,
            token_provider=lambda: TokenProbe(state['in'], '/m.so',
                                              'slot 0' if state['in'] else 'no card'))

        async def scenario():
            async with app.run_test() as pilot:
                await pilot.pause()
                assert 'no token detected' in _status_text(app)
                state['in'] = True
                app.query_one('#view-activate', ActivateView).refresh_token_status()
                await pilot.pause()
                assert 'token present' in _status_text(app)
        _run(scenario)

    def test_present_but_unconfigured_claims_neither(self):
        # The reported confusion: a real card reads "token present", then Activate
        # returns UNAVAILABLE. The line must claim neither readiness nor absence.
        app = OperatorApp(auto_start=False, poll_interval=0.05,
                          token_provider=lambda: TokenProbe(True, '/m.so', 'slot 0'))
        assert app.activation_configured is False  # stub activator

        async def scenario():
            async with app.run_test() as pilot:
                await pilot.pause()
                text = _status_text(app)
                assert 'card detected' in text
                assert 'cannot activate' in text
                assert 'token present' not in text     # would imply readiness
                assert 'no token detected' not in text  # plainly false
                assert '--ca-bundle' in text            # names the fix
                assert 'slot 0' in text                 # keeps the probe detail
        _run(scenario)

    def test_absent_and_unconfigured_reports_both(self):
        probe = TokenProbe(False, '/m.so', 'module loaded, no card in any slot')
        app = OperatorApp(auto_start=False, poll_interval=0.05,
                          token_provider=lambda: probe)

        async def scenario():
            async with app.run_test() as pilot:
                await pilot.pause()
                text = _status_text(app)
                assert 'no token detected' in text
                assert 'no card in any slot' in text
                assert '--ca-bundle' in text
        _run(scenario)

    def test_configured_present_says_token_present(self):
        # a wired activator restores the plain green reading
        app = OperatorApp(auto_start=False, poll_interval=0.05,
                          activator=lambda pin, mfa: None,
                          token_provider=lambda: TokenProbe(True, '/m.so', 'slot 0'))
        assert app.activation_configured is True

        async def scenario():
            async with app.run_test() as pilot:
                await pilot.pause()
                text = _status_text(app)
                assert 'token present' in text
                assert 'cannot activate' not in text
                assert '--ca-bundle' not in text  # no nagging once configured
        _run(scenario)

    def test_result_line_warns_before_any_press(self):
        app = OperatorApp(auto_start=False, poll_interval=0.05,
                          token_provider=lambda: TokenProbe(True, '/m.so', 'slot 0'))

        async def scenario():
            async with app.run_test() as pilot:
                await pilot.pause()
                result = str(app.query_one('#activate-result', Static).content)
                assert 'activation not configured' in result
                assert 'enter PIN' not in result  # no futile invitation
        _run(scenario)

    def test_result_line_keeps_prompt_when_configured(self):
        app = OperatorApp(auto_start=False, poll_interval=0.05,
                          activator=lambda pin, mfa: None,
                          token_provider=lambda: TokenProbe(True, '/m.so', 'slot 0'))

        async def scenario():
            async with app.run_test() as pilot:
                await pilot.pause()
                result = str(app.query_one('#activate-result', Static).content)
                assert 'enter PIN' in result
        _run(scenario)

    def test_view_falls_back_to_bool_only_app(self):
        # ActivateView is also driven against embedder/stub apps that expose only
        # token_present(); the bool-only branch must render, not raise
        app = OperatorApp(auto_start=False, poll_interval=0.05,
                          activator=lambda pin, mfa: None,
                          token_provider=lambda: True)

        async def scenario():
            async with app.run_test() as pilot:
                await pilot.pause()
                # stand in for a bool-only app: no token_status, just the bool
                app.token_status = None
                app.token_present = lambda: True
                app.query_one('#view-activate', ActivateView).refresh_token_status()
                await pilot.pause()
                assert 'token present' in _status_text(app)
                del app.token_status, app.token_present
        _run(scenario)
