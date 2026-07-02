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
"""Operator session lifecycle tests (card-removal, idle, step-up, reverify)."""
from autonomous_trust.core.operator.session import (
    OperatorSession, SessionState, RequestDecision)


class _Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t

    def advance(self, dt):
        self.t += dt


class _FakeToken:
    def __init__(self, present=True):
        self.present = present

    def is_present(self):
        return self.present


class TestCardRemoval:
    def test_card_removal_locks_and_zeroizes(self):
        clk = _Clock()
        tok = _FakeToken(present=True)
        zeroed = []
        s = OperatorSession(token=tok, now=clk, zeroize=lambda: zeroed.append(True))
        s.register_secret('pin_session', object())
        assert s.poll() is SessionState.ACTIVE
        tok.present = False
        assert s.poll() is SessionState.LOCKED
        assert s.lock_reason == 'card removed'
        assert s.get_secret('pin_session') is None   # zeroized
        assert zeroed == [True]                       # callback fired

    def test_locked_request_denied(self):
        clk = _Clock()
        tok = _FakeToken(present=False)
        s = OperatorSession(token=tok, now=clk)
        assert s.authorize(required_tier=0) is RequestDecision.LOCKED


class TestIdleTimeout:
    def test_idle_locks(self):
        clk = _Clock()
        s = OperatorSession(idle_timeout_sec=300, now=clk)
        s.touch()
        clk.advance(301)
        assert s.poll() is SessionState.LOCKED
        assert s.lock_reason == 'idle timeout'

    def test_activity_resets_idle(self):
        clk = _Clock()
        s = OperatorSession(idle_timeout_sec=300, now=clk)
        clk.advance(200)
        s.touch()
        clk.advance(200)            # 400 total, but only 200 since last touch
        assert s.poll() is SessionState.ACTIVE

    def test_unlock_requires_card_and_reauth(self):
        clk = _Clock()
        tok = _FakeToken(present=True)
        s = OperatorSession(token=tok, idle_timeout_sec=300, now=clk)
        clk.advance(301)
        assert s.poll() is SessionState.LOCKED
        assert s.unlock(reauth_ok=False) is False     # re-auth failed
        tok.present = False
        assert s.unlock(reauth_ok=True) is False       # card absent
        tok.present = True
        assert s.unlock(reauth_ok=True) is True
        assert s.poll() is SessionState.ACTIVE


class TestStepUp:
    def test_high_tier_requires_step_up(self):
        clk = _Clock()
        s = OperatorSession(step_up_tier=2, now=clk)
        assert s.authorize(required_tier=1) is RequestDecision.ALLOW
        assert s.authorize(required_tier=2) is RequestDecision.STEP_UP_REQUIRED
        s.complete_step_up()
        # Immediately after step-up (grace 0, same instant) the request proceeds.
        assert s.authorize(required_tier=2) is RequestDecision.ALLOW

    def test_step_up_grace_window(self):
        clk = _Clock()
        s = OperatorSession(step_up_tier=2, step_up_grace_sec=60, now=clk)
        s.complete_step_up()
        clk.advance(30)
        assert s.authorize(required_tier=3) is RequestDecision.ALLOW   # within grace
        clk.advance(40)                                                 # 70 > 60
        assert s.authorize(required_tier=3) is RequestDecision.STEP_UP_REQUIRED


class TestReverify:
    def test_needs_reverify_after_interval(self):
        clk = _Clock()
        s = OperatorSession(reverify_interval_sec=3600, now=clk)
        assert s.needs_reverify() is False
        clk.advance(3600)
        assert s.needs_reverify() is True
        s.mark_verified()
        assert s.needs_reverify() is False

    def test_reverify_disabled_when_zero(self):
        clk = _Clock()
        s = OperatorSession(reverify_interval_sec=0, now=clk)
        clk.advance(100000)
        assert s.needs_reverify() is False
