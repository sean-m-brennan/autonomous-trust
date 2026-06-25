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
"""Operator session lifecycle (PIV_MFA_OPERATOR_ACCESS_PLAN.md §3.4).

The daemon node stays autonomous; what is *session-gated is the operator's
authority to originate requests*. `OperatorSession` is a small, clock-injectable
state machine enforcing:

  * **Card removal** -- when the PIV token's `is_present()` flips false, the
    session locks and in-memory secrets are zeroized.
  * **Idle timeout** -- no activity for ``idle_timeout_sec`` locks the session;
    resuming requires fresh re-auth (PIN + second factor).
  * **Step-up re-auth** -- originating a request whose target ``required_tier``
    is at/above ``step_up_tier`` forces a fresh MFA challenge.
  * **Periodic re-verify** -- ``reverify_interval_sec`` (from `ZtaPolicy`) bounds
    how long a verification stays fresh.

It owns no node and no I/O: callers poll it and act on its decisions, so it is
deterministic and unit-testable with an injected clock.
"""
from __future__ import annotations

import time
from enum import Enum
from typing import Callable, Optional


class SessionState(Enum):
    ACTIVE = 'active'
    LOCKED = 'locked'


class RequestDecision(Enum):
    ALLOW = 'allow'                      # originate the request
    STEP_UP_REQUIRED = 'step_up_required'  # high tier: re-auth, then retry
    LOCKED = 'locked'                    # session locked: re-auth to resume


class OperatorSession:
    """Local auth-state gate for operator request origination.

    Args:
        token:                a `PivToken` whose `is_present()` drives
                              card-removal locking (None => always present).
        idle_timeout_sec:     inactivity before auto-lock (0 disables).
        reverify_interval_sec: freshness window for the last verification
                              (mirrors `ZtaPolicy.reverify_interval_sec`).
        step_up_tier:         requests with required_tier >= this force step-up.
        step_up_grace_sec:    a completed step-up authorizes high-tier requests
                              for this long (0 => step up every high-tier request).
        now:                  monotonic clock (injectable for tests).
        zeroize:              optional callback invoked on lock to wipe external
                              secret material (e.g. close the PKCS#11 session).
    """

    def __init__(self, token=None, idle_timeout_sec: float = 300,
                 reverify_interval_sec: float = 3600,
                 step_up_tier: int = 2, step_up_grace_sec: float = 0,
                 now: Callable[[], float] = time.monotonic,
                 zeroize: Optional[Callable[[], None]] = None):
        self._token = token
        self._idle_timeout = idle_timeout_sec
        self._reverify_interval = reverify_interval_sec
        self._step_up_tier = step_up_tier
        self._step_up_grace = step_up_grace_sec
        self._now = now
        self._zeroize_cb = zeroize
        self.state = SessionState.ACTIVE
        self.lock_reason = ''
        self._secrets: dict = {}
        t = now()
        self._last_activity = t
        self._last_verify = t
        # None => no explicit step-up yet, so the first high-tier request forces
        # a fresh MFA challenge (activation MFA does not pre-authorize high tier).
        self._last_step_up: Optional[float] = None

    # -- secret custody --------------------------------------------------

    def register_secret(self, key: str, value) -> None:
        """Hold an in-memory secret to be zeroized on lock."""
        self._secrets[key] = value

    def get_secret(self, key: str):
        return self._secrets.get(key)

    def _zeroize(self) -> None:
        # Best-effort: drop references and clear the map, then let the caller
        # tear down external material. (Python can't truly wipe immutables; the
        # PIN/key proper never leave the card -- see plan §8.)
        for k in list(self._secrets):
            self._secrets[k] = None
        self._secrets.clear()
        if self._zeroize_cb is not None:
            try:
                self._zeroize_cb()
            except Exception:
                pass

    # -- card / activity -------------------------------------------------

    def card_present(self) -> bool:
        if self._token is None:
            return True
        try:
            return bool(self._token.is_present())
        except Exception:
            return False

    def touch(self) -> None:
        """Record operator activity (resets the idle timer) while active."""
        if self.state is SessionState.ACTIVE:
            self._last_activity = self._now()

    # -- lock / unlock ---------------------------------------------------

    def lock(self, reason: str) -> None:
        if self.state is SessionState.LOCKED:
            return
        self.state = SessionState.LOCKED
        self.lock_reason = reason
        self._zeroize()

    def poll(self) -> SessionState:
        """Re-evaluate lock conditions (card removal, idle). Call each tick."""
        if self.state is SessionState.LOCKED:
            return self.state
        if not self.card_present():
            self.lock('card removed')
        elif self._idle_timeout and (
                self._now() - self._last_activity > self._idle_timeout):
            self.lock('idle timeout')
        return self.state

    def unlock(self, reauth_ok: bool) -> bool:
        """Resume after fresh re-auth (PIN + second factor done by the caller).

        Returns True if resumed. Refuses if re-auth failed or the card is absent.
        """
        if not reauth_ok or not self.card_present():
            return False
        t = self._now()
        self.state = SessionState.ACTIVE
        self.lock_reason = ''
        self._last_activity = t
        self._last_verify = t
        # Re-auth resumes the session but does not pre-authorize high tier; the
        # next high-tier request still forces a fresh step-up.
        self._last_step_up = None
        return True

    # -- re-verification -------------------------------------------------

    def needs_reverify(self) -> bool:
        if not self._reverify_interval:
            return False
        return (self._now() - self._last_verify) >= self._reverify_interval

    def mark_verified(self) -> None:
        self._last_verify = self._now()

    # -- request authorization ------------------------------------------

    def authorize(self, required_tier: int = 0) -> RequestDecision:
        """Decide whether the operator may originate a request right now."""
        if self.poll() is SessionState.LOCKED:
            return RequestDecision.LOCKED
        if required_tier >= self._step_up_tier and (
                self._last_step_up is None
                or (self._now() - self._last_step_up) > self._step_up_grace):
            return RequestDecision.STEP_UP_REQUIRED
        self.touch()
        return RequestDecision.ALLOW

    def complete_step_up(self) -> None:
        """Record a successful step-up MFA challenge for a high-tier request."""
        t = self._now()
        self._last_step_up = t
        self._last_activity = t
        self._last_verify = t
