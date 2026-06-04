"""Unit tests for the demo pause / auto-pause state machine.

These cover the pure decision logic behind the Pause/Resume button and the
"auto-pause right before the narrative" behavior wired into
``dashboard/live_server.py``. The logic lives in the Dash-free
``dashboard/pause_control.py`` module so it's verifiable without standing up a
server (Dash/plotly are the operator-side heavy deps); the full callback
wiring is exercised live.

Run: ``pytest examples/dod_mission/test_pause_control.py``
"""
import sys
from pathlib import Path

# Import the module directly (add the dashboard dir to the path) rather than
# via the `dashboard` package, whose __init__ pulls in the Dash-heavy app
# modules. pause_control itself has no heavy deps, so this runs anywhere.
sys.path.insert(0, str(Path(__file__).resolve().parent / "dashboard"))
import pause_control as pc  # noqa: E402


# ---- apply_pause_click --------------------------------------------------

def test_click_pauses_a_running_demo_and_latches_auto_done():
    # Running, auto-pause not yet fired; a click should pause and latch.
    assert pc.apply_pause_click(True, False, False) == (True, True)


def test_click_resumes_a_paused_demo():
    assert pc.apply_pause_click(True, True, True) == (False, True)


def test_no_click_is_a_no_op():
    assert pc.apply_pause_click(False, False, False) == (False, False)
    assert pc.apply_pause_click(False, True, True) == (True, True)


def test_click_latches_auto_done_even_when_resuming():
    # Manual control must disable any later auto-pause, even on a resume click.
    _, auto_done = pc.apply_pause_click(True, True, False)
    assert auto_done is True


# ---- auto_pause ---------------------------------------------------------

def test_auto_pause_fires_once_at_the_cue():
    # Clock reaches the cue, auto-pause not yet done -> freeze + latch.
    assert pc.auto_pause(False, False, 0.0, 0.0) == (True, True)
    assert pc.auto_pause(False, False, 120.0, 120.0) == (True, True)


def test_auto_pause_does_not_fire_before_the_cue():
    assert pc.auto_pause(False, False, 59.0, 60.0) == (False, False)


def test_auto_pause_does_not_refire_once_done():
    # Already latched (operator resumed, or it fired earlier): stay running.
    assert pc.auto_pause(False, True, 500.0, 60.0) == (False, True)


def test_auto_pause_disabled_when_no_cue():
    # narration_start_t None => feature off; never freezes.
    assert pc.auto_pause(False, False, 9999.0, None) == (False, False)


def test_auto_pause_preserves_paused_flag_when_not_firing():
    assert pc.auto_pause(True, True, 10.0, 5.0) == (True, True)


# ---- representative tick sequence (how _refresh threads the two) --------

def test_sequence_autopause_then_manual_resume_then_manual_pause():
    cue = 0.0
    is_paused, auto_done = False, False

    # Tick 1 (running): no click; clock at cue -> auto-pause fires.
    is_paused, auto_done = pc.apply_pause_click(False, is_paused, auto_done)
    is_paused, auto_done = pc.auto_pause(is_paused, auto_done, 1.0, cue)
    assert (is_paused, auto_done) == (True, True)

    # Tick 2 (frozen): operator clicks Resume.
    is_paused, auto_done = pc.apply_pause_click(True, is_paused, auto_done)
    assert (is_paused, auto_done) == (False, True)
    # auto_pause must not re-fire now that it's latched.
    is_paused, auto_done = pc.auto_pause(is_paused, auto_done, 5.0, cue)
    assert is_paused is False

    # Tick 3 (running): operator clicks Pause mid-narrative.
    is_paused, auto_done = pc.apply_pause_click(True, is_paused, auto_done)
    assert is_paused is True
