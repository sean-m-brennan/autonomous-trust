# ******************
#  Copyright 2025 Sean M. Brennan and contributors
#  Licensed under the Apache License, Version 2.0
# ******************
"""Pure pause / auto-pause state machine for the demo dashboard.

Kept free of Dash/plotly imports so the decision logic behind the
Pause/Resume button and the "auto-pause right before the narrative" behavior
is unit-testable without standing up a server. ``live_server`` imports these
and wires them into its tick callback; see ``test_pause_control.py``.
"""
from __future__ import annotations

from typing import Optional


def apply_pause_click(clicked: bool, is_paused: bool,
                      auto_done: bool) -> tuple[bool, bool]:
    """Fold a Pause/Resume button click into the pause state.

    A click toggles ``is_paused`` and latches ``auto_done`` — once the
    operator takes manual control, the auto-pause cue must not fire again.
    Returns the updated ``(is_paused, auto_done)``.
    """
    if clicked:
        return (not is_paused), True
    return is_paused, auto_done


def auto_pause(is_paused: bool, auto_done: bool, t_seconds: float,
               narration_start_t: Optional[float]) -> tuple[bool, bool]:
    """Freeze the demo the first time the clock reaches the narration cue.

    Fires at most once (gated by ``auto_done``) and only when a cue is
    configured (``narration_start_t`` is not ``None``). Returns the updated
    ``(is_paused, auto_done)``.
    """
    if (not auto_done and narration_start_t is not None
            and t_seconds >= narration_start_t):
        return True, True
    return is_paused, auto_done
