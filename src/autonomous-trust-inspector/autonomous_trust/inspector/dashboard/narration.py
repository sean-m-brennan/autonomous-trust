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

"""
Narration overlay system for presentation mode — reusable across demos.

Displays phase-specific explanatory text overlaid on the dashboard.
In presentation mode, these appear as semi-transparent banners that
auto-advance with the scenario timeline or hold on pause.

The narration credits all trust decisions to the autonomous network,
never to a human operator — this is a core design principle.

Each demo provides its own narration script (list of timed text blocks).
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Optional


@dataclass
class NarrationAnchor:
    """A cue that re-times a narration block to a recorded event.

    A block's authored ``t_start`` is the *fallback* — used for live runs
    and when the cue never fires. When a recording is available,
    :func:`resolve_narration` replaces the start with the scenario time at
    which this cue actually occurred, so the narrative tracks the emergent
    timeline (reputation actually crossing a threshold, the rogue actually
    being detected) instead of an idealised schedule.

    Kinds (``kind``):
        "event"        first ``event_log`` record of ``event_type``
                       (optionally restricted to ``peer``).
        "peer_sample"  first ``REPUTATION_SAMPLE`` for ``peer`` whose score
                       satisfies ``op`` vs ``threshold``. ``op`` is one of
                       "first" (any sample), "above" (> threshold),
                       "below" (< threshold).
        "cohort_above" first scenario time at which *every* peer in
                       ``cohort`` has produced a sample > ``threshold``.

    ``offset`` is added to the resolved time (e.g. hold a beat a few
    seconds after the triggering event).
    """
    kind: str
    event_type: Optional[str] = None
    peer: Optional[str] = None
    op: str = "first"
    threshold: Optional[float] = None
    cohort: Optional[list] = None
    offset: float = 0.0


@dataclass
class NarrationBlock:
    """A single narration overlay.

    Attributes:
        t_start:     Scenario time to show (seconds) — fallback when no
                     ``anchor`` resolves (see :class:`NarrationAnchor`).
        t_end:       Scenario time to hide (seconds, None = show until next)
        text:        The narration text (supports simple HTML)
        subtext:     Smaller explanatory text below the main text
        style:       "default", "alert", "success", "info"
        anchor:      Optional cue that re-times this block against a
                     recording (see :func:`resolve_narration`).
        gate:        Optional live-gate key. When set, the block is withheld
                     in a LIVE run until the caller reports the gate satisfied
                     (see :meth:`NarrationOverlay.advance_to`'s ``gates`` arg)
                     — for beats whose real moment floats run-to-run (e.g. a
                     jet strike gated on an emergent threat) and so can't be
                     pinned to a fixed ``t_start``. ``t_start`` still acts as
                     the earliest time the block may show. No effect on the
                     recording path (which re-times via ``anchor``).
    """
    t_start: float
    t_end: Optional[float] = None
    text: str = ""
    subtext: str = ""
    style: str = "default"
    anchor: Optional[NarrationAnchor] = None
    gate: Optional[str] = None


STYLE_COLORS = {
    "default": {"bg": "rgba(15,23,42,0.85)", "border": "#3B82F6",
                "text": "#E2E8F0"},
    "alert":   {"bg": "rgba(127,29,29,0.85)", "border": "#EF4444",
                "text": "#FCA5A5"},
    "success": {"bg": "rgba(6,78,59,0.85)",   "border": "#10B981",
                "text": "#A7F3D0"},
    "info":    {"bg": "rgba(30,58,138,0.85)",  "border": "#60A5FA",
                "text": "#BFDBFE"},
}


class NarrationOverlay:
    """Manages timed narration blocks and renders the current overlay.

    Usage:
        narration = NarrationOverlay(script=[...])
        narration.advance_to(t_seconds=125.0)
        html = narration.to_html()
    """

    def __init__(self, script: list[NarrationBlock]):
        self._script = sorted(script, key=lambda b: b.t_start)
        self._current: Optional[NarrationBlock] = None
        self._visible = True

    def advance_to(self, t_seconds: float, gates: Optional[dict] = None):
        """Update the current narration block based on scenario time.

        ``gates`` maps gate-key -> bool of live conditions the caller is
        tracking. When a ``gates`` dict is supplied, a block carrying a
        ``gate`` that is not satisfied is skipped (the search falls through to
        the most recent ungated/satisfied block), so a beat whose real moment
        floats — e.g. ``gate="jet_over_target"`` — is held past its authored
        ``t_start`` until its condition is met, without leaving the overlay
        blank (the prior block persists). When ``gates`` is None (no caller
        gating — e.g. canned playback, where a gated block is re-timed by its
        ``anchor`` or falls back to ``t_start``) gates are ignored entirely, so
        behaviour is unchanged. A block with no ``gate`` is never affected."""
        self._current = None
        for block in reversed(self._script):
            if t_seconds >= block.t_start:
                if (gates is not None and block.gate is not None
                        and not gates.get(block.gate)):
                    continue  # gated beat not yet live — try the earlier block
                if block.t_end is None or t_seconds < block.t_end:
                    self._current = block
                break

    @property
    def current_block(self) -> Optional[NarrationBlock]:
        return self._current

    def toggle_visibility(self):
        self._visible = not self._visible

    def to_html(self) -> str:
        """Render the current narration overlay."""
        if not self._visible or self._current is None:
            return ""

        block = self._current
        colors = STYLE_COLORS.get(block.style, STYLE_COLORS["default"])

        subtext_html = ""
        if block.subtext:
            subtext_html = (
                f'<div style="font-size:13px;color:{colors["text"]};'
                f'opacity:0.8;margin-top:6px">{block.subtext}</div>'
            )

        return (
            f'<div style="position:fixed;bottom:40px;left:50%;'
            f'transform:translateX(-50%);max-width:700px;width:90%;'
            f'background:{colors["bg"]};border:1px solid {colors["border"]};'
            f'border-radius:10px;padding:16px 24px;z-index:1000;'
            f'backdrop-filter:blur(8px);text-align:center">'
            f'<div style="font-size:16px;color:{colors["text"]};'
            f'font-weight:500;line-height:1.4">{block.text}</div>'
            f'{subtext_html}'
            f'</div>'
        )


# --- event-anchored re-timing -------------------------------------------

def _iter_snapshots(recording: dict, snap_type: str):
    """Yield (t, snapshot) for sidecar snapshots of ``snap_type``, time-sorted."""
    snaps = recording.get("snapshots") or []
    out = [(float(s.get("t", 0.0)), s) for s in snaps
           if isinstance(s, dict) and s.get("type") == snap_type]
    out.sort(key=lambda ts: ts[0])
    return out


def resolve_anchor(anchor: NarrationAnchor,
                   recording: dict) -> Optional[float]:
    """Compute the scenario time a cue fired in ``recording``, or None.

    ``recording`` is the loaded playback dict (``event_log`` + ``snapshots``
    sidecar, as written by the coordinator's EventRecorder). Returns None
    when the cue never occurs in this recording (the caller then keeps the
    block's authored fallback time).
    """
    if anchor is None:
        return None
    kind = anchor.kind

    if kind == "event":
        events = recording.get("event_log") or []
        hits = [float(e.get("t", 0.0)) for e in events
                if isinstance(e, dict)
                and (anchor.event_type is None
                     or e.get("type") == anchor.event_type)
                and (anchor.peer is None or e.get("peer") == anchor.peer)]
        if hits:
            return min(hits) + anchor.offset
        return None

    if kind == "peer_sample":
        for t, s in _iter_snapshots(recording, "REPUTATION_SAMPLE"):
            if anchor.peer is not None and s.get("peer") != anchor.peer:
                continue
            try:
                score = float(s.get("score", 0.0))
            except (TypeError, ValueError):
                continue
            if anchor.op == "first":
                return t + anchor.offset
            if anchor.op == "above" and anchor.threshold is not None \
                    and score > anchor.threshold:
                return t + anchor.offset
            if anchor.op == "below" and anchor.threshold is not None \
                    and score < anchor.threshold:
                return t + anchor.offset
        return None

    if kind == "cohort_above":
        cohort = set(anchor.cohort or [])
        if not cohort or anchor.threshold is None:
            return None
        # Walk samples in time order; the cue fires the moment the LAST
        # cohort member first crosses the threshold (i.e. all are above).
        above_since: dict = {}
        for t, s in _iter_snapshots(recording, "REPUTATION_SAMPLE"):
            peer = s.get("peer")
            if peer not in cohort:
                continue
            try:
                score = float(s.get("score", 0.0))
            except (TypeError, ValueError):
                continue
            if score > anchor.threshold:
                above_since.setdefault(peer, t)
            else:
                # Dropped back below — must re-cross to count.
                above_since.pop(peer, None)
            if cohort <= set(above_since):
                return max(above_since.values()) + anchor.offset
        return None

    return None


def resolve_narration(script: list[NarrationBlock],
                      recording: Optional[dict],
                      *, cohort: Optional[list] = None,
                      min_dwell: float = 15.0,
                      max_dwell: Optional[float] = None) -> list[NarrationBlock]:
    """Re-time anchored blocks to when their cues actually fired, and pace
    them so each card is readable.

    Returns a new list of blocks (the input is not mutated). For each block
    with an ``anchor`` that resolves against ``recording``, the start moves
    to the cue's actual time; unanchored blocks keep their authored start.
    With ``recording`` None (live mode) this is an identity passthrough
    (the live overlay paces itself off the authored times).

    Pacing model (the recording path):

    * Starts are made monotonic and spaced by at least ``min_dwell`` — a
      beat never precedes the one before it, and cues that resolve to the
      same (or near-identical) instant — e.g. a single reputation sample
      drops the rogue past both the 0.5 and 0.2 lines, or a whole cascade
      lands right after a late detection — are spread out so none flashes
      by faster than it can be read.
    * Each card then stays up **until the next card begins** (persist-until-
      next), so there are no blank gaps mid-narrative and the authored
      relative pacing of well-separated beats is preserved. ``max_dwell``,
      if set, caps how long a single card lingers when the next beat is far
      off (a long dead stretch while waiting for an emergent event), after
      which the card hides; the last card persists to the end of playback
      (capped by ``max_dwell`` when given).

    ``min_dwell`` / ``max_dwell`` are in SCENARIO seconds. At playback
    speeds above 1x a scenario-second is less wall-clock time, so the caller
    should scale ``min_dwell`` by the speed to keep the on-screen time
    constant (see examples/dod_mission/__main__).

    ``cohort`` supplies the peer-name list for any ``cohort_above`` anchor
    that doesn't carry its own (the membership is usually only known at
    runtime, from the scenario roster), without mutating the shared script.
    """
    ordered = sorted(script, key=lambda b: b.t_start)
    if recording is None:
        return list(ordered)
    if max_dwell is not None and max_dwell < min_dwell:
        max_dwell = min_dwell

    # Resolve each block's start: its cue's actual time, else authored.
    starts: list[float] = []
    for b in ordered:
        anchor = b.anchor
        if (anchor is not None and anchor.kind == "cohort_above"
                and not anchor.cohort and cohort):
            anchor = replace(anchor, cohort=list(cohort))
        resolved = resolve_anchor(anchor, recording) if anchor else None
        starts.append(resolved if resolved is not None else float(b.t_start))

    # Monotonic + min_dwell spacing: each start is at least ``min_dwell``
    # after the previous one, which guarantees the previous card (whose end
    # is the next start, below) stays up at least that long.
    cursor: Optional[float] = None
    spaced: list[float] = []
    for start in starts:
        if cursor is not None:
            start = max(start, cursor + min_dwell)
        spaced.append(start)
        cursor = start

    # End each card at the next card's start (persist-until-next → no blank
    # gaps), optionally capped at ``max_dwell`` so a card doesn't linger
    # through a long wait for an emergent beat.
    out: list[NarrationBlock] = []
    for i, (b, start) in enumerate(zip(ordered, spaced)):
        if i + 1 < len(spaced):
            t_end = spaced[i + 1]
        else:
            t_end = None
        if max_dwell is not None:
            capped = start + max_dwell
            t_end = capped if t_end is None else min(t_end, capped)
        out.append(NarrationBlock(
            t_start=start, t_end=t_end, text=b.text, subtext=b.subtext,
            style=b.style, anchor=b.anchor, gate=b.gate))
    return out
