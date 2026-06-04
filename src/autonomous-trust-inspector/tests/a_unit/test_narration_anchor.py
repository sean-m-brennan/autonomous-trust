# ******************
#  Copyright 2025 Sean M. Brennan and contributors
#  Licensed under the Apache License, Version 2.0
# ******************
"""Unit tests for event-anchored narration re-timing."""

from autonomous_trust.inspector.dashboard.narration import (
    NarrationBlock, NarrationAnchor, NarrationOverlay,
    resolve_anchor, resolve_narration,
)


def _recording():
    """A small synthetic recording with an inverted/late timeline so the
    re-timer has something to actually move (cf. the idealised t_starts)."""
    return {
        "event_log": [
            {"t": 0.0, "type": "PEER_JOIN", "peer": "squad-captain"},
            {"t": 300.0, "type": "COMPROMISE_DETECT", "peer": "mq800"},
            {"t": 305.0, "type": "COMPROMISE_DETECT", "peer": "mq800"},
        ],
        "snapshots": [
            {"t": 90.0, "type": "REPUTATION_SAMPLE", "peer": "a", "score": 0.5},
            {"t": 120.0, "type": "REPUTATION_SAMPLE", "peer": "a", "score": 0.8},
            {"t": 95.0, "type": "REPUTATION_SAMPLE", "peer": "b", "score": 0.6},
            {"t": 150.0, "type": "REPUTATION_SAMPLE", "peer": "b", "score": 0.9},
            {"t": 200.0, "type": "REPUTATION_SAMPLE", "peer": "mq800",
             "score": 0.5},
            {"t": 320.0, "type": "REPUTATION_SAMPLE", "peer": "mq800",
             "score": 0.1},
        ],
    }


def test_event_anchor_uses_first_matching_event():
    rec = _recording()
    a = NarrationAnchor(kind="event", event_type="COMPROMISE_DETECT",
                        peer="mq800")
    assert resolve_anchor(a, rec) == 300.0
    # offset is additive
    a2 = NarrationAnchor(kind="event", event_type="COMPROMISE_DETECT",
                         peer="mq800", offset=5.0)
    assert resolve_anchor(a2, rec) == 305.0


def test_event_anchor_missing_returns_none():
    a = NarrationAnchor(kind="event", event_type="PEER_EXCLUDE", peer="mq800")
    assert resolve_anchor(a, _recording()) is None


def test_peer_sample_first_above_below():
    rec = _recording()
    assert resolve_anchor(
        NarrationAnchor(kind="peer_sample", peer="mq800", op="first"),
        rec) == 200.0
    assert resolve_anchor(
        NarrationAnchor(kind="peer_sample", peer="a", op="above",
                        threshold=0.7), rec) == 120.0
    assert resolve_anchor(
        NarrationAnchor(kind="peer_sample", peer="mq800", op="below",
                        threshold=0.5), rec) == 320.0


def test_cohort_above_fires_when_last_member_crosses():
    rec = _recording()
    a = NarrationAnchor(kind="cohort_above", op="above", threshold=0.7,
                        cohort=["a", "b"])
    # a crosses 0.7 at 120, b at 150 -> cohort satisfied at 150
    assert resolve_anchor(a, rec) == 150.0


def test_cohort_above_unmet_returns_none():
    rec = _recording()
    # 'c' never produces a sample -> never satisfied
    a = NarrationAnchor(kind="cohort_above", op="above", threshold=0.7,
                        cohort=["a", "b", "c"])
    assert resolve_anchor(a, rec) is None


def test_resolve_narration_none_recording_is_identity():
    script = [NarrationBlock(t_start=0, t_end=10, text="x"),
              NarrationBlock(t_start=10, t_end=20, text="y")]
    out = resolve_narration(script, None)
    assert [b.t_start for b in out] == [0, 10]


def test_resolve_narration_retimes_and_persists_until_next():
    script = [
        NarrationBlock(t_start=0, t_end=15, text="intro"),
        NarrationBlock(t_start=240, t_end=255, text="mq800 arrives",
                       anchor=NarrationAnchor(kind="peer_sample", peer="mq800",
                                              op="first")),
    ]
    out = resolve_narration(script, _recording())
    assert out[0].t_start == 0
    # intro persists until the next card begins (no blank gap)
    assert out[0].t_end == out[1].t_start
    # mq800 first sample at 200 -> beat moves earlier than authored 240
    assert out[1].t_start == 200.0
    # last card persists to the end of playback
    assert out[1].t_end is None


def test_resolve_narration_min_dwell_guaranteed_for_every_card():
    # Every card must stay up at least min_dwell, including non-bunched ones.
    script = [
        NarrationBlock(t_start=0, t_end=2, text="a"),    # tiny authored dur
        NarrationBlock(t_start=3, t_end=5, text="b"),
        NarrationBlock(t_start=6, t_end=8, text="c"),
    ]
    out = resolve_narration(script, _recording(), min_dwell=15.0)
    for i in range(len(out) - 1):
        assert out[i].t_end - out[i].t_start >= 15.0


def test_resolve_narration_max_dwell_caps_a_lingering_card():
    script = [
        NarrationBlock(t_start=0, t_end=10, text="early"),
        NarrationBlock(t_start=400, t_end=410, text="much later"),
    ]
    out = resolve_narration(script, _recording(), min_dwell=15.0,
                            max_dwell=45.0)
    # 'early' would otherwise persist 400s until the next card; capped at 45.
    assert out[0].t_end == 45.0
    # last card capped too
    assert out[1].t_end == out[1].t_start + 45.0


def test_resolve_narration_cohort_injected_at_runtime():
    script = [NarrationBlock(
        t_start=100, t_end=120, text="trusted",
        anchor=NarrationAnchor(kind="cohort_above", op="above", threshold=0.7))]
    out = resolve_narration(script, _recording(), cohort=["a", "b"])
    assert out[0].t_start == 150.0
    # the shared script's anchor was not mutated
    assert script[0].anchor.cohort is None


def test_resolve_narration_spaces_bunched_beats_so_all_render():
    # Two beats whose cues resolve to the SAME instant must still each show
    # for the full min_dwell rather than flashing by.
    script = [
        NarrationBlock(t_start=270, t_end=285, text="collapse",
                       anchor=NarrationAnchor(kind="peer_sample", peer="mq800",
                                              op="below", threshold=0.5)),
        NarrationBlock(t_start=285, t_end=305, text="excluded",
                       anchor=NarrationAnchor(kind="peer_sample", peer="mq800",
                                              op="below", threshold=0.2)),
    ]
    out = resolve_narration(script, _recording(), min_dwell=15.0)
    # both resolve to 320; second is pushed out by min_dwell so the first
    # gets its full readable window
    assert out[0].t_start == 320.0
    assert out[1].t_start == 335.0
    assert out[0].t_end - out[0].t_start >= 15.0
    ov = NarrationOverlay(out)
    seen = set()
    t = 315.0
    while t < 360.0:
        ov.advance_to(t)
        if ov.current_block:
            seen.add(ov.current_block.text)
        t += 0.5
    assert seen == {"collapse", "excluded"}


def test_monotonic_keeps_narrative_order_despite_inverted_data():
    # 'detect' cue (event @300) authored before 'collapse' (rep<0.5 @320);
    # even if raw data inverted them, script order is preserved.
    script = [
        NarrationBlock(t_start=255, t_end=270, text="detect",
                       anchor=NarrationAnchor(kind="event",
                                              event_type="COMPROMISE_DETECT",
                                              peer="mq800")),
        NarrationBlock(t_start=270, t_end=285, text="collapse",
                       anchor=NarrationAnchor(kind="peer_sample", peer="mq800",
                                              op="below", threshold=0.5)),
    ]
    out = resolve_narration(script, _recording())
    assert out[0].t_start == 300.0
    assert out[1].t_start >= out[0].t_start
