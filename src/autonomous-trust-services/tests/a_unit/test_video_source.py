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

"""`VideoSource`, against real video files (the S12 video-coverage gap).

`VideoSource.next()` is the video service's capture state machine — rate
decimation, `speed` dropping, end-of-file rotation, seeking, resize — and it had
no tests at all. What coverage existed was of constants and of `handle_requests`,
neither of which can fail in a way anyone would notice.

Driven by real clips written with `cv2.VideoWriter` rather than a mocked
`VideoCapture`, because every property under test is a property of *decoding*:
how many frames a call consumes depends on the file's own FPS, and a mock would
return whatever the test already assumed. Each frame is written as a flat
greyscale value carrying its own index, so an assertion can name which frame came
back; the tolerance is for MJPEG, which is lossy.
"""

import os

import pytest

try:
    import cv2
    import numpy as np
    from autonomous_trust.services.video.server import (
        VideoSource, VideoPosition)
    from autonomous_trust.services.data.server import DataConfig
    _HAS_VIDEO = True
except ImportError:
    _HAS_VIDEO = False

pytestmark = pytest.mark.skipif(not _HAS_VIDEO, reason='cv2 not installed')

FRAME_W, FRAME_H = 64, 48
STEP = 6            # pixel value per frame index; wide enough to survive MJPEG


def _write_clip(path, n_frames, fps, base=0):
    """A clip whose i-th frame is a flat field of ``base + i * STEP``."""
    writer = cv2.VideoWriter(path, cv2.VideoWriter_fourcc(*'MJPG'), fps,
                             (FRAME_W, FRAME_H))
    assert writer.isOpened(), 'no MJPG encoder available'
    for i in range(n_frames):
        writer.write(np.full((FRAME_H, FRAME_W, 3), base + i * STEP,
                             dtype=np.uint8))
    writer.release()
    return path


def _frame_index(frame, base=0):
    """Which frame this is, recovered from its pixel value."""
    if frame is None:
        return None
    return round((float(frame[:, :, 0].mean()) - base) / STEP)


def _source(path, fps=60, speed=1, size=None, metric=None):
    """`fps` defaults high so `next()` consumes exactly one frame per call
    unless a test is specifically about rate decimation.

    `metric` resolves to VideoPosition.SECONDS at CALL time, not as a default
    argument: defaults are evaluated when this module is imported, which happens
    even when the cv2 guard above already failed -- naming VideoPosition there
    turned a clean skip into a collection-time NameError for the whole file.
    """
    return VideoSource(DataConfig(path, frame_size=size, speed=speed),
                       frames_per_second=fps,
                       position_metric=VideoPosition.SECONDS if metric is None
                       else metric)


@pytest.fixture
def clip(tmp_path):
    return _write_clip(str(tmp_path / 'clip.avi'), 12, 10.0)


class TestRateDecimation:
    """`next()` consumes ``int(source_fps / requested_fps)`` frames and returns
    the LAST of them, which is how a fast source is watched at a slower rate
    without falling behind."""

    def test_a_faster_source_is_subsampled(self, tmp_path):
        path = _write_clip(str(tmp_path / 'fast.avi'), 12, 20.0)
        src = _source(path, fps=10)          # 20 / 10 -> two frames per call
        got = [_frame_index(src.next()[2]) for _ in range(6)]
        assert got == [1, 3, 5, 7, 9, 11], got

    def test_requesting_more_than_the_source_has_yields_every_frame(self, clip):
        """`int(10/60)` is 0, and a call that consumed no frames would return
        the same image forever; the floor of 1 is what prevents that."""
        src = _source(clip, fps=60)
        got = [_frame_index(src.next()[2]) for _ in range(4)]
        assert got == [0, 1, 2, 3], got


class TestSpeedDecimation:
    """`speed` drops frames by position: only every Nth is emitted."""

    def test_speed_two_emits_every_other_position(self, clip):
        src = _source(clip, speed=2)
        results = [src.next() for _ in range(6)]
        positions = [pos for _more, pos, _f in results]
        emitted = [_frame_index(f) for _m, _p, f in results]
        assert positions == [1, 2, 3, 4, 5, 6]
        # Position 1 is dropped (1 % 2 != 0), so the FIRST call yields nothing.
        # Worth stating rather than glossing: a consumer that treats the first
        # None as end-of-stream sees an empty source.
        assert emitted == [None, 1, None, 3, None, 5], emitted

    def test_speed_one_emits_everything(self, clip):
        src = _source(clip, speed=1)
        assert [_frame_index(src.next()[2]) for _ in range(4)] == [0, 1, 2, 3]


class TestEndOfStreamAndRotation:
    """"Re-entry capable": the source loops rather than ending."""

    def test_exhausting_a_clip_reports_no_more_then_restarts(self, clip):
        src = _source(clip)
        for _ in range(12):
            src.next()
        more, _pos, frame = src.next()
        assert more is False and frame is None
        # The capture is dropped so the next call re-opens from the top.
        assert src.vid_cap is None
        more, pos, frame = src.next()
        assert more is True
        assert pos == 1, 'position restarts with the clip'
        assert _frame_index(frame) == 0

    def test_multiple_paths_rotate_in_glob_order(self, tmp_path):
        _write_clip(str(tmp_path / 'clip_a.avi'), 3, 10.0, base=0)
        _write_clip(str(tmp_path / 'clip_b.avi'), 3, 10.0, base=120)
        src = _source(str(tmp_path / 'clip_*.avi'))
        assert len(src.paths) == 2

        first = [_frame_index(src.next()[2]) for _ in range(3)]
        assert first == [0, 1, 2]
        assert src.next()[2] is None                 # end of clip_a

        second = [_frame_index(src.next()[2], base=120) for _ in range(3)]
        assert second == [0, 1, 2], 'did not roll on to the second file'
        assert src.next()[2] is None                 # end of clip_b

        # ...and back around to the first.
        assert _frame_index(src.next()[2]) == 0


class TestFrameShaping:
    def test_size_resizes_and_keeps_aspect(self, clip):
        src = _source(clip, size=32)
        frame = src.next()[2]
        assert frame.shape[1] == 32
        assert frame.shape[0] == 24, 'aspect ratio not preserved'

    def test_no_size_leaves_the_frame_alone(self, clip):
        assert _source(clip).next()[2].shape[:2] == (FRAME_H, FRAME_W)

    def test_post_proc_runs_before_the_resize(self, clip):
        """Order matters: a detector annotating a frame must see the capture
        resolution, not the transport one, or its boxes land at the wrong
        scale."""
        seen = []

        def note(frame):
            seen.append(frame.shape[:2])
            return frame

        _source(clip, size=32).next(post_proc=note)
        assert seen == [(FRAME_H, FRAME_W)]


class TestDisconnect:
    def test_disconnect_releases_and_rewinds(self, clip):
        src = _source(clip)
        src.next()
        src.next()
        assert src.vid_cap is not None and src.frame_position == 2
        src.disconnect()
        assert src.vid_cap is None and src.frame_position == 0
        # And the next call starts the clip over.
        assert _frame_index(src.next()[2]) == 0

    def test_disconnect_before_any_capture_is_harmless(self, clip):
        src = _source(clip)
        src.disconnect()            # must not raise on a never-opened source
        assert src.vid_cap is None


class TestSeek:
    def test_a_frame_seek_positions_the_first_read(self, clip):
        src = _source(clip, metric=VideoPosition.FRAMES)
        more, pos, frame = src.next(at_position=5)
        assert more is True
        assert _frame_index(frame) == 5
        # The reported position counts frames YIELDED, not the place in the
        # clip: it used to be set to the seek target, which meant a SECONDS
        # seek reported a count in seconds through a field the wire header
        # calls an index.
        assert pos == 1

    def test_a_seconds_seek_positions_the_first_read(self, clip):
        """The clip is 10 fps, so second 0.5 is frame 5. Asserted through the
        SECONDS metric because it is the DEFAULT, and the two metrics take the
        same argument with different units — a caller that picks the wrong one
        gets a plausible frame from the wrong place rather than an error."""
        src = _source(clip, metric=VideoPosition.SECONDS)
        _more, _pos, frame = src.next(at_position=1)     # 1 s @ 10 fps
        assert _frame_index(frame) == 10

    def test_seek_applies_on_every_call_not_just_the_first(self, clip):
        """The fix for the defect this suite found (user's call, 2026-08-13).

        `at_position` used to be honoured only inside the
        ``if self.vid_cap is None`` branch, so every call after the first played
        on sequentially and the argument did nothing. The caller that uses it —
        `evaluation/dash_components/mock_sources.py::VideoSimSource.run` —
        passes `at_position=elapsed` on EVERY tick to track the demo clock, and
        got one frame per tick regardless of how much time had passed, with no
        resync after a pause.
        """
        src = _source(clip, metric=VideoPosition.FRAMES)
        src.next(at_position=0)
        src.next(at_position=0)
        assert _frame_index(src.next(at_position=9)[2]) == 9
        # ...and it can go backwards, which is what a resync after a pause is.
        assert _frame_index(src.next(at_position=1)[2]) == 1

    def test_an_unchanged_position_plays_on_rather_than_replaying(self, clip):
        """A caller polling faster than its clock advances passes the same
        position repeatedly; re-applying it would pin the display to one frame.
        Not re-seeking is also what leaves the no-position caller
        (`VideoProcess.acquire`) playing straight through."""
        src = _source(clip, metric=VideoPosition.FRAMES)
        got = [_frame_index(src.next(at_position=4)[2]) for _ in range(3)]
        assert got == [4, 5, 6], got

    def test_a_position_past_the_end_wraps_instead_of_running_dry(self, clip):
        """A clock-tracking caller runs past a short clip within seconds, and a
        seek beyond the end yields a failed read rather than a frame. Wrapping
        keeps this class's established looping while the position drives the
        rate."""
        src = _source(clip, metric=VideoPosition.FRAMES)   # 12-frame clip
        _more, _pos, frame = src.next(at_position=14)
        assert _frame_index(frame) == 2, 'did not wrap into the clip'

    def test_a_seconds_position_past_the_end_wraps_too(self, clip):
        """The wrap is per-metric — the SECONDS branch divides by the source
        FPS to get a duration — and SECONDS is the default, so it is the branch
        the clock-tracking caller actually takes. The clip is 12 frames at
        10 fps, i.e. 1.2 s, so second 1.5 is second 0.3 is frame 3."""
        src = _source(clip, metric=VideoPosition.SECONDS)
        _more, _pos, frame = src.next(at_position=1.5)
        assert _frame_index(frame) == 3, 'did not wrap into the clip'

    def test_a_fractional_seek_no_longer_suppresses_every_frame(self, clip):
        """`frame_position` used to be BOTH the seek target and the counter
        `speed` decimates on, so a fractional `at_position` made every later
        position fractional, `position % speed` was never 0, and the source
        emitted nothing at all — silently. The two are separate fields now."""
        src = _source(clip, metric=VideoPosition.SECONDS)
        _more, pos, frame = src.next(at_position=0.2)
        assert pos == 1, 'the yielded-frame counter stays an integer'
        assert frame is not None

    def test_the_same_position_is_re_applied_after_a_disconnect(self, clip):
        """`disconnect()` drops the capture, so the position last applied to it
        is meaningless; if it were remembered, the first position after a
        reconnect would match it, be skipped as unchanged, and the source would
        resume from the top of the clip instead of where it was asked for."""
        src = _source(clip, metric=VideoPosition.FRAMES)
        assert _frame_index(src.next(at_position=7)[2]) == 7
        src.disconnect()
        assert _frame_index(src.next(at_position=7)[2]) == 7

    def test_the_same_position_is_re_applied_after_the_clip_reopens(self, clip):
        """Same reasoning across the end-of-stream rotation, which reopens the
        capture without going through `disconnect()`: a caller whose clock has
        not moved since the clip ran out must still land where it asked, not at
        frame 0."""
        src = _source(clip, metric=VideoPosition.FRAMES)
        assert _frame_index(src.next(at_position=9)[2]) == 9
        more = True
        while more:                       # 10, 11, then the clip runs out
            more, _pos, _frame = src.next(at_position=9)
        assert src.vid_cap is None, 'the source did not rotate'
        assert _frame_index(src.next(at_position=9)[2]) == 9
