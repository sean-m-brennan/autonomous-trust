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
import struct
from unittest.mock import MagicMock

import pytest

try:
    import cv2
    import imutils
    from autonomous_trust.services.video.server import (
        VideoProtocol, VideoPosition, VideoSource, VideoProcess,
    )
    from autonomous_trust.services.video.client import VideoRecv, VideoRcvr
    _HAS_VIDEO = True
except ImportError as _e:
    _HAS_VIDEO = False

pytestmark = pytest.mark.skipif(not _HAS_VIDEO, reason="cv2/imutils not installed")


# --- VideoProtocol ---

class TestVideoProtocol:
    def test_inherits_data_protocol(self):
        assert VideoProtocol.request == 'request'
        assert VideoProtocol.data == 'data'
        assert VideoProtocol.video == 'video'


# --- VideoPosition ---

class TestVideoPosition:
    def test_frames(self):
        assert VideoPosition.FRAMES == 'frames'

    def test_seconds(self):
        assert VideoPosition.SECONDS == 'seconds'


# --- VideoRecv ---

class TestVideoRecv:
    def test_creation_defaults(self):
        vr = VideoRecv()
        assert vr.size == 640
        assert vr.raw is False
        assert vr.fast_encoding is False

    def test_creation_custom(self):
        vr = VideoRecv(size=320, raw=True, fast_encoding=True)
        assert vr.size == 320
        assert vr.raw is True
        assert vr.fast_encoding is True

    def test_initialize(self):
        vr = VideoRecv.initialize(size=480, raw=True, fast_encoding=False)
        assert isinstance(vr, VideoRecv)
        assert vr.size == 480
        assert vr.raw is True


# --- VideoProcess ---

class TestVideoProcess:
    def test_header_fmt(self):
        size = struct.calcsize(VideoProcess.header_fmt)
        assert size > 0

    def test_handle_requests_adds_client(self):
        proc = MagicMock(spec=VideoProcess)
        proc.active = True
        proc.clients = {}
        proc.client_props = {}
        proc.handle_requests = VideoProcess.handle_requests.__get__(proc)
        message = MagicMock()
        message.function = VideoProtocol.request
        message.obj = (True, 'video-sink')
        message.from_whom.uuid = 'peer-1'
        result = proc.handle_requests(None, message)
        assert result is True
        assert 'peer-1' in proc.clients
        assert proc.client_props['peer-1'] == (True,)

    def test_handle_requests_wrong_function(self):
        proc = MagicMock(spec=VideoProcess)
        proc.active = True
        proc.clients = {}
        proc.client_props = {}
        proc.handle_requests = VideoProcess.handle_requests.__get__(proc)
        message = MagicMock()
        message.function = 'wrong'
        result = proc.handle_requests(None, message)
        assert result is False

    def test_handle_requests_inactive(self):
        proc = MagicMock(spec=VideoProcess)
        proc.active = False
        proc.clients = {}
        proc.client_props = {}
        proc.handle_requests = VideoProcess.handle_requests.__get__(proc)
        message = MagicMock()
        message.function = VideoProtocol.request
        result = proc.handle_requests(None, message)
        assert result is False


# --- VideoRcvr ---

class TestVideoRcvr:
    def test_header_fmt_matches_process(self):
        assert VideoRcvr.header_fmt == VideoProcess.header_fmt


def _decoded_frame(frame=b'\x00'):
    """Stand in for the codec: what is under test is the roster lookup, not
    msgpack or OpenCV."""
    from unittest.mock import patch
    return patch('autonomous_trust.services.video.client.deserialize',
                 return_value=frame)


class TestVideoProcessFanout:
    """`process()`'s one pass: acquire a frame, encode it once per encoding, and
    send each client the variant it asked for (ISSUES §5 S12).

    Untested until now, and it is where the per-client bookkeeping lives: the
    fast/slow choice is read from `client_props` while the recipient comes from
    `clients`, two dicts keyed alike and populated at different moments, so a
    client can be in one and not the other.
    """

    def _proc(self, clients, client_props, queue):
        from autonomous_trust.core import CfgIds
        proc = MagicMock(spec=VideoProcess)
        proc.active = True
        proc.clients = clients
        proc.client_props = client_props
        proc.q_cadence = 0.01
        proc.cadence = 0
        proc.logger = MagicMock()
        proc.header_fmt = VideoProcess.header_fmt
        # One pass, then stop: the real loop runs until signalled.
        proc.keep_running = MagicMock(side_effect=[True, False])
        proc.process_messages = MagicMock()
        proc.sleep_until = MagicMock()
        frame = __import__('numpy').zeros((4, 4, 3), dtype='uint8')
        proc.acquire = MagicMock(return_value=(frame, 7))
        proc.process = VideoProcess.process.__get__(proc)
        return proc, {CfgIds.network: queue}

    def test_each_client_gets_the_encoding_it_asked_for(self):
        from autonomous_trust.core import CfgIds
        queue = MagicMock()
        peer_fast, peer_slow = MagicMock(), MagicMock()
        proc, queues = self._proc(
            {'fast-id': ('sink-a', peer_fast), 'slow-id': ('sink-b', peer_slow)},
            {'fast-id': (True,), 'slow-id': (False,)},
            queue)
        proc.process(queues, MagicMock())

        sent = [call.args[0] for call in queue.put.call_args_list]
        assert len(sent) == 2
        by_peer = {msg.to_whom: msg for msg in sent}
        hdr = struct.calcsize(VideoProcess.header_fmt)
        fast_len, fast_flag, fast_idx = struct.unpack(
            VideoProcess.header_fmt, by_peer[peer_fast].obj[:hdr])
        slow_len, slow_flag, slow_idx = struct.unpack(
            VideoProcess.header_fmt, by_peer[peer_slow].obj[:hdr])
        assert fast_flag is True and slow_flag is False
        # The index is the frame number, so a receiver can tell a repeat from a
        # new frame; both clients are shown the same one.
        assert fast_idx == slow_idx == 7
        # ...and the header's length field must describe the body that follows,
        # since that is what the receiver slices on.
        assert len(by_peer[peer_fast].obj) - hdr == fast_len
        assert len(by_peer[peer_slow].obj) - hdr == slow_len

    def test_a_full_queue_drops_the_frame_rather_than_raising(self):
        """Video is lossy by nature and the network queue is shared: a dropped
        frame is a hiccup, while an exception out of `process()` takes the whole
        service down and stops every client, not just the slow one."""
        from queue import Full
        queue = MagicMock()
        queue.put.side_effect = Full()
        proc, queues = self._proc({'c': ('sink', MagicMock())}, {'c': (True,)},
                                  queue)
        proc.process(queues, MagicMock())      # must not raise
        assert proc.logger.debug.called

    def test_an_inactive_source_sends_nothing(self):
        queue = MagicMock()
        proc, queues = self._proc({'c': ('sink', MagicMock())}, {'c': (True,)},
                                  queue)
        proc.active = False
        proc.process(queues, MagicMock())
        assert not queue.put.called
        assert not proc.acquire.called

    def test_a_dropped_frame_is_not_sent(self):
        """`acquire` returns None whenever `speed` decimation suppresses a
        position -- every other call at speed 2 -- so this is the common case,
        not an error path."""
        queue = MagicMock()
        proc, queues = self._proc({'c': ('sink', MagicMock())}, {'c': (True,)},
                                  queue)
        proc.acquire = MagicMock(return_value=(None, 3))
        proc.process(queues, MagicMock())
        assert not queue.put.called


class TestVideoRcvrCohortSync:
    """The receiver's roster does not cross the process boundary on its own: one
    Cohort is pickled into each worker, so `cohort.peers` is a separate dict per
    process. Its copy stayed empty and every frame was dropped in silence.
    """

    def _rcvr(self, peers):
        rcvr = MagicMock(spec=VideoRcvr)
        rcvr.q_cadence = 0.01
        rcvr.name = 'video-sink'
        rcvr._unknown_peer_drops = 0
        rcvr.logger = MagicMock()
        rcvr.cfg = MagicMock(size=None, raw=True)   # skips resize + imencode
        # spec=VideoRcvr hands back a Mock for class attributes, and
        # handle_video unpacks with self.header_fmt.
        rcvr.header_fmt = VideoProcess.header_fmt
        rcvr.hdr_size = struct.calcsize(VideoProcess.header_fmt)
        rcvr.cohort = MagicMock()
        rcvr.cohort.peers = peers
        rcvr.handle_video = VideoRcvr.handle_video.__get__(rcvr)
        return rcvr

    def _frame_msg(self, uuid):
        msg = MagicMock()
        msg.function = VideoProtocol.video
        msg.from_whom.uuid = uuid
        msg.obj = struct.pack(VideoProcess.header_fmt, 0, False, 7) + b'body'
        return msg

    def test_an_unknown_peer_is_reported_not_dropped_silently(self):
        rcvr = self._rcvr({})
        with _decoded_frame():
            rcvr.handle_video(None, self._frame_msg('unknown'))
        assert rcvr._unknown_peer_drops == 1
        assert rcvr.logger.warning.called

    def test_the_warning_is_rate_limited(self):
        """A stream is 30 frames a second; one line per frame would be its own
        outage."""
        rcvr = self._rcvr({})
        with _decoded_frame():
            for _ in range(150):
                rcvr.handle_video(None, self._frame_msg('unknown'))
        assert rcvr._unknown_peer_drops == 150
        assert rcvr.logger.warning.call_count == 2      # at 1 and 101

    def test_a_known_peer_still_gets_its_frame(self):
        peer = MagicMock()
        rcvr = self._rcvr({'uuid-1': peer})
        with _decoded_frame():
            rcvr.handle_video(None, self._frame_msg('uuid-1'))
        assert peer.video_stream.put.called
        assert rcvr._unknown_peer_drops == 0

