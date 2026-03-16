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
