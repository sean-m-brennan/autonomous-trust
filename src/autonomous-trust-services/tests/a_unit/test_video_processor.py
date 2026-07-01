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

import hashlib

import pytest

try:
    # The mediapipe import is guarded inside processor.py, so this only needs
    # cv2 present; the checksum tests below don't touch mediapipe.
    from autonomous_trust.services.video.processor import VideoProcessor
    _HAS_PROC = True
except ImportError:
    _HAS_PROC = False

pytestmark = pytest.mark.skipif(not _HAS_PROC, reason="cv2 not installed")


class TestModelChecksum:
    """S8: the object-detection model must be integrity-checked."""

    def test_pin_is_valid_sha256(self):
        pin = VideoProcessor.model_sha256
        assert isinstance(pin, str) and len(pin) == 64
        int(pin, 16)  # hex-decodable

    def test_model_digest_matches_hashlib(self, tmp_path):
        blob = b'the quick brown fox' * 1000
        f = tmp_path / 'blob.bin'
        f.write_bytes(blob)
        expected = hashlib.sha256(blob).hexdigest()
        assert VideoProcessor._model_digest(str(f)) == expected

    def test_model_digest_streams_large_file(self, tmp_path):
        # Larger than the 1 MiB read chunk to exercise the streaming loop.
        blob = b'\x00\x01\x02\x03' * (1 << 19)  # 2 MiB
        f = tmp_path / 'big.bin'
        f.write_bytes(blob)
        assert VideoProcessor._model_digest(str(f)) == hashlib.sha256(blob).hexdigest()
