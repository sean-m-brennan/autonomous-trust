# ******************
#  Copyright 2023 TekFive, Inc., Sean M. Brennan, and contributors
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
import logging
import os
import os.path
import socket
import urllib.request

import numpy as np
import cv2

# mediapipe is an optional heavy dependency (on-node EfficientDet detection).
# Import it lazily so the module can be imported/exported even where mediapipe
# is not installed; instantiation fails with a clear message instead.
try:
    from mediapipe.tasks import python as mp_python
    from mediapipe.tasks.python import vision as mp_vision
    _HAS_MEDIAPIPE = True
except ImportError:
    mp_python = None
    mp_vision = None
    _HAS_MEDIAPIPE = False

from .server import VideoProcess


class VideoProcessor(VideoProcess):
    model_filename = 'efficientdet_lite0.tflite'
    model_url = 'https://storage.googleapis.com/mediapipe-models/object_detector/efficientdet_lite0/float32/latest/efficientdet_lite0.tflite'
    # S8: SHA-256 the downloaded model is pinned against. The `model_url`
    # points at the "/latest/" alias, which is mutable; if the upstream
    # asset is ever updated (or substituted by a compromised host / MITM on
    # the HTTPS transport) the hash check below fails closed and the detector
    # refuses to instantiate rather than loading an unverified model. To
    # adopt a new upstream model, download it, recompute the SHA-256, and
    # update this constant deliberately.
    model_sha256 = '40338edf5ec70d43e318b0a716a84d4564cd1802759a7a07170c7e43796dbf58'
    TEXT_COLOR = (255, 0, 0)  # red

    @classmethod
    def _model_digest(cls, path) -> str:
        """Return the hex SHA-256 of the file at *path*."""
        h = hashlib.sha256()
        with open(path, 'rb') as fd:
            for chunk in iter(lambda: fd.read(1 << 20), b''):
                h.update(chunk)
        return h.hexdigest()

    def __init__(self, *args):
        super().__init__(*args)
        self.size = 320  # override
        self.count = 0
        log = logging.getLogger(__name__)
        if not _HAS_MEDIAPIPE:
            raise RuntimeError(
                'VideoProcessor requires the optional "mediapipe" dependency '
                '(pip install mediapipe>=0.10.5) for on-node object detection.')
        model_path = os.path.join(os.path.dirname(__file__), self.model_filename)

        # Treat an on-disk copy that fails the pin as untrusted (partial
        # download, corruption, or tampering) and re-fetch it.
        if os.path.exists(model_path):
            if self._model_digest(model_path) != self.model_sha256:
                log.warning('Cached model %s failed checksum; re-downloading',
                            model_path)
                os.remove(model_path)

        if not os.path.exists(model_path):
            # noqa: S310 silences Bandit's audit warning about the download;
            # integrity is enforced by the checksum verification below.
            try:
                old_timeout = socket.getdefaulttimeout()
                socket.setdefaulttimeout(30)
                try:
                    urllib.request.urlretrieve(self.model_url, model_path)  # noqa: S310
                finally:
                    socket.setdefaulttimeout(old_timeout)
            except Exception as e:
                log.warning('Failed to download model %s: %s', self.model_url, e)

        # Fail closed: never hand an unverified model to the detector.
        if not os.path.exists(model_path):
            raise RuntimeError(
                'Object-detection model %s unavailable (download failed)'
                % self.model_filename)
        actual = self._model_digest(model_path)
        if actual != self.model_sha256:
            os.remove(model_path)
            raise RuntimeError(
                'Object-detection model %s failed SHA-256 verification '
                '(expected %s, got %s); refusing to load.'
                % (self.model_filename, self.model_sha256, actual))

        options = mp_vision.ObjectDetectorOptions(
            base_options=mp_python.BaseOptions(model_asset_path=model_path),
            score_threshold=0.5)
        self.detector = mp_vision.ObjectDetector.create_from_options(options)

    def visualize(self, image, detection_result) -> np.ndarray:
        for detection in detection_result.detections:
            # Draw bounding_box
            bbox = detection.bounding_box
            start_point = bbox.origin_x, bbox.origin_y
            end_point = bbox.origin_x + bbox.width, bbox.origin_y + bbox.height
            cv2.rectangle(image, start_point, end_point, self.TEXT_COLOR, 3)
        return image

    def process_frame(self, frame):
        self.count += 1
        if self.count % self.cadence == 0:
            # Detection takes ~0.5s; cadence-based frame skipping limits how
            # often we run it so that only every Nth frame is processed.
            detection_result = self.detector.detect(frame)
            frame = self.visualize(frame, detection_result)
        return frame
