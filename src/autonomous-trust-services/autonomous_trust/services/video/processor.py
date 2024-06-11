# ******************
#  Copyright 2024 TekFive, Inc. and contributors
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

import os.path
import urllib.request

import numpy as np
from mediapipe.tasks import python
from mediapipe.tasks.python import vision
import cv2

from .server import VideoProcess


class VideoProcessor(VideoProcess):
    model_filename = 'efficientdet_lite0.tflite'
    model_url = 'https://storage.googleapis.com/mediapipe-models/object_detector/efficientdet_lite0/float32/latest/efficientdet_lite0.tflite'
    TEXT_COLOR = (255, 0, 0)  # red

    def __init__(self, *args):
        super().__init__(*args)
        self.size = 320  # override
        self.count = 0
        model_path = os.path.join(os.path.dirname(__file__), self.model_filename)
        if not os.path.exists(model_path):
            urllib.request.urlretrieve(self.model_url, model_path)
        options = vision.ObjectDetectorOptions(base_options=python.BaseOptions(model_asset_path=model_path),
                                               score_threshold=0)
        self.detector = vision.ObjectDetector.create_from_options(options)

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
        if self.count % self.cadence:
            # FIXME takes about .5 sec so only do this for some
            detection_result = self.detector.detect(frame)
            frame = self.visualize(frame, detection_result)
        return frame
