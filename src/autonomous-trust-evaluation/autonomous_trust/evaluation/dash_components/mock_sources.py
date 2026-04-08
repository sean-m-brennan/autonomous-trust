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

import logging
import random
import time
from collections import deque

_logger = logging.getLogger(__name__)
from datetime import datetime
from typing import Optional

import cv2
import numpy as np

from autonomous_trust.inspector.peer.daq import PeerDataAcq
from autonomous_trust.services.data.server import DataConfig
from autonomous_trust.services.video.server import VideoSource

"""
Mock sources, strictly for interactive testing of the UI.
This file is for the 'false-sim', i.e. autonomous_trust.simulator.dash_components.__main__
"""


class SimVideoSource(VideoSource):
    def __init__(self, path: str, size: int = 320, speed: int = 1, fps: int = 20):
        cfg = DataConfig(path, size, speed, 1)
        super().__init__(cfg, fps)
        self.buffer = deque(maxlen=1)
        self.halt = False
        self.peer: Optional[PeerDataAcq] = None
        self.start: datetime = None

    def connect(self, peer: PeerDataAcq):
        self.peer = peer
        self.start = self.peer.time

    def run(self, extra_process: [[np.ndarray], np.ndarray] = None):
        if extra_process is None:
            extra_process = lambda x: x
        prev = 0
        while not self.halt:
            frame_start = time.time()
            if self.peer is not None:
                elapsed = int((self.peer.time - self.start).total_seconds())
                if self.peer.active and not self.peer.cohort.paused and prev < elapsed:
                    _logger.debug('Elapsed %d', elapsed)
                    more, frame_num, frame = self.next(at_position=elapsed, post_proc=extra_process)
                    prev = elapsed
                    if frame is not None:
                        _, frame = cv2.imencode('.jpg', frame)
                        self.buffer.append((frame_num, frame, 1))
            elapsed = time.time() - frame_start
            remaining = max(0, (1.0 / self.fps) - elapsed)
            time.sleep(remaining)


class SimDataSource(object):
    cadence = .5

    def __init__(self):
        self.buffer = deque(maxlen=1)
        self.halt = False

    def run(self):
        while not self.halt:
            data = random.random()
            self.buffer.append(data)
            time.sleep(self.cadence)
