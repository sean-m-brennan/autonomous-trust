import glob
import random
import time
from collections import deque
from datetime import timedelta, datetime
from queue import Queue

import cv2
import imutils
import numpy as np

from autonomous_trust.services.network_statistics import NetworkSource

"""
Mock sources, strictly for interactive testing of the UI.
This file is for the 'false-sim', i.e. autonomous_trust.simulator.dash_components.__main__
"""


class SimVideoSource(object):
    fps = 20

    def __init__(self, path: str, size: int = 320, speed: int = 1):
        self.video_path_pattern = path
        self.size = size
        self.speed = speed
        self.buffer = deque(maxlen=1)
        self.halt = False

    def run(self, extra_process: [[np.ndarray], np.ndarray] = None):
        if extra_process is None:
            extra_process = lambda x: x
        for path in sorted(glob.glob(self.video_path_pattern)):
            vid = None
            while not self.halt:
                vid = cv2.VideoCapture(path)
                frame_count = int(vid.get(cv2.CAP_PROP_FPS) / self.fps)
                if frame_count < 1:
                    frame_count = 1
                more = True
                idx = 0
                while more and not self.halt:
                    frame = None
                    for _ in range(frame_count):
                        more, frame = vid.read()
                        if not more:
                            break
                    idx += 1
                    if frame is None:
                        more = False
                        continue
                    if idx % self.speed > 0:
                        continue

                    frame = extra_process(frame)

                    if self.size is not None:
                        frame = imutils.resize(frame, width=self.size)

                    _, frame = cv2.imencode('.jpg', frame)

                    if frame is not None:
                        self.buffer.append((idx, frame, 1))
                    time.sleep(1. / self.fps)  # FIXME

            if vid is not None:
                print('no more video')
                vid.release()


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


class SimNetSource(NetworkSource):  # FIXME unused
    def __init__(self):
        self.prev = {}
        self.last_time = {}

    def acquire(self, uuid: str) -> tuple[float, float, int, int, int, int]:
        if uuid not in self.prev:
            self.prev[uuid] = (0., 0., 0, 0, 0, 0)
            self.last_time[uuid] = datetime.now() - timedelta(seconds=1)
        up, down, sent, recv, out, in_ = self.prev[uuid]
        now = datetime.now()
        elapsed = (now - self.last_time[uuid]).total_seconds()
        current = sent + random.randint(0, 500), recv + random.randint(0, 500), \
            out + random.randint(0, 2), in_ + random.randint(0, 2)
        up, down = (current[0] - self.prev[uuid][2]) / elapsed, (current[1] - self.prev[uuid][3]) / elapsed
        self.prev[uuid] = up, down, *current
        return self.prev[uuid]
