import glob
import os.path
import struct
from enum import Enum
from queue import Full
from typing import Optional, Callable

import cv2
import imutils
import numpy as np

from autonomous_trust.core import ProcMeta, Configuration, CfgIds
from autonomous_trust.core.network import Message
from ..data.serialize import serialize
from ..data.server import DataConfig, DataProcess, DataProtocol

class VideoProtocol(DataProtocol):  # FIXME remove?
    video = 'video'

class VideoPosition(str, Enum):
    FRAMES = 'frames'
    SECONDS = 'seconds'

class VideoSource(object):
    """Re-entry capable video daq"""
    def __init__(self, source: DataConfig, frames_per_second: int = 20, position_metric: VideoPosition = VideoPosition.SECONDS):
        self.size = source.frame_size
        self.speed = source.speed
        self.fps = frames_per_second
        self.position_metric = position_metric
        path = source.device_path
        if not os.path.isabs(path):
            vid_dir = os.path.join(Configuration.get_data_dir(), 'video')
            path = os.path.join(vid_dir, path)
        self.paths = sorted(glob.glob(path))
        self.path_index = 0
        self.frame_position = 0
        self.vid_cap: Optional[cv2.VideoCapture] = None

    def next(self, at_position: int = 0, post_proc: Callable[[np.ndarray], np.ndarray] = lambda x: x) -> tuple[bool, int, Optional[np.ndarray]]:
        if self.vid_cap is None:
            path = self.paths[self.path_index]
            self.vid_cap = cv2.VideoCapture(path)
            self.frame_position = 0
            if at_position > self.frame_position:
                self.frame_position = at_position
                if self.position_metric == VideoPosition.SECONDS:
                    self.vid_cap.set(cv2.CAP_PROP_POS_MSEC, int(at_position * 1000))
                else:
                    self.vid_cap.set(cv2.CAP_PROP_POS_FRAMES, at_position)
        frame_count = int(self.vid_cap.get(cv2.CAP_PROP_FPS) / self.fps)  # skip frames if fps is too small
        if frame_count < 1:
            frame_count = 1
        frame = None
        more = True
        for _ in range(frame_count):
            more, frame = self.vid_cap.read()
            if not more:
                break
        self.frame_position += 1
        if frame is None:
            more = False
        if not more:
            self.path_index += 1
            self.path_index %= len(self.paths)
            self.vid_cap.release()
            self.vid_cap = None
        if frame is None:
            return more, self.frame_position, None
        if self.frame_position % self.speed > 0:  # yield no frames if fps is too large
            return more, self.frame_position, None

        frame = post_proc(frame)
        if self.size is not None:
            frame = imutils.resize(frame, width=self.size)
        return more, self.frame_position, frame

    def disconnect(self):
        self.vid_cap.release()
        self.vid_cap = None
        self.frame_position = 0


class VideoProcess(DataProcess, metaclass=ProcMeta,
                   proc_name='video-source', description='Video image stream service'):
    def __init__(self, configurations, subsystems, log_queue, dependencies):
        super().__init__(configurations, subsystems, log_queue, dependencies=dependencies)
        if self.active:
            self.src = VideoSource(self.cfg)
            self.client_props: dict[str, tuple] = {}

    def process_frame(self, frame: np.ndarray) -> np.ndarray:
        """Implements frame processing before resizing and shipping. Default: pass-through"""
        return frame

    def acquire(self):
        _, frame_num, frame = self.src.next(post_proc=self.process_frame)
        return frame, frame_num

    def handle_requests(self, _, message):
        if message.function == VideoProtocol.request and self.active:
            fast_encoding, proc_name = message.obj
            uuid = message.from_whom.uuid
            if uuid not in self.clients:
                self.clients[uuid] = proc_name, message.from_whom
                self.client_props[uuid] = fast_encoding,
            return True
        return False

    def process(self, queues, signal):
        while self.keep_running(signal):
            self.process_messages(queues)

            if self.active:
                frame, index = self.acquire()
                if frame is not None:
                    quick_info = serialize(frame, True)
                    slow_info = serialize(frame, False)
                    quick_header = struct.pack(self.header_fmt, len(quick_info), True, index)
                    slow_header = struct.pack(self.header_fmt, len(slow_info), False, index)
                    for client_id in self.clients:
                        proc_name, peer = self.clients[client_id]
                        fast_encoding, = self.client_props[client_id]
                        if fast_encoding:
                            msg_obj = quick_header + quick_info
                        else:
                            msg_obj = slow_header + slow_info
                        msg = Message(proc_name, VideoProtocol.video, msg_obj, peer)
                        try:
                            queues[CfgIds.network].put(msg, block=True, timeout=self.q_cadence)
                        except Full:
                            pass  # skip this frame

            self.sleep_until(self.cadence)
