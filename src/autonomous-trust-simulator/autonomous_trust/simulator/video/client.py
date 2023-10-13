import struct
from queue import Full, Empty

import cv2
import imutils

from autonomous_trust.core import ProcMeta
from autonomous_trust.services.video.serialize import deserialize
from autonomous_trust.services.video import VideoRcvr
from autonomous_trust.services.video.server import VideoProtocol

from .noise import Noise, add_noise


class VideoSimRcvr(VideoRcvr, metaclass=ProcMeta,
                   proc_name='video-sink', description='Video image stream consumer'):
    def __init__(self, configurations, subsystems, log_queue, dependencies, **kwargs):
        super().__init__(configurations, subsystems, log_queue, dependencies=dependencies, **kwargs)
        self.noisy = kwargs.get('noisy', False)
        self.image_shape = (int(self.cfg.size * 0.5625), self.cfg.size, 3)

    def handle_video(self, _, message):
        if message.function == VideoProtocol.video:
            try:
                uuid = message.from_whom.uuid
                hdr = message.obj[:self.hdr_size]
                data = message.obj[self.hdr_size:]
                (_, fast_encoding, idx) = struct.unpack(self.header_fmt, hdr)
                frame = deserialize(data, fast_encoding)
                if frame is not None:
                    self.image_shape = frame.shape
                    if self.cfg.size is not None:
                        frame = imutils.resize(frame, width=self.cfg.size)
                    if self.noisy:
                        frame = add_noise(Noise.GAUSSIAN, frame)
                    if not self.cfg.raw:
                        _, frame = cv2.imencode('.jpg', frame)
                    msg = idx, frame, 1
                else:
                    msg = idx, add_noise(Noise.GAUSSIAN, None, self.image_shape), 100
                if uuid in self.cohort.peers:
                    self.cohort.peers[uuid].video_stream.put(msg, block=True, timeout=self.q_cadence)
            except (Full, Empty):
                pass
