import struct
from typing import Optional

import cv2
import numpy as np

from .. import net_util as net
from .noise import Noise, add_noise
from .serial import deserialize


def default_display(ref: str, frame: np.ndarray, cadence: int = 1):
    cv2.imshow('video feed - ' + ref, frame)
    cv2.waitKey(cadence)


class VideoRcvr(net.Client):
    header_fmt = "!Q?"

    def __init__(self, callback: [[str, np.ndarray, Optional[int]], None] = default_display,
                 size: int = 640):
        super().__init__()
        self.display_callback = callback
        self.image_shape = (int(size * 0.5625), size, 3)

    def get_frame(self):
        noise = add_noise(Noise.GAUSSIAN, None, self.image_shape), 100

        if not self.is_socket_closed():
            try:
                (_, fast_encoding), data = self.recv_all(self.header_fmt)
            except (net.ReceiveFormatError, OSError, AttributeError):
                return noise

            frame = deserialize(data, fast_encoding)
            frame = add_noise(Noise.GAUSSIAN, frame)
            return frame, 1
        return noise

    def recv_data(self, **kwargs):
        frame, pause = self.get_frame()
        if frame is not None:
            self.image_shape = frame.shape
            self.display_callback(kwargs['name'], frame, pause)


if __name__ == '__main__':
    VideoRcvr(size=800).run(server='127.0.1.1', port=9999, name='localhost')
