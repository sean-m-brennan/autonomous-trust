from typing import Optional

import imutils
import numpy as np

from ..radio import networking as net  # FIXME
from .noise import Noise, add_noise
from autonomous_trust.services.video.serialize import deserialize
from autonomous_trust.services.video import VideoRcvr


class VideoSimRcvr(VideoRcvr):
    def get_frame(self, noisy: bool = True, size: Optional[int] = None) -> tuple[np.ndarray, int]:
        noise = add_noise(Noise.GAUSSIAN, None, self.image_shape), 100

        if self.connected:
            try:
                (_, fast_encoding), data = self.recv_all()
            except (net.ReceiveFormatError, OSError, AttributeError):
                return noise

            frame = deserialize(data, fast_encoding)
            if size is not None:
                frame = imutils.resize(frame, width=size)
            if noisy:
                frame = add_noise(Noise.GAUSSIAN, frame)
            return frame, 1
        return noise


if __name__ == '__main__':
    VideoSimRcvr(size=800).run(server='localhost', port=9999, name='localhost')
