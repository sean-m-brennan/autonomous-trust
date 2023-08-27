import glob
import os.path
import struct

import cv2
import imutils

from .. import net_util as net
from .serial import serialize


class VideoSource(net.Server):
    header_fmt = "!Q?"

    def process(self, **kwargs):
        video_path_pattern = kwargs['video_path_pattern']  # required
        size = kwargs.get('size', 640)
        loops = kwargs.get('loops', 1)
        speed = kwargs.get('speed', 1)
        fast_encoding = kwargs.get('fast_encoding', False)

        for path in sorted(glob.glob(video_path_pattern)):
            loop = 0
            while loop < loops:
                vid = cv2.VideoCapture(path)
                more = True
                idx = 0
                while more:
                    more, frame = vid.read()
                    idx += 1
                    if frame is None:
                        more = False
                        continue
                    if idx % speed > 0:
                        continue

                    frame = imutils.resize(frame, width=size)

                    if len(self.clients) > 0 and frame is not None:
                        for client_socket in self.clients:
                            info = serialize(frame, fast_encoding)
                            message = self.prepend_header(self.header_fmt, info, fast_encoding)
                            try:
                                client_socket.sendall(message)
                            except (ConnectionResetError, BrokenPipeError):
                                self.clients.remove(client_socket)
                loop += 1

    def run(self, video_path_pattern: str, size=640, loops=2, speed=1, port=9999, fast_encoding=False):
        if not os.path.isabs(video_path_pattern):
            video_path_pattern = os.path.join(os.path.dirname(__file__), video_path_pattern)

        super().run(port=port, video_path_pattern=video_path_pattern,
                    size=size, loops=loops, speed=speed, fast_encoding=fast_encoding)


if __name__ == '__main__':
    VideoSource().run('data/220505_02_MTB_4k_0*.mp4', size=800, speed=2, fast_encoding=True)
