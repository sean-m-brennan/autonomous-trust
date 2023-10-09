import glob
import os.path
import struct
from queue import Full, Empty

import cv2
import imutils
import numpy as np

from autonomous_trust.core import Process, ProcMeta, Configuration, CfgIds
from autonomous_trust.core.protocol import Protocol
from autonomous_trust.core.network import Message
from autonomous_trust.core.identity import Identity
from .serialize import serialize


class VideoProtocol(Protocol):
    request = 'request'
    video = 'video'


class VideoSource(Process, metaclass=ProcMeta,
                  proc_name='video-source', description='Video image stream service'):
    header_fmt = "!Q?Q"
    capability_name = 'video'

    def __init__(self, configurations, subsystems, log_queue, dependencies, **kwargs):
        super().__init__(configurations, subsystems, log_queue, dependencies=dependencies)
        self.video_path_pattern = kwargs['path']
        self.size = kwargs.get('size', 640)
        self.speed = kwargs.get('speed', 1)
        if not os.path.isabs(self.video_path_pattern):
            vid_dir = os.path.join(Configuration.get_data_dir(), 'video')
            self.video_path_pattern = os.path.join(vid_dir, self.video_path_pattern)
        self.protocol = VideoProtocol(self.name, self.logger, configurations[CfgIds.peers])
        self.protocol.register_handler(VideoProtocol.request, self.handle_requests)
        self.clients: dict[str, tuple[bool, str, Identity]] = {}

    def handle_requests(self, _, message):
        if message.function == VideoProtocol.request:
            fast_encoding, proc_name = message.obj
            uuid = message.from_whom.uuid
            if uuid not in self.clients:
                self.clients[uuid] = fast_encoding, proc_name, message.from_whom
            return True
        return False

    def process_messages(self, queues):
        try:
            message = queues[self.name].get(block=True, timeout=self.q_cadence)
        except Empty:
            message = None
        if message:
            if not self.protocol.run_message_handlers(queues, message):
                    if isinstance(message, Message):
                        self.logger.error('Unhandled message %s' % message.function)
                    else:
                        self.logger.error('Unhandled message of type %s' % message.__class__.__name__)  # noqa

    def process(self, queues, signal):
        for path in sorted(glob.glob(self.video_path_pattern)):
            vid = None
            while self.keep_running(signal):
                vid = cv2.VideoCapture(path)
                more = True
                idx = 0
                while more and self.keep_running(signal):  # more is always True for device (not file)
                    self.process_messages(queues)

                    more, frame = vid.read()
                    idx += 1
                    if frame is None:
                        more = False
                        continue
                    if idx % self.speed > 0:
                        continue

                    frame = self.process_frame(frame)

                    if self.size is not None:
                        frame = imutils.resize(frame, width=self.size)

                    if frame is not None:
                        quick_info = serialize(frame, True)
                        slow_info = serialize(frame, False)
                        quick_header = struct.pack(self.header_fmt, len(quick_info), True, idx)
                        slow_header = struct.pack(self.header_fmt, len(slow_info), False, idx)
                        for client_id in self.clients:
                            fast_encoding, proc_name, peer = self.clients[client_id]
                            if fast_encoding:
                                msg_obj = quick_header + quick_info
                            else:
                                msg_obj = slow_header + slow_info
                            msg = Message(proc_name, VideoProtocol.video, msg_obj, peer)
                            try:
                                queues[CfgIds.network].put(msg, block=True, timeout=self.q_cadence)
                            except Full:
                                pass  # skip this frame

                    # FIXME speed of output
                    #self.sleep_until(self.cadence)
            if vid is not None:
                vid.release()

    def process_frame(self, frame: np.ndarray) -> np.ndarray:
        """Implements frame processing before resizing and shipping. Default: pass-through"""
        return frame
