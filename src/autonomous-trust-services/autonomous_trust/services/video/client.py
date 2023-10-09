import struct
from queue import Empty, Full

import cv2
import imutils

from autonomous_trust.core import Process, ProcMeta, CfgIds
from autonomous_trust.core.network import Message
from .serialize import deserialize
from .server import VideoSource, VideoProtocol


class VideoRcvr(Process, metaclass=ProcMeta,
                proc_name='video-sink', description='Video image stream consumer'):
    header_fmt = VideoSource.header_fmt

    def __init__(self, configurations, subsystems, log_queue, dependencies, **kwargs):
        super().__init__(configurations, subsystems, log_queue, dependencies=dependencies)
        self.cohort = kwargs['cohort']
        self.size = kwargs.get('size', 640)
        self.encode = kwargs.get('encode', False)
        self.fast_encoding = kwargs.get('fast_encoding', False)
        self.servicers = []
        self.hdr_size = struct.calcsize(self.header_fmt)
        self.protocol = VideoProtocol(self.name, self.logger, configurations[CfgIds.peers])
        self.protocol.register_handler(VideoProtocol.video, self.handle_video)

    def handle_video(self, _, message):
        if message.function == VideoProtocol.video:
            try:
                uuid = message.from_whom.uuid
                hdr = message.obj[:self.hdr_size]
                data = message.obj[self.hdr_size:]
                (_, fast_encoding, idx) = struct.unpack(self.header_fmt, hdr)
                frame = deserialize(data, fast_encoding)
                if frame is not None:
                    if self.size is not None:
                        frame = imutils.resize(frame, width=self.size)
                    if self.encode:
                        _, frame = cv2.imencode('.jpg', frame)
                if uuid in self.cohort.peers:
                    self.cohort.peers[uuid].video_stream.put((idx, frame, 1), block=True, timeout=self.q_cadence)
            except (Full, Empty):
                pass

    def process(self, queues, signal):
        while self.keep_running(signal):
            for peer in self.protocol.peer_capabilities[VideoSource.capability_name]:
                if peer not in self.servicers:
                    self.servicers.append(peer)
                    msg_obj = self.fast_encoding, self.name
                    msg = Message(VideoSource.name, VideoProtocol.request, msg_obj, peer)
                    queues[CfgIds.network].put(msg, block=True, timeout=self.q_cadence)

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
