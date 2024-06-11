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

import struct
from queue import Empty, Full

import cv2
import imutils

from autonomous_trust.core import Process, ProcMeta, CfgIds, InitializableConfig
from autonomous_trust.core.network import Message
from autonomous_trust.services.data.serialize import deserialize
from .server import VideoProcess, VideoProtocol


class VideoRecv(InitializableConfig):
    def __init__(self, size=640, raw=False, fast_encoding=False):
        self.size = size
        self.raw = raw
        self.fast_encoding = fast_encoding

    @classmethod
    def initialize(cls, size: int = 640, raw: bool = False, fast_encoding: bool = False):
        return cls(size, raw, fast_encoding)


class VideoRcvr(Process, metaclass=ProcMeta,
                proc_name='video-sink', description='Video image stream consumer'):
    header_fmt = VideoProcess.header_fmt

    def __init__(self, configurations, subsystems, log_queue, dependencies, **kwargs):
        super().__init__(configurations, subsystems, log_queue, dependencies=dependencies)
        self.cohort = kwargs['cohort']
        self.cfg = configurations[self.name]
        self.servicers = []
        self.hdr_size = struct.calcsize(self.header_fmt)
        self.protocol = VideoProtocol(self.name, self.logger, configurations)
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
                    if self.cfg.size is not None:
                        frame = imutils.resize(frame, width=self.cfg.size)
                    if not self.cfg.raw:
                        _, frame = cv2.imencode('.jpg', frame)
                if uuid in self.cohort.peers:
                    self.cohort.peers[uuid].video_stream.put((idx, frame, 1), block=True, timeout=self.q_cadence)
            except (Full, Empty):
                pass

    def process(self, queues, signal):
        while self.keep_running(signal):
            if VideoProcess.capability_name in self.protocol.peer_capabilities:
                for peer in self.protocol.peer_capabilities[VideoProcess.capability_name]:
                    if peer not in self.servicers:
                        self.servicers.append(peer)
                        msg_obj = self.cfg.fast_encoding, self.name
                        msg = Message(VideoProcess.name, VideoProtocol.request, msg_obj, peer)
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
