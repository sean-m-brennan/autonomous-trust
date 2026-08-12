# ******************
#  Copyright 2023 TekFive, Inc., Sean M. Brennan, and contributors
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

import base64
import logging
import threading
from queue import Empty

from flask import Flask, Response

from .core import DashComponent, DashControl, html

_logger = logging.getLogger(__name__)
from ..peer.daq import PeerDataAcq, stream_take_latest


class VideoFeed(DashComponent):
    via_ws = False

    #: How long a wait blocks before looping to re-check `halt`. Not a poll
    #: interval: a frame arriving sooner returns immediately, so this bounds
    #: shutdown latency only, and an idle feed costs 1 wakeup/s instead of 10.
    wait_sec = 1.0

    def __init__(self, ctl: DashControl, peer: PeerDataAcq, number: int):
        super().__init__(ctl.app)
        self.ctl = ctl
        self.number = str(number)
        self.peer = peer
        self.halt = False
        self.img_id = f'feed_{self.number}'
        #: The caption element, addressable so a live value (the peer's position)
        #: can be pushed into it instead of rebuilding the whole detail body.
        self.title_id = f'feed-title-{self.number}'
        if self.via_ws:
            threading.Thread(target=self.xmit).start()
        else:
            # Flask constraint, and the ACCEPTED design (2026-08-12):
            # add_url_rule MUST be called before app.run() — the route table is
            # frozen at server start. That is why VideoFeed registers its route at
            # __init__ time even when the peer's metadata doesn't (yet) declare a
            # video stream. A Blueprint with dynamic registration could work
            # around it, but that was weighed and declined: it is significant
            # wiring to remove a constraint nothing is hitting.
            self.ctl.server.add_url_rule(f'/video_feed_{self.number}', f'video_feed_{self.number}',
                                     lambda: Response(self.rcv(), mimetype='multipart/x-mixed-replace; boundary=frame'))

    def _next_frame(self):
        """The newest frame available, or None if the feed should idle.

        Waits on the stream rather than polling it (I15). The old
        `while len(stream) < 1: sleep(0.1)` had three problems: it spun, it
        capped a 30 fps source at 10 fps and added up to 100 ms of latency per
        frame, and it could not work at all against what production supplies --
        `QueuePool` hands out `manager.Queue` proxies, which have neither
        `__len__` nor `pop`, and neither `TypeError` nor `AttributeError` was
        caught here.
        """
        if self.peer.cohort.paused or not self.peer.active:
            # Waits on the peer's active event, so opening a detail drawer
            # starts the feed at once instead of up to a poll interval later.
            self.peer.wait_active(self.wait_sec)
            return None
        try:
            idx, frame, cadence = stream_take_latest(self.peer.video_stream,
                                                     self.wait_sec)
        except Empty:
            return None
        return frame.tobytes() if hasattr(frame, 'tobytes') else frame

    def xmit(self):
        while not self.halt:
            frame = self._next_frame()
            if frame:
                _logger.debug('xmit frame')
                frame = b'--frame\r\nContent-Type: image/jpeg\r\n\r\n' + frame + b'\r\n\r\n'
                self.ctl.emit('video', dict(id=self.img_id, data=frame), binary=True)

    def rcv(self):
        while not self.halt:
            frame = self._next_frame()
            if frame:
                yield (b'--frame\r\n'
                       b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n\r\n')

    def div(self, title: str, style: dict = None) -> html.Div:
        if style is None:
            style = {'float': 'left', 'padding': 10}
        return html.Div([html.H1(title, id=self.title_id),
                         html.Img(id=self.img_id)], style=style)
