import base64
import threading
import time
from queue import Empty

from flask import Flask, Response

from .core import DashComponent, DashControl, html
from ..peer.daq import PeerDataAcq


class VideoFeed(DashComponent):
    def __init__(self, ctl: DashControl, server: Flask, peer: PeerDataAcq, number: int):
        super().__init__(ctl.app)
        self.ctl = ctl
        self.server = server
        self.number = str(number)
        self.peer = peer
        self.halt = False
        self.img_id = 'feed_%s' % self.number
        threading.Thread(target=self.rcv).start()

        # FIXME must be able to dynamically add this?
        # note: cannot be called once the server is running
        #self.server.add_url_rule('/video_feed_%s' % self.number, 'video_feed_%s' % self.number,
        #                         lambda: Response(self.rcv(), mimetype='multipart/x-mixed-replace; boundary=frame'))

    def rcv(self):
        while not self.halt:
            if self.peer.cohort.paused:
                time.sleep(0.02)
                continue
            try:
                while not self.halt and len(self.peer.video_stream) < 1:
                    time.sleep(0.02)  # max 50 fps
                idx, frame, cadence = self.peer.video_stream.pop()
                frame = frame.tobytes()
            except (Empty, IndexError):
                continue
            if frame:
                print('xmit frame')
                frame = b'--frame\r\nContent-Type: image/jpeg\r\n\r\n' + frame + b'\r\n\r\n'
                self.ctl.emit('video', dict(id=self.img_id, data=frame), binary=True)
            #    yield (b'--frame\r\n'
            #           b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n\r\n')

    def div(self, title: str, style: dict = None) -> html.Div:
        if style is None:
            style = {'float': 'left', 'padding': 10}
        return html.Div([html.H1(title), html.Img(id=self.img_id)], style=style)
