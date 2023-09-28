from queue import Empty

from flask import Flask, Response
from dash import Dash, html

from .util import DashComponent
from ..peer.daq import PeerDataAcq


class VideoFeed(DashComponent):
    def __init__(self, app: Dash, server: Flask, peer: PeerDataAcq, number: int):
        super().__init__(app, server)
        self.server = server
        self.number = str(number)
        self.peer = peer
        self._halt = False

        @self.server.route('/video_feed%s' % self.number)
        def video_feed():
            return Response(self.rcv(), mimetype='multipart/x-mixed-replace; boundary=frame')

    @property
    def halt(self):
        return self._halt

    @halt.setter
    def halt(self, h: bool):
        self._halt = h

    def rcv(self):
        while not self._halt:
            try:
                frame = self.peer.video_stream.get(block=True).tobytes()
            except Empty:
                continue
            yield (b'--frame\r\n'
                   b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n\r\n')

    def div(self, title: str, style: dict = None) -> html.Div:
        if style is None:
            style = {'float': 'left', 'padding': 10}
        return html.Div([html.H1(title),
                         html.Img(src='/video_feed%s' % self.number, id='feed%s' % self.number)],
                        style=style)
