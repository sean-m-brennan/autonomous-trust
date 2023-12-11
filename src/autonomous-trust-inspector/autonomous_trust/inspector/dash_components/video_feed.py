from queue import Empty

from flask import Flask, Response
from dash import Dash, html

from .core import DashComponent
from ..peer.daq import PeerDataAcq


class VideoFeed(DashComponent):
    def __init__(self, app: Dash, server: Flask, peer: PeerDataAcq, number: int):
        super().__init__(app, server)
        self.server = server
        self.number = str(number)
        self.peer = peer
        self.halt = False

        # note: cannot be called once the server is running
        self.server.add_url_rule('/video_feed_%s' % self.number, 'video_feed_%s' % self.number,
                                 lambda: Response(self.rcv(), mimetype='multipart/x-mixed-replace; boundary=frame'))

    def rcv(self):
        while not self.halt:
            try:
                idx, frame, cadence = self.peer.video_stream.get()  # speed is determined by source speed
                frame = frame.tobytes()
            except Empty:
                continue
            if frame:
                yield (b'--frame\r\n'
                       b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n\r\n')

    def div(self, title: str, style: dict = None) -> html.Div:
        if style is None:
            style = {'float': 'left', 'padding': 10}
        return html.Div([html.H1(title),
                         html.Img(src='/video_feed_%s' % self.number, id='feed_%s' % self.number)],
                        style=style)
