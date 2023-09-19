import threading
import time
from queue import Queue, Empty

from flask import Flask, Response
import dash
from dash import Dash, html

from ..dash_components.util import DashComponent
from .client import VideoRcvr
from .server import VideoSource


class VideoFeed(DashComponent):
    queues = []

    def __init__(self, app: Dash, server: Flask, number: int = None, video_size=320):
        super().__init__(app, server)
        self.server = server
        self.number = ''
        self.index = 0
        if number is not None:
            self.number = str(number)
            self.index = number - 1
        self.queues.append(Queue())
        self.client = VideoRcvr(size=video_size, callback=self.frame_to_queue(self.index))
        self._halt = False

        if len(self.queues) == 1:
            @self.server.route('/video_feed<int:num>')
            def video_feed(num: int):
                return Response(self.rcv(int(num) - 1), mimetype='multipart/x-mixed-replace; boundary=frame')

    def __del__(self):
        self.queues.remove(self.queues[self.index])

    @property
    def halt(self):
        return self._halt

    @halt.setter
    def halt(self, h: bool):
        self._halt = h
        self.client.halt = h

    @classmethod
    def frame_to_queue(cls, idx):
        def cb(_, frame, pause):
            if frame is not None:
                cls.queues[idx].put(frame, block=True)
            if pause is not None:
                time.sleep(pause / 100.)

        return cb

    def rcv(self, idx):
        while not self._halt:
            try:
                frame = self.queues[idx].get(block=True).tobytes()
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

    def run(self, server: str, port: int, **kwargs):
        self.client.run(server, port, **kwargs)


if __name__ == '__main__':  # For interactive testing
    num_clients = 4
    with_servers = True

    webserver = Flask(__name__)
    webapp = dash.Dash(__name__, server=webserver,
                       prevent_initial_callbacks=True, update_title=None)
    feeds = []
    for i in range(num_clients):
        feeds.append(VideoFeed(webapp, webserver, i + 1))
    drone_divs = []
    for feed in feeds:
        drone_divs.append(feed.div("Drone %s" % feed.number))
    webapp.layout = html.Div(drone_divs)

    threads = []
    v_servers = []
    if with_servers:
        vid_map = {0: 15, 1: 17, 2: 18, 3: 20, 4: 21}
        for i in range(num_clients):
            srv = VideoSource()
            thread = threading.Thread(target=srv.run, args=('data/220505_02_MTB_4k_0%d.mp4' % vid_map[i],),
                                      kwargs=dict(port=9990 + i, size=320, speed=1, fast_encoding=True))
            v_servers.append(srv)
            threads.append(thread)

    for idx, feed in enumerate(feeds):
        threads.append(threading.Thread(target=feed.run, args=('localhost', 9990 + idx), kwargs={'encode': True}))
    for t in threads:
        t.start()
    webapp.run()
    for srv in v_servers:
        srv.halt = True
    for feed in feeds:
        feed.halt = True
    for t in threads:
        t.join()
