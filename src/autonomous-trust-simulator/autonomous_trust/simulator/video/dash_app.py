import threading
import time
from queue import Queue, Empty

from flask import Flask, Response
import dash
from dash import html

from .client import VideoRcvr
from .server import VideoSource


class VideoDisplay(object):
    num_clients = 4
    vid_size = 320

    def __init__(self):
        self.server = Flask(__name__)
        self.app = dash.Dash(__name__, server=self.server,
                             prevent_initial_callbacks=True, update_title=None)
        self.queues = []
        self.halt = False
        self.v_clients = []
        for i in range(self.num_clients):
            self.v_clients.append(VideoRcvr(size=self.vid_size, callback=self.frame_to_queue(i)))
            self.queues.append(Queue())

        @self.server.route('/video_feed<num>')
        def video_feed(num):
            return Response(self.rcv(int(num) - 1), mimetype='multipart/x-mixed-replace; boundary=frame')

        drone_divs = []
        for feed in range(1, self.num_clients + 1):
            drone_divs.append(html.Div([html.H1("Drone %d" % feed),
                                        html.Img(src='/video_feed%d' % feed, id='feed%d' % feed)],
                                       style={'float': 'left', 'padding': 10}))
        self.app.layout = html.Div(drone_divs)

    def frame_to_queue(self, idx):
        def cb(_, frame, pause):
            if frame is not None:
                self.queues[idx].put(frame, block=True)
            if pause is not None:
                time.sleep(pause/100.)
        return cb

    def rcv(self, idx):
        while not self.halt:
            try:
                frame = self.queues[idx].get(block=True).tobytes()
            except Empty:
                continue
            yield (b'--frame\r\n'
                   b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n\r\n')

    @staticmethod
    def spawn_server(idx):
        """Normally video servers run separately"""
        vid_map = {0: 15, 1: 17, 2: 18, 3: 20, 4: 21}
        srv = VideoSource()
        thread = threading.Thread(target=srv.run, args=('data/220505_02_MTB_4k_0%d.mp4' % vid_map[idx],),
                                  kwargs=dict(port=9990 + idx, size=320, speed=1, fast_encoding=True))
        return thread, srv

    def run(self, with_servers=False):
        threads = []

        v_servers = []
        if with_servers:
            for i in range(self.num_clients):
                t, s = self.spawn_server(i)
                v_servers.append(s)
                threads.append(t)

        for idx, cl in enumerate(self.v_clients):
            threads.append(threading.Thread(target=cl.run, args=('localhost', 9990 + idx), kwargs={'encode': True}))
        for t in threads:
            t.start()
        self.app.run(debug=False)
        for srv in v_servers:
            srv.halt = True
        self.halt = True
        for cl in self.v_clients:
            cl.halt = True
        for t in threads:
            t.join()


if __name__ == '__main__':
    VideoDisplay().run(True)
