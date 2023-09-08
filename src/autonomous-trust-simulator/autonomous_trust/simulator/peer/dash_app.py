import os
import threading
from datetime import datetime, timedelta

import plotly
from flask import Flask
from dash import Dash, html, dcc, Output, Input, State
import plotly.graph_objects as go
import numpy as np
from uuid import uuid4

from ..radio.iface import Antenna, NetInterface
from .peer import PeerData
from .path import BezierData, PathData, EllipseData, Variability
from .position import GeoPosition, UTMPosition
from ..sim_data import SimState, SimConfig
from ..simulator import Simulator
from ..sim_client import SimClient


def generate_config(filepath: str):
    t5 = GeoPosition(34.669650, -86.575907, 182).convert(UTMPosition)
    uah = GeoPosition(34.725279, -86.639962, 198).convert(UTMPosition)
    mid = t5.midpoint(uah)
    one = UTMPosition(t5.zone, t5.easting, uah.northing, mid.alt)
    two = UTMPosition(t5.zone, uah.easting, t5.northing, mid.alt)
    start = datetime.now()
    end = datetime.now() + timedelta(minutes=30)
    shape1 = BezierData(t5, uah, [one, two])
    path1 = PathData(start, end, shape1, Variability.GAUSSIAN, 4.4, Variability.UNIFORM)
    peer1 = PeerData(str(uuid4()), '192.168.0.2', path1.shape.start, -200.,
                     Antenna.DIPOLE, NetInterface.SMALL, start, end, path1, [])
    shape2 = EllipseData(uah, 1000, 600, -45.)
    path2 = PathData(start, end, shape2, Variability.GAUSSIAN, 4.4, Variability.UNIFORM)
    peer2 = PeerData(str(uuid4()), '192.168.0.1', path2.shape.start, -200.,
                     Antenna.DIPOLE, NetInterface.SMALL, start, end, path2, [])
    config = SimConfig(time=start, peers=[peer1, peer2])
    config.to_file(filepath)


class MapDisplay(object):
    """Dynamic map of peer positions that updates from simulator"""
    def __init__(self, sim_config: str):
        self.server = Flask(__name__)
        self.app = Dash(__name__, server=self.server)
        self.sim = Simulator(sim_config)
        self.cli = SimClient()
        self.mapbox_token = os.environ.get('MAPBOX', '')
        self.resolution = 20
        self.tick = -1
        self.state = SimState()

        self.app.layout = html.Div([
            html.Div(id='time'),
            html.Div([
                dcc.Graph(id='graph', animate=True),
                dcc.Interval(id="interval", interval=1000, n_intervals=0),
                # FIXME use store for previous n positions
                # dcc.Store(id='offset', data=0),
                # dcc.Store(id='store', data=dict(x=x, y=y, resolution=self.resolution)),
            ]),
            html.Div(id='map')
        ])

        @self.app.callback(Output('time', 'children'),
                           Input('interval', 'n_intervals'))
        def update_time(tick):
            self.update_data(tick)
            return self.state.time.isoformat(' ')

        @self.app.callback(Output('graph', 'figure'),
                           Input('interval', 'n_intervals'))
        def update_paths(tick):
            self.update_data(tick)
            x = []
            y = []
            for uuid in self.state.peers:
                position = self.state.peers[uuid]
                x.append(position.x)
                y.append(position.y)
            # FIXME append trace
            data = plotly.graph_objs.Scatter(x=x, y=y, name='Scatter', mode='lines+markers')
            return {'data': [data],
                    'layout': go.Layout(xaxis=dict(range=[min(x), max(x)]),
                                        yaxis=dict(range=[min(y), max(y)]))
                    }

        @self.app.callback(Output('map', 'children'),
                           Input('interval', 'n_intervals'))
        def update_map(tick):
            self.update_data(tick)
            ctr = self.state.center
            scale = self.state.scale
            # FIXME update map
            return

        # self.app.clientside_callback(  # FIXME:
        #    """

    # function (n_intervals, data, offset) {
    #    offset = offset % data.x.length;
    #    const end = Math.min((offset + 10), data.x.length);
    #    return [[{x: [data.x.slice(offset, end)], y: [data.y.slice(offset, end)]}, [0], 500], end]
    # }
    # """,
    # [Output('graph', 'extendData'),
    # Output('offset', 'data')],
    # [Input('interval', 'n_intervals')],
    # [State('store', 'data'), State('offset', 'data')]
    # )

    def update_data(self, tick):
        if tick > self.tick:
            self.state = self.cli.recv_data()
            self.tick += 1

    def run(self):
        t1 = threading.Thread(target=self.sim.run, args=(8888,))
        t1.start()
        self.app.run_server(debug=True)
        self.sim.halt = True
        t1.join()


if __name__ == '__main__':
    cfg = os.path.join(os.path.dirname(__file__), 'test.cfg')
    if not os.path.exists(cfg):
        try:
            generate_config(cfg)
        except:
            os.remove(cfg)
            raise
    try:
        MapDisplay(cfg).run()
    finally:
        if os.path.exists(cfg):
            os.remove(cfg)
