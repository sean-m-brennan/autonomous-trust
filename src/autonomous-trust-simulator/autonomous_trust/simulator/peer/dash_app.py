import logging
import os
import threading
import time
from collections import deque, namedtuple
from datetime import datetime, timedelta

from flask import Flask
from dash import Dash, html, dcc, Output, Input
import plotly.graph_objects as go
import plotly.colors as colors
from uuid import uuid4

from ..radio.iface import Antenna, NetInterface
from .peer import PeerData
from .path import BezierData, PathData, EllipseData, Variability
from .position import GeoPosition, UTMPosition
from ..sim_data import SimConfig
from ..simulator import Simulator
from ..sim_client import SimClient
from .dash_config import generate_config, generate_small_config


Coord = namedtuple('Coord', 'lat lon')
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)  # reduce callback noise from Flask


class MapDisplay(object):
    """Dynamic map of peer positions that updates from simulator"""
    trace_len = 30

    def __init__(self, host: str = '127.0.0.1', port: int = 8050, size: int = 600):
        self.host = host
        self.port = port
        self.server = Flask(__name__)
        self.app = Dash(__name__, server=self.server,
                        prevent_initial_callbacks=True, update_title=None)
        self.cli = SimClient(debug=True)
        self.mapbox_token = os.environ.get('MAPBOX', None)
        self.use_mapbox = False if self.mapbox_token is None else True
        self.tick = -1
        self.state = None
        self.halt = False
        self.started = False
        self.height = size

        self.app.layout = html.Div([
            html.Div(id='time'),
            html.Div([
                dcc.Graph(id='graph', config={'displayModeBar': False}),
                dcc.Interval(id="interval", interval=.5 * 1000, n_intervals=0),
            ]),
        ])

        self.fig = go.Figure()
        self.color_map = {}
        self.coords = {}
        self.z_scale = 10000
        self.all = []

        @self.app.callback(Output('time', 'children'),
                           Input('interval', 'n_intervals'))
        def update_time(tick):
            self.update_data(tick)
            if self.state is None:
                return
            return self.state.time.isoformat(' ').rsplit('.')[0]

        @self.app.callback(Output('graph', 'figure'),
                           [Input('interval', 'n_intervals'),
                            Input('graph', 'relayoutData')])
        def update_paths(tick, relayout):
            self.update_data(tick)
            if self.state is None:
                if self.started:
                    self.halt = True
                return
            self.started = True
            #center = self.state.center.convert(GeoPosition)
            for uuid in self.state.peers:
                position = self.state.peers[uuid].convert(GeoPosition)
                if uuid not in self.coords:
                    self.coords[uuid] = Coord(deque(maxlen=self.trace_len), deque(maxlen=self.trace_len))
                self.coords[uuid].lat.append(position.x)
                self.coords[uuid].lon.append(position.y)
                self.fig.update_traces(selector=dict(name=uuid), mode='lines', overwrite=True,
                                       lat=list(self.coords[uuid].lat), lon=list(self.coords[uuid].lon))
                self.fig.update_traces(selector=dict(name='mark-%s' % uuid), mode='markers', overwrite=True,
                                       lat=[self.coords[uuid].lat[-1]], lon=[self.coords[uuid].lon[-1]])
                self.all.append(position)
            scale = self.z_scale
            if relayout is not None:
                center = GeoPosition.middle(self.all)
                if self.use_mapbox:
                    if 'mapbox.zoom' in relayout:
                        scale = relayout['mapbox.zoom']
                    self.fig.update_layout({'mapbox.center.lat': center.lat,
                                            'mapbox.center.lon': center.lon,
                                            'mapbox.zoom': scale}, True)
                else:
                    if 'geo.projection.scale' in relayout:
                        scale = relayout['geo.projection.scale']
                    self.fig.update_layout({'geo.center.lat': center.lat,
                                            'geo.center.lon': center.lon,
                                            'geo.projection.scale': scale}, True)
            return self.fig

    def acquire_initial_conditions(self):
        while self.cli.is_socket_closed():
            time.sleep(0.5)
        self.update_data(0)
        if self.state is None:
            raise RuntimeError('Unconnected client')
        center = self.state.center.convert(GeoPosition)
        scatter = go.Scattergeo
        if self.use_mapbox:
            scatter = go.Scattermapbox
            self.z_scale = 12  # TODO: compute, this is tuned
        for idx, uuid in enumerate(self.state.peers):
            position = self.state.peers[uuid].convert(GeoPosition)
            self.color_map[uuid] = colors.qualitative.Light24[idx]
            self.fig.add_trace(scatter(lat=[position.lat], lon=[position.lon],
                                       mode='markers', marker=dict(color=self.color_map[uuid], opacity=.7),
                                       name='mark-' + uuid))
            self.fig.add_trace(scatter(lat=[position.lat], lon=[position.lon],
                                       mode='lines', line=dict(color=self.color_map[uuid], width=3),
                                       name=uuid))
        basic_layout = dict(showlegend=False, autosize=False, hovermode='closest',
                            uirevision='keep', height=self.height)
        if self.use_mapbox:
            self.fig.update_layout(**basic_layout,
                                   mapbox=dict(
                                       accesstoken=self.mapbox_token,
                                       style="dark",
                                       center=dict(lat=center.lat, lon=center.lon),
                                       zoom=self.z_scale,
                                   ))
        else:
            self.fig.update_layout(**basic_layout,
                                   geo=dict(scope='usa',
                                            showsubunits=True,
                                            center=dict(lat=center.lat, lon=center.lon),
                                            # zoom=self.z_scale  #FIXME wrong
                                            ))

    def update_data(self, tick):
        if tick > self.tick:
            self.state = self.cli.recv_data()
            self.tick += 1

    def run(self, sim_host: str = '127.0.0.1', sim_port: int = 8778,
            with_server: bool = False, sim_config: str = None):
        threads = []
        sim = None
        if with_server:
            sim = Simulator(sim_config, 60, debug=True)  # in seconds
            threads.append(threading.Thread(target=sim.run, args=(sim_port,)))

        threads.append(threading.Thread(target=self.cli.run, args=(sim_host, sim_port)))
        for t in threads:
            t.start()
        self.acquire_initial_conditions()
        self.app.run(self.host, self.port)
        self.cli.halt = True
        if sim is not None:
            sim.halt = True
        for t in threads:
            t.join()


if __name__ == '__main__':
    cfg = os.path.join(os.path.dirname(__file__), 'test.cfg')
    if not os.path.exists(cfg):
        try:
            generate_small_config(cfg)
        except:
            os.remove(cfg)
            raise
    try:
        MapDisplay().run(with_server=True, sim_config=cfg)
    finally:
        if os.path.exists(cfg):
            os.remove(cfg)
