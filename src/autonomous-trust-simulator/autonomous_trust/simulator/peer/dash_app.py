import logging
import os
import threading
from collections import deque, namedtuple
from queue import Queue, Empty

from flask import Flask
from dash import Dash, html, dcc, Output, Input
import plotly.graph_objects as go
import plotly.colors as colors

from ..sim_client import SimClient
from .position import GeoPosition

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
        self.queue = Queue(maxsize=1)
        self.mapbox_token = os.environ.get('MAPBOX', None)
        self.use_mapbox = False if self.mapbox_token is None else True
        self.interval = -1
        self.state = None
        self.halt = False
        self.height = size
        self.fig = None
        self.color_map = {}
        self.coords = {}
        self.z_scale = 10000
        self.all = []

        self.app.layout = html.Div([
            html.Div(id='time'),
            html.Div([
                dcc.Graph(id='graph', config={'displayModeBar': False}),
                dcc.Interval(id="interval", interval=1000, n_intervals=0),
            ]),
        ])

        @self.app.callback(Output('time', 'children'),
                           Input('interval', 'n_intervals'))
        def update_time(_):
            self.update_state()
            if self.state is None:
                return
            return self.state.time.isoformat(' ').rsplit('.')[0]

        @self.app.callback(Output('graph', 'figure'),
                           [Input('interval', 'n_intervals'),
                            Input('graph', 'relayoutData')])
        def update_paths(_, relayout):
            self.update_state()
            if self.state is None:
                return
            # center = self.state.center.convert(GeoPosition)
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

    def state_to_queue(self):
        def cb(state):
            if state is not None:
                self.queue.put(state, block=True, timeout=None)
        return cb

    def update_state(self, block: bool = True):
        if block:
            self.state = self.queue.get()
        else:
            try:
                self.state = self.queue.get_nowait()
            except Empty:
                pass
        if self.state.blank:
            self.acquire_initial_conditions()

    def acquire_initial_conditions(self):
        # reset
        self.fig = go.Figure()
        self.coords = {}
        self.color_map = {}
        self.all = []

        self.update_state(block=True)
        center = self.state.center.convert(GeoPosition)
        scatter = go.Scattergeo
        if self.use_mapbox:
            scatter = go.Scattermapbox
            self.z_scale = 12  # TODO: compute, this is tuned for the chosen config
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

    def run(self, sim_host: str = '127.0.0.1', sim_port: int = 8778):
        client = SimClient(callback=self.state_to_queue())
        thread = threading.Thread(target=client.run, args=(sim_host, sim_port))
        thread.start()
        self.acquire_initial_conditions()
        self.app.run(self.host, self.port)
        client.halt = True
        thread.join()


if __name__ == '__main__':
    # simulator must be started separately (misbehaves as a thread)
    MapDisplay().run()
