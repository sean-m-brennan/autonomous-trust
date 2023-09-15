import atexit
import logging
import os
import threading
import time
from collections import deque, namedtuple
from queue import Queue, Empty

from flask import Flask
from dash import Dash, html, dcc, Output, Input, ctx
from dash_iconify import DashIconify
from dash.exceptions import PreventUpdate
import plotly.graph_objects as go
import plotly.colors as colors

from ..sim_client import SimClient
from .position import GeoPosition

Coord = namedtuple('Coord', 'lat lon')
log = logging.getLogger('werkzeug')
log.setLevel(logging.WARNING)  # reduce callback noise from Flask


class MapDisplay(object):
    """Dynamic map of peer positions that updates from simulator"""
    trace_len = 10
    max_pitch = 60
    fig_margin = 5

    def __init__(self, sim_host: str = '127.0.0.1', sim_port: int = 8778, size: int = 600, max_resolution: int = 300):
        self.client = SimClient(callback=self.state_to_queue())
        self.server = Flask(__name__)
        self.app = Dash(__name__, server=self.server,
                        prevent_initial_callbacks=True, update_title=None)
        self.queue = Queue(maxsize=1)
        self.mapbox_token = os.environ.get('MAPBOX', None)
        self.mapbox_style = 'dark'
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
        self.paused = False
        self.pitch = self.max_pitch
        self.bearing = 0
        self.max_resolution = max_resolution
        self.can_reset = False

        def make_icon(icon_name, text):
            return [DashIconify(icon=icon_name, height=30),
                    html.Br(), text]

        self.pause_txt = make_icon('solar:pause-linear', 'Pause')
        self.play_txt = make_icon('solar:play-linear', 'Play')
        btn_style = {'font-size': '0.75em', 'width': 100}

        self.app.layout = html.Div([
            html.Div(id='time',
                     style={'width': '100%', 'font-size': 'xx-large'}),
            html.Div([
                dcc.Graph(id='graph', config=dict(displayModeBar=False),
                          style=dict(width='95%', height=self.height, float='left')),
                html.Div([
                    'Pitch',
                    dcc.Slider(0, self.max_pitch, 5, value=self.pitch, id='pitch-slider',
                               vertical=True, verticalHeight=self.height * .9),
                ], style=dict(float='left')),
                dcc.Interval(id="interval", interval=1000, n_intervals=0),
                html.Div([
                    'Bearing',
                    dcc.Slider(0, 340, 20, value=self.bearing, id='bearing-slider'),
                ], style=dict(width='95%')),
            ], id='map-ctrls'),

            html.Div([html.Br(), html.Br()]),

            html.Div([
                html.Div([
                    html.Div([
                        html.Button(make_icon('solar:rewind-10-seconds-back-linear', 'Skip back'),
                                    id='skip-back-btn', n_clicks=0, style=btn_style),
                        html.Button(make_icon('solar:rewind-back-linear', 'Slow down'),
                                    id='slow-btn', n_clicks=0, style=btn_style),
                        html.Button(self.pause_txt,
                                    id='pause-btn', n_clicks=0, style=btn_style),
                        html.Button(make_icon('solar:rewind-forward-linear', 'Speed up'),
                                    id='fast-btn', n_clicks=0, style=btn_style),
                        html.Button(make_icon('solar:rewind-10-seconds-forward-linear', 'Skip forward'),
                                    id='skip-for-btn', n_clicks=0, style=btn_style),
                        html.Button(make_icon('solar:refresh-linear', 'Reset'),
                                    id='reset-btn', n_clicks=0, disabled=True, style=btn_style),
                    ], style=dict(width='50%', margin='0 auto')
                    ),
                    html.Div([html.Br()]),
                ], style={'overflow-x': 'auto', 'width': '100%'}),
                html.Div([
                    dcc.Slider(60, self.max_resolution, 30, value=self.client.resolution, id='resolution-slider'),
                    html.Div('Simulation Time Resolution (seconds)', style={'text-align': 'center'}),
                ], style=dict({'margin': '0 auto 0', 'width': '100%'})),
            ], id='sim_ctrls'),

            html.Div(id='container-slider-timestamp'),
        ])

        @self.app.callback(Output('pause-btn', 'children'),
                           Input('skip-back-btn', 'n_clicks'),
                           Input('slow-btn', 'n_clicks'),
                           Input('pause-btn', 'n_clicks'),
                           Input('reset-btn', 'n_clicks'),
                           Input('fast-btn', 'n_clicks'),
                           Input('skip-for-btn', 'n_clicks'),
                           prevent_initial_call=True)
        def handle_buttons(back, slow, pause, reset, fast, forward):
            if 'skip-back-btn' == ctx.triggered_id:
                self.client.tick -= 10
                if self.client.tick < 1:
                    self.client.tick = 0
                # TODO remove traces?
            elif 'slow-btn' == ctx.triggered_id:
                self.client.cadence -= 10
                if self.client.cadence < 1:
                    self.client.cadence = 1
            elif 'pause-btn' == ctx.triggered_id:
                self.paused = not self.paused
            elif 'reset-btn' == ctx.triggered_id:
                self.paused = False
            elif 'fast-btn' == ctx.triggered_id:
                self.client.cadence += 10
                if self.client.cadence > 20:
                    self.client.cadence = 20
            elif 'skip-for-btn' == ctx.triggered_id:
                self.client.tick += 10
                if self.client.tick > self.client.resolution:
                    self.client.tick = self.client.resolution
            if self.paused:
                pause_txt = self.play_txt
            else:
                pause_txt = self.pause_txt
            return pause_txt

        @self.app.callback(Output('container-slider-timestamp', 'children'),
                           Input('pitch-slider', 'value'),
                           Input('bearing-slider', 'value'),
                           Input('resolution-slider', 'value'),
                           prevent_initial_call=True)
        def handle_sliders(pitch, bearing, resolution):
            if 'pitch-slider' == ctx.triggered_id:
                self.pitch = pitch
            elif 'bearing-slider' == ctx.triggered_id:
                self.bearing = bearing
            elif 'resolution-slider' == ctx.triggered_id:
                # FIXME Simulation - IndexError: list index out of range - path.py, line 92,
                self.client.resolution = resolution
            return html.Div()

        @self.app.callback(Output('reset-btn', 'disabled'),
                           Output('pause-btn', 'disabled'),
                           Output('skip-back-btn', 'disabled'),
                           Output('slow-btn', 'disabled'),
                           Output('fast-btn', 'disabled'),
                           Output('skip-for-btn', 'disabled'),
                           Input('interval', 'n_intervals'))
        def reset_disabled(interval):
            if self.can_reset:
                return False, True, True, True, True, True
            return True, False, False, False, False, False

        @self.app.callback(Output('time', 'children'),
                           Input('interval', 'n_intervals'))
        def update_time(_):
            if self.paused:
                raise PreventUpdate
            self.update_state()
            if self.state is None:
                return
            return self.state.time.isoformat(' ').rsplit('.')[0]

        @self.app.callback(Output('graph', 'figure'),
                           [Input('interval', 'n_intervals'),
                            Input('graph', 'relayoutData')])
        def update_paths(_, relayout):
            if self.paused:
                raise PreventUpdate
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
                margin = dict(l=self.fig_margin, r=self.fig_margin, t=self.fig_margin, b=self.fig_margin)
                if self.use_mapbox:
                    if 'mapbox.zoom' in relayout:
                        scale = relayout['mapbox.zoom']
                    self.fig.update_layout(dict(mapbox=dict(accesstoken=self.mapbox_token,
                                                            style=self.mapbox_style,
                                                            center=dict(lat=center.lat, lon=center.lon),
                                                            zoom=scale,
                                                            pitch=self.pitch,
                                                            bearing=self.bearing,
                                                            ),
                                                margin=margin,
                                                ),
                                           True)
                else:
                    if 'geo.projection.scale' in relayout:
                        scale = relayout['geo.projection.scale']
                    self.fig.update_layout(dict(geo=dict(center=dict(lat=center.lat, lon=center.lon),
                                                         projection=dict(scale=scale),
                                                         ),
                                                margin=margin,
                                                ),
                                           True)
            return self.fig

        self.thread = threading.Thread(target=self.client.run, args=(sim_host, sim_port))
        self.thread.start()
        atexit.register(self.interrupt)
        self.acquire_initial_conditions()
        # end __init__

    def interrupt(self):
        self.client.halt = True
        if self.client.sock is not None:
            self.client.sock.close()
        self.thread.join()

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
            self.paused = True
            self.can_reset = True
            while self.paused:
                time.sleep(0.1)
            self.can_reset = False
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
            self.z_scale = 12  # TODO: compute, this is tuned for the example config
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
                            uirevision='keep', height=self.height,
                            margin=dict(l=self.fig_margin, r=self.fig_margin, t=self.fig_margin, b=self.fig_margin),
                            )
        if self.use_mapbox:
            self.fig.update_layout(**basic_layout,
                                   mapbox=dict(accesstoken=self.mapbox_token,
                                               style=self.mapbox_style,
                                               center=dict(lat=center.lat, lon=center.lon),
                                               zoom=self.z_scale,
                                               pitch=self.pitch,
                                               bearing=self.bearing,
                                               ),
                                   )
        else:
            self.fig.update_layout(**basic_layout,
                                   geo=dict(scope='usa',
                                            showsubunits=True,
                                            center=dict(lat=center.lat, lon=center.lon),
                                            projection=dict(scale=self.z_scale),
                                            ),
                                   )

    def run(self, host: str = '127.0.0.1', port: int = 8050):
        self.app.run(host, port)


if __name__ == '__main__':
    # simulator must be started separately
    MapDisplay().run()
else:
    gunicorn_app = MapDisplay().app
