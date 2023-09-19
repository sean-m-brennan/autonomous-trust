import os
from collections import deque, namedtuple
from queue import Queue

from dash import Dash, html, dcc, Output, Input, ctx
import dash_bootstrap_components as dbc
from dash.exceptions import PreventUpdate
from flask import Flask
import plotly.graph_objects as go
import plotly.colors as colors

from ...sim_data import SimState
from ...dash_components.util import DashComponent
from ..position import GeoPosition
from ..daq import Cohort

Coord = namedtuple('Coord', 'lat lon')


class DynamicMap(DashComponent):
    trace_len = 10
    max_pitch = 60
    fig_margin = 5

    def __init__(self, app: Dash, server: Flask, cohort: Cohort, size: int = 600, style: str = 'dark'):
        super().__init__(app, server)
        self.cohort = cohort
        self.queue = Queue(maxsize=1)
        self.mapbox_token = os.environ.get('MAPBOX', None)
        self.mapbox_style = style
        self.use_mapbox = False if self.mapbox_token is None else True
        self.height = size
        self.fig = None
        self.color_map = {}
        self.coords: dict[str, Coord] = {}
        self.z_scale = 10000
        self.pitch = self.max_pitch
        self.bearing = 0
        self.skip = 5
        self.skip_trace = False
        self.following: str = ''
        self.center = None
        self.state: SimState
        self.update_display = True

        @self.app.callback(Output('graph', 'figure'),
                           [Input('interval', 'n_intervals'),
                            Input('graph', 'relayoutData')])
        def update_paths(_, relayout):
            if not self.update_display:
                raise PreventUpdate
            if not self.cohort.paused:
                self.state = self.cohort.update()
                if self.state is None:
                    return
                self.center = self.state.center.convert(GeoPosition)
                if self.skip_trace:
                    self.skip_trace = False
                else:
                    for uuid in self.state.peers:
                        position = self.state.peers[uuid].position.convert(GeoPosition)
                        if uuid not in self.coords:
                            self.coords[uuid] = Coord(deque(maxlen=self.trace_len), deque(maxlen=self.trace_len))
                        self.coords[uuid].lat.append(position.x)
                        self.coords[uuid].lon.append(position.y)
                        self.fig.update_traces(selector=dict(name=uuid), mode='lines', overwrite=True,
                                               lat=list(self.coords[uuid].lat), lon=list(self.coords[uuid].lon))
                        self.fig.update_traces(selector=dict(name='mark-%s' % uuid), mode='markers', overwrite=True,
                                               lat=[self.coords[uuid].lat[-1]], lon=[self.coords[uuid].lon[-1]])
                        if self.following == uuid:
                            # FIXME disable previous marker
                            self.center = GeoPosition(self.coords[uuid].lat[-1], self.coords[uuid].lon[-1])
                            self.fig.update_traces(selector=dict(name='follow-%s' % uuid), mode='markers',
                                                   overwrite=True,
                                                   lat=[self.coords[uuid].lat[-1]], lon=[self.coords[uuid].lon[-1]])
            scale = self.z_scale
            if relayout is not None:
                margin = dict(l=self.fig_margin, r=self.fig_margin, t=self.fig_margin, b=self.fig_margin)
                if self.use_mapbox:
                    if 'mapbox.zoom' in relayout:
                        scale = relayout['mapbox.zoom']
                    self.fig.update_layout(dict(mapbox=dict(accesstoken=self.mapbox_token,
                                                            style=self.mapbox_style,
                                                            center=dict(lat=self.center.lat, lon=self.center.lon),
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
                    self.fig.update_layout(dict(geo=dict(center=dict(lat=self.center.lat, lon=self.center.lon),
                                                         projection=dict(scale=scale),
                                                         ),
                                                margin=margin,
                                                ),
                                           True)
            return self.fig

        @self.app.callback(Output('map-slider-target', 'children'),
                           Input('pitch-slider', 'value'),
                           Input('bearing-slider', 'value'),
                           prevent_initial_call=True)
        def handle_sliders(pitch, bearing):
            if 'pitch-slider' == ctx.triggered_id:
                self.pitch = pitch
            elif 'bearing-slider' == ctx.triggered_id:
                self.bearing = bearing
            return html.Div()

        self.acquire_initial_conditions()
        #  end __init__

    def trim_traces(self, num: int):
        for uuid in self.state.peers:
            self.coords[uuid] = Coord(deque(list(self.coords[uuid].lat)[num:-1]),
                                      deque(list(self.coords[uuid].lon)[num:-1]))
        self.skip_trace = True

    def state_to_queue(self):
        def cb(state):
            if state is not None:
                self.queue.put(state, block=True, timeout=None)

        return cb

    def div(self):
        return html.Div([
            dcc.Interval(id="interval", interval=1000, n_intervals=0),
            dbc.Row([
                dbc.Col([
                    dbc.Stack([
                        html.Div([
                            'Pitch',
                            dcc.Slider(0, self.max_pitch, 5, value=self.pitch,
                                       id='pitch-slider', vertical=True, verticalHeight=self.height),
                        ]),
                        dcc.Graph(id='graph', config=dict(displayModeBar=False),
                                  style=dict(width='95%', height=self.height)),
                    ], direction="horizontal"),
                ]),
            ]),
            dbc.Row([
                dbc.Col(
                    html.Div([
                        'Bearing',
                        dcc.Slider(0, 340, 20, value=self.bearing, id='bearing-slider'),
                    ]),
                ),
            ]),
        ])

    def acquire_initial_conditions(self):
        # reset
        self.fig = go.Figure()
        self.coords = {}
        self.color_map = {}

        self.state = self.cohort.update(block=True)
        print(self.state)
        center = self.state.center.convert(GeoPosition)
        scatter = go.Scattergeo
        if self.use_mapbox:
            scatter = go.Scattermapbox
            self.z_scale = 12  # TODO: compute, this is tuned for the example config
        for idx, uuid in enumerate(self.state.peers):
            position = self.state.peers[uuid].position.convert(GeoPosition)
            self.color_map[uuid] = colors.qualitative.Light24[idx]
            self.fig.add_trace(scatter(lat=[position.lat], lon=[position.lon],
                                       mode='markers', marker=dict(color=self.color_map[uuid], opacity=.7),
                                       name='mark-%s' % uuid))
            self.fig.add_trace(scatter(lat=[position.lat], lon=[position.lon],
                                       mode='lines', line=dict(color=self.color_map[uuid], width=3),
                                       name=uuid))
            self.fig.add_trace(scatter(lat=[0], lon=[0],
                                       mode='markers', marker=dict(color='white', size=5, opacity=.5),
                                       name='follow-%s' % uuid))
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
