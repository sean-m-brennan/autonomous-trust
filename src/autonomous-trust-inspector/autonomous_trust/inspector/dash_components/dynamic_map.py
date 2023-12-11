import os
from collections import deque, namedtuple
from logging import Logger
from queue import Queue

import dash_bootstrap_components as dbc
import plotly.graph_objects as go
import plotly.colors as colors

from autonomous_trust.services.peer.position import GeoPosition
from .core import DashControl, DashComponent, html, dcc, Output, Input, ctx
from ..peer.daq import CohortInterface


Coord = namedtuple('Coord', 'lat lon')


class DynamicMap(DashComponent):
    trace_len = 10
    max_pitch = 60
    fig_margin = 5
    default_scale = 10000

    def __init__(self, ctl: DashControl, cohort: CohortInterface, logger: Logger, size: int = 600, style: str = 'dark'):
        super().__init__(ctl.app, ctl.server)
        self.ctl = ctl
        self.cohort = cohort
        self.logger = logger
        self.height = size
        self.width = size * 1.3
        self.mapbox_style = style

        self.queue = Queue(maxsize=1)
        self.mapbox_token = os.environ.get('MAPBOX', None)
        self.use_mapbox = False if self.mapbox_token is None else True
        self.fig = go.Figure()
        self.color_map = {}
        self.coords: dict[str, Coord] = {}
        self.z_scale = self.default_scale
        self.pitch = self.max_pitch
        self.bearing = 0
        self.skip = 5
        self.skip_trace = False
        self.following: str = ''
        self.center = None
        self.initialized = False

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

        @self.app.callback(Output('div-null', 'children'),
                           Input('map-graph', 'relayoutData'))
        def get_map_scale(relayout):
            if relayout is not None:
                if self.use_mapbox:
                    if 'mapbox.zoom' in relayout:
                        self.z_scale = relayout['mapbox.zoom']
                else:
                    if 'geo.projection.scale' in relayout:
                        self.z_scale = relayout['geo.projection.scale']
            return ''

        self.basic_layout = dict(showlegend=False, autosize=False, hovermode='closest',
                                 uirevision='keep', height=self.height, width=self.width,  # FIXME 75% of screen
                                 margin=dict(l=self.fig_margin, r=self.fig_margin,
                                             t=self.fig_margin, b=self.fig_margin),
                                 )

        self.cohort.register_updater(self.update_paths)
        self.acquire_initial_conditions()

        #  end __init__

    def update_paths(self):
        if self.cohort.center is None:
            self.logger.debug('Bad data update (null center)')
            return
        if len(self.cohort.peers) == 0:
            self.logger.debug('Bad data update (no peers)')
            return
        self.center = self.cohort.center.convert(GeoPosition)
        if self.skip_trace:
            self.skip_trace = False
        else:
            for uuid in self.cohort.peers:
                if not self.cohort.peers[uuid].active:
                    continue
                position = self.cohort.peers[uuid].position.convert(GeoPosition)
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
        if self.z_scale != self.default_scale:  # FIXME or pitch/bearing/follow changes
            margin = dict(l=self.fig_margin, r=self.fig_margin, t=self.fig_margin, b=self.fig_margin)
            if self.use_mapbox:
                self.fig.update_layout(dict(**self.basic_layout,
                                            mapbox=dict(accesstoken=self.mapbox_token,
                                                        style=self.mapbox_style,
                                                        center=dict(lat=self.center.lat, lon=self.center.lon),
                                                        zoom=self.z_scale,
                                                        pitch=self.pitch,
                                                        bearing=self.bearing,
                                                        ),),
                                       True)
            else:
                self.fig.update_layout(dict(**self.basic_layout,
                                            geo=dict(center=dict(lat=self.center.lat, lon=self.center.lon),
                                                     projection=dict(scale=self.z_scale),
                                                     ),),
                                       True)
        config = dict(displayModeBar=False)
        self.ctl.emit('update_graph_figure', ['map-graph', self.fig.to_dict(), config])

    def trim_traces(self, num: int):
        for uuid in self.cohort.peers:
            if not self.cohort.peers[uuid].active:
                continue
            self.coords[uuid] = Coord(deque(list(self.coords[uuid].lat)[num:-1]),
                                      deque(list(self.coords[uuid].lon)[num:-1]))
        self.skip_trace = True

    def div(self):
        return html.Div([
            html.Div(id='div-null', style={'display': 'none'}),
            dbc.Row([
                dbc.Col([
                    dbc.Stack([
                        html.Div([
                            'Pitch',
                            dcc.Slider(0, self.max_pitch, 5, value=self.pitch,
                                       id='pitch-slider', vertical=True, verticalHeight=self.height),
                        ]),
                        dcc.Graph(id='map-graph', figure=self.fig, config=dict(displayModeBar=False),),
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

        self.cohort.update(initial=True)  # FIXME initial - must not run components
        self.logger.debug('Initialize map: %d peers' % len(self.cohort.peers))
        center = self.cohort.center.convert(GeoPosition)
        scatter = go.Scattergeo
        if self.use_mapbox:
            scatter = go.Scattermapbox
            self.z_scale = 14  # TODO: compute, this is tuned for the example config
        for idx, uuid in enumerate(self.cohort.peers):
            if self.cohort.peers[uuid].active:
                position = self.cohort.peers[uuid].position.convert(GeoPosition)
            else:
                position = GeoPosition(0., 0., 0.)  # hide it
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
        if self.use_mapbox:
            self.fig.update_layout(**self.basic_layout,
                                   mapbox=dict(accesstoken=self.mapbox_token,
                                               style=self.mapbox_style,
                                               center=dict(lat=center.lat, lon=center.lon),
                                               zoom=self.z_scale,
                                               pitch=self.pitch,
                                               bearing=self.bearing,
                                               ),
                                   )
        else:
            self.fig.update_layout(**self.basic_layout,
                                   geo=dict(scope='usa',
                                            showsubunits=True,
                                            center=dict(lat=center.lat, lon=center.lon),
                                            projection=dict(scale=self.z_scale),
                                            ),
                                   )
        if self.initialized:  # i.e. a reset
            config = dict(displayModeBar=False)
            if self.use_mapbox:
                config['mapboxtoken'] = self.mapbox_token
            self.ctl.emit('new_graph_figure', ['map-graph', self.fig.to_dict(), config])
