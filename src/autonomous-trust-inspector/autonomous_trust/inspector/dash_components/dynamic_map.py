# ******************
#  Copyright 2023 TekFive, Inc., Sean M. Brennan, and contributors
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
# ******************

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
        super().__init__(ctl.app)
        self.ctl = ctl
        self.cohort = cohort
        self.logger = logger
        self.height = size
        self.width = size * 1.3
        self.map_style = style

        self.queue = Queue(maxsize=1)
        self.use_map = os.environ.get('MAPBOX', None) is not None
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
        self.peer_tracker: dict[str, bool] = {}

        @ctl.callback(Output('map-slider-target', 'children'),
                      [Input('pitch-slider', 'value'),
                       Input('bearing-slider', 'value')],
                      # prevent_initial_call=True
                      )
        def handle_sliders(pitch, bearing):
            if 'pitch-slider' == ctx.triggered_id:
                self.pitch = pitch
            elif 'bearing-slider' == ctx.triggered_id:
                self.bearing = bearing
            return ''

        @ctl.callback(Output('map-scale-target', 'children'),
                      [Input('map-graph', 'relayoutData')])
        def get_map_scale(relay_out):
            if relay_out is not None:
                if self.use_map:
                    if 'map.zoom' in relay_out:
                        self.z_scale = relay_out['map.zoom']
                else:
                    if 'geo.projection.scale' in relay_out:
                        self.z_scale = relay_out['geo.projection.scale']
            return ''

        # UI tuning open: use 75% of screen instead of fixed
        # self.width / self.height — needs viewport-aware sizing.
        self.basic_layout = dict(showlegend=False, autosize=False, hovermode='closest',
                                 uirevision='keep', height=self.height, width=self.width,
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
            for idx, uuid in enumerate(self.cohort.peers):
                if not self.cohort.peers[uuid].active:
                    self.peer_tracker[uuid] = False
                    continue
                position = self.cohort.peers[uuid].position.convert(GeoPosition)
                if uuid not in self.coords:
                    self.coords[uuid] = Coord(deque(maxlen=self.trace_len), deque(maxlen=self.trace_len))
                self.coords[uuid].lat.append(position.x)
                self.coords[uuid].lon.append(position.y)
                if uuid in self.peer_tracker and self.peer_tracker[uuid] is True:
                    # traces already created
                    self.fig.update_traces(selector=dict(name=uuid), mode='lines', overwrite=True,
                                           lat=list(self.coords[uuid].lat), lon=list(self.coords[uuid].lon))
                    self.fig.update_traces(selector=dict(name=f'mark-{uuid}'), mode='markers', overwrite=True,
                                           lat=[self.coords[uuid].lat[-1]], lon=[self.coords[uuid].lon[-1]])
                else:
                    self.add_traces(idx, uuid)
                    self.peer_tracker[uuid] = True
                if self.following == uuid:
                    # UI tuning open: hide the previous follow-marker
                    # when the target changes (currently both linger).
                    self.center = GeoPosition(self.coords[uuid].lat[-1], self.coords[uuid].lon[-1])
                    self.fig.update_traces(selector=dict(name=f'follow-{uuid}'), mode='markers',
                                           overwrite=True,
                                           lat=[self.coords[uuid].lat[-1]], lon=[self.coords[uuid].lon[-1]])
        # UI tuning open: also trigger this branch on pitch / bearing
        # / follow changes — z_scale alone misses camera-state edits.
        if self.z_scale != self.default_scale:
            margin = dict(l=self.fig_margin, r=self.fig_margin, t=self.fig_margin, b=self.fig_margin)
            if self.use_map:
                self.fig.update_layout(dict(**self.basic_layout,
                                            map=dict(style=self.map_style,
                                                     center=dict(lat=self.center.lat, lon=self.center.lon),
                                                     zoom=self.z_scale,
                                                     pitch=self.pitch,
                                                     bearing=self.bearing,
                                                     ), ),
                                       True)
            else:
                self.fig.update_layout(dict(**self.basic_layout,
                                            geo=dict(center=dict(lat=self.center.lat, lon=self.center.lon),
                                                     projection=dict(scale=self.z_scale),
                                                     ), ),
                                       True)
        if self.ctl.legacy:
            config = dict(displayModeBar=False)
            self.ctl.emit('update_figure', ['map-graph', self.fig.to_dict(), config])
        else:
            self.ctl.push_mods({'map-graph': {'figure': self.fig.to_dict()}})

    def trim_traces(self, num: int):
        for uuid in self.cohort.peers:
            if not self.cohort.peers[uuid].active:
                continue
            self.coords[uuid] = Coord(deque(list(self.coords[uuid].lat)[num:-1]),
                                      deque(list(self.coords[uuid].lon)[num:-1]))
        self.skip_trace = True

    def div(self):
        return html.Div([
            html.Div(id='map-scale-target', style={'display': 'none'}),
            html.Div(id='map-slider-target', style={'display': 'none'}),
            dbc.Row([
                dbc.Col([
                    dbc.Stack([
                        html.Div([
                            'Pitch',
                            dcc.Slider(0, self.max_pitch, 5, value=self.pitch,
                                       id='pitch-slider', vertical=True, verticalHeight=self.height),
                        ]),
                        dcc.Graph(id='map-graph', figure=self.fig, config=dict(displayModeBar=False),
                                  animate=True),
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

    def add_traces(self, idx, uuid):
        position = self.cohort.peers[uuid].position.convert(GeoPosition)
        scatter = go.Scattergeo
        if self.use_map:
            scatter = go.Scattermap
        self.color_map[uuid] = colors.qualitative.Light24[idx]
        self.fig.add_trace(scatter(lat=[position.lat], lon=[position.lon],
                                   mode='markers', marker=dict(color=self.color_map[uuid], opacity=.7),
                                   name=f'mark-{uuid}'))
        self.fig.add_trace(scatter(lat=[position.lat], lon=[position.lon],
                                   mode='lines', line=dict(color=self.color_map[uuid], width=3),
                                   name=uuid))
        self.fig.add_trace(scatter(lat=[0], lon=[0],
                                   mode='markers', marker=dict(color='white', size=5, opacity=.5),
                                   name=f'follow-{uuid}'))

    def acquire_initial_conditions(self):
        # reset
        self.fig = go.Figure()
        self.coords: dict[str, GeoPosition] = {}
        self.color_map: dict[str, str] = {}

        # UI tuning open: the `initial=True` signal should bypass
        # component-update side-effects during the first render;
        # currently it runs the full update path.
        self.cohort.update(initial=True)
        self.logger.debug(f'Initialize map: {len(self.cohort.peers)} peers')
        center = self.cohort.center.convert(GeoPosition)
        if self.use_map:
            # UI tuning open: compute z_scale from cohort bounding box;
            # 14 is hand-tuned for the example config.
            self.z_scale = 14
        for idx, uuid in enumerate(self.cohort.peers):
            if self.cohort.peers[uuid].active:
                self.peer_tracker[uuid] = True
                self.add_traces(idx, uuid)
            else:
                # UI tuning open: defer inactive-peer trace insertion
                # until the update pass; doing it here forces a layout
                # pass at init time.
                self.peer_tracker[uuid] = False
                #position = GeoPosition(0., 0., 0.)  # hide it
        if self.use_map:
            self.fig.update_layout(**self.basic_layout,
                                   map=dict(style=self.map_style,
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
            if self.ctl.legacy:
                config = dict(displayModeBar=False)
                self.ctl.emit('update_figure', ['map-graph', self.fig.to_dict(), config])
            else:
                self.ctl.push_mods({'map-graph': {'figure': self.fig.to_dict()}})
