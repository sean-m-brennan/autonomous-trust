# ******************
#  Copyright 2024 TekFive, Inc. and contributors
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

from logging import Logger

import dash_bootstrap_components as dbc

from autonomous_trust.inspector.peer.daq import CohortInterface
from autonomous_trust.inspector.dash_components import make_icon, DashComponent
from autonomous_trust.inspector.dash_components import DashControl, html, dcc, Output, Input, ctx
from autonomous_trust.inspector.dash_components import DynamicMap

from .sim_iface import SimulationInterface


class SimulationControls(DashComponent):
    def __init__(self, dash_info: DashControl, sim: SimulationInterface, cohort: CohortInterface,
                 logger: Logger, mapp: DynamicMap, max_resolution: int = 300):
        super().__init__(dash_info.app)
        self.ctl = dash_info
        self.sim = sim
        self.cohort = cohort
        self.map = mapp
        self.max_resolution = max_resolution
        self.skip = 5

        self.buttons = ['skip-back-btn', 'slow-btn', 'pause-btn', 'fast-btn', 'skip-for-btn']

        self.pause_txt = make_icon('solar:pause-linear', 'Pause')
        self.play_txt = make_icon('solar:play-linear', 'Play')
        font_size_elt = 'font-size'
        if self.uses_react:
            font_size_elt = 'fontSize'
        self.btn_style = {font_size_elt: '0.75em', 'width': 100}
        self.play_pause = self.pause_txt
        if self.sim.paused:
            self.play_pause = self.play_txt

        @self.ctl.callback(Output('pause-btn', 'children'),
                           [Input('skip-back-btn', 'n_clicks'),
                            Input('slow-btn', 'n_clicks'),
                            Input('pause-btn', 'n_clicks'),
                            Input('reset-btn', 'n_clicks'),
                            Input('fast-btn', 'n_clicks'),
                            Input('skip-for-btn', 'n_clicks')],
                           #prevent_initial_call=True
                           )
        def handle_buttons(_back, _slow, _pause, _reset, _fast, _forward):
            if 'skip-back-btn' == ctx.triggered_id:
                self.sim.tick -= self.skip
                if self.sim.tick < 1:
                    self.sim.tick = 0
                self.map.trim_traces(self.skip)
                logger.debug('Simulation: skip back')
            elif 'slow-btn' == ctx.triggered_id:
                self.sim.cadence -= self.skip
                if self.sim.cadence < 1:
                    self.sim.cadence = 1
                logger.debug('Simulation: slow')
            elif 'pause-btn' == ctx.triggered_id:
                self.sim.paused = not self.sim.paused
                self.cohort.paused = self.sim.paused
                logger.debug('Simulation: %s' % 'paused' if self.sim.paused else 'play')
            elif 'reset-btn' == ctx.triggered_id:
                self.sim.paused = False
                self.cohort.paused = self.sim.paused
                logger.debug('Simulation: reset')
            elif 'fast-btn' == ctx.triggered_id:
                self.sim.cadence += self.skip
                if self.sim.cadence > 20:
                    self.sim.cadence = 20
                logger.debug('Simulation: fast')
            elif 'skip-for-btn' == ctx.triggered_id:
                self.sim.tick += self.skip
                if self.sim.tick > self.sim.resolution:
                    self.sim.tick = self.sim.resolution
                logger.debug('Simulation: skip forward')
            if self.sim.paused:
                pause_txt = self.play_txt
            else:
                pause_txt = self.pause_txt
            return pause_txt

        @self.ctl.callback(Output('sim-ctrls-target', 'children'),
                           [Input('resolution-slider', 'value')],
                           #prevent_initial_call=True
                           )
        def handle_sliders(resolution):
            if 'resolution-slider' == ctx.triggered_id:
                if self.sim.resolution < resolution:
                    self.map.trim_traces(resolution - self.sim.resolution)
                self.sim.resolution = resolution
            return html.Div()

        ## end __init__

    def change_controls(self, disable: bool):
        self.ctl.push_mods({'reset-btn': {'disabled': not disable}})
        for button in self.buttons:
            self.ctl.push_mods({button: {'disabled': disable}})

    def disable_controls(self):
        self.change_controls(True)

    def enable_controls(self):
        self.change_controls(False)

    def div(self):
        text_align_elt = 'text-align'
        if self.uses_react:
            text_align_elt = 'textAlign'
        return html.Div([
            html.Div(id='sim-ctrls-target'),
            dbc.Row([
                dbc.Col([
                    html.Div([
                        html.Button(make_icon('solar:rewind-5-seconds-back-linear', 'Skip back'),
                                    id='skip-back-btn', n_clicks=0, style=self.btn_style),
                        html.Button(make_icon('solar:rewind-back-linear', 'Slow down'),
                                    id='slow-btn', n_clicks=0, style=self.btn_style),
                        html.Button(self.play_pause,
                                    id='pause-btn', n_clicks=0, style=self.btn_style),
                        html.Button(make_icon('solar:rewind-forward-linear', 'Speed up'),
                                    id='fast-btn', n_clicks=0, style=self.btn_style),
                        html.Button(make_icon('solar:rewind-5-seconds-forward-linear', 'Skip forward'),
                                    id='skip-for-btn', n_clicks=0, style=self.btn_style),
                        html.Button(make_icon('solar:refresh-linear', 'Reset'),
                                    id='reset-btn', n_clicks=0, disabled=True, style=self.btn_style),
                    ], style=dict(width='50%', margin='0 auto')),
                    html.Br(),
                ]),
            ], justify="center"),
            dbc.Row([
                dbc.Col([
                    dcc.Slider(60, self.max_resolution, 30, value=self.sim.resolution, id='resolution-slider'),
                    html.Div('Simulation Time Resolution (seconds)', style={text_align_elt: 'center'}),
                ]),
            ]),
        ], id='sim_ctrls')
