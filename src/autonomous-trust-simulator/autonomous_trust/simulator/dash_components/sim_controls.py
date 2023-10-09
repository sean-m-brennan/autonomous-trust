from flask import Flask
from dash import Dash, html, dcc, Output, Input, ctx
import dash_bootstrap_components as dbc

from autonomous_trust.inspector.peer.daq import CohortInterface
from autonomous_trust.inspector.dash_components.util import make_icon, DashComponent
from autonomous_trust.inspector.dash_components.dynamic_map import DynamicMap

from .sim_iface import SimulationInterface


class SimulationControls(DashComponent):
    def __init__(self, app: Dash, server: Flask, sim: SimulationInterface, cohort: CohortInterface,
                 mapp: DynamicMap, max_resolution: int = 300, with_interval: bool = True):
        super().__init__(app, server)
        self.sim = sim
        self.cohort = cohort
        self.map = mapp
        self.max_resolution = max_resolution
        self.with_interval = with_interval
        self.skip = 5

        self.pause_txt = make_icon('solar:pause-linear', 'Pause')
        self.play_txt = make_icon('solar:play-linear', 'Play')
        self.btn_style = {'font-size': '0.75em', 'width': 100}
        self.play_pause = self.pause_txt
        if self.sim.paused:
            self.play_pause = self.play_txt

        @self.app.callback(Output('pause-btn', 'children'),
                           Input('skip-back-btn', 'n_clicks'),
                           Input('slow-btn', 'n_clicks'),
                           Input('pause-btn', 'n_clicks'),
                           Input('reset-btn', 'n_clicks'),
                           Input('fast-btn', 'n_clicks'),
                           Input('skip-for-btn', 'n_clicks'),
                           prevent_initial_call=True)
        def handle_buttons(_back, _slow, _pause, _reset, _fast, _forward):
            if 'skip-back-btn' == ctx.triggered_id:
                self.sim.tick -= self.skip
                if self.sim.tick < 1:
                    self.sim.tick = 0
                self.map.trim_traces(self.skip)
            elif 'slow-btn' == ctx.triggered_id:
                self.sim.cadence -= self.skip
                if self.sim.cadence < 1:
                    self.sim.cadence = 1
            elif 'pause-btn' == ctx.triggered_id:
                self.sim.paused = not self.sim.paused
                self.cohort.paused = self.sim.paused
            elif 'reset-btn' == ctx.triggered_id:
                self.sim.paused = False
            elif 'fast-btn' == ctx.triggered_id:
                self.sim.cadence += self.skip
                if self.sim.cadence > 20:
                    self.sim.cadence = 20
            elif 'skip-for-btn' == ctx.triggered_id:
                self.sim.tick += self.skip
                if self.sim.tick > self.sim.resolution:
                    self.sim.tick = self.sim.resolution
            if self.sim.paused:
                pause_txt = self.play_txt
            else:
                pause_txt = self.pause_txt
            return pause_txt

        @self.app.callback(Output('sim-ctrls-target', 'children'),
                           Input('resolution-slider', 'value'),
                           prevent_initial_call=True)
        def handle_sliders(_pitch, _bearing, resolution):
            if 'resolution-slider' == ctx.triggered_id:
                if self.sim.resolution < resolution:
                    self.map.trim_traces(resolution - self.sim.resolution)
                self.sim.resolution = resolution
            return html.Div()

        @self.app.callback(Output('reset-btn', 'disabled'),
                           Output('pause-btn', 'disabled'),
                           Output('skip-back-btn', 'disabled'),
                           Output('slow-btn', 'disabled'),
                           Output('fast-btn', 'disabled'),
                           Output('skip-for-btn', 'disabled'),
                           Input('interval', 'n_intervals'))
        def reset_disabled(_):
            self.sim.update()  # this is the only call among all components, for sync
            if self.sim.can_reset:
                return False, True, True, True, True, True
            return True, False, False, False, False, False

    def div(self):
        additional = []
        if self.with_interval:
            additional.append(dcc.Interval(id="interval", interval=1000, n_intervals=0))
        return html.Div(additional + [
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
                    html.Div('Simulation Time Resolution (seconds)', style={'text-align': 'center'}),
                ]),
            ]),
        ], id='sim_ctrls')
