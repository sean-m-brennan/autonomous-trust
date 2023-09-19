from datetime import datetime

from flask import Flask
from dash import Dash, html, dcc, Output, Input
import dash_bootstrap_components as dbc
from dash.exceptions import PreventUpdate

from ..daq import Cohort
from ...dash_components.util import DashComponent


class TimerTitle(DashComponent):
    def __init__(self, app: Dash, server: Flask, cohort: Cohort, with_interval: bool = True):
        super().__init__(app, server)
        self.with_interval = with_interval

        @self.app.callback(Output('time', 'children'),
                           Input('interval', 'n_intervals'))
        def update_time(_):
            if cohort.paused:
                raise PreventUpdate
            state = cohort.update()
            if state is None:
                return
            return state.time.isoformat(' ').rsplit('.')[0]

    def div(self, title: str):
        additional = []
        if self.with_interval:
            additional.append(dcc.Interval(id="interval", interval=1000, n_intervals=0))
        return html.Div(additional + [
            dbc.Row([
                dbc.Col(html.Div([title], style={'font-size': 'xx-large'}), width=6),
                dbc.Col(html.Div([datetime.now().replace(second=0).isoformat(' ').rsplit('.')[0]],
                                 id='time', style={'font-size': 'xx-large'}), width=4),
            ], justify='between'),
        ], id='heading')
