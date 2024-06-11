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

from datetime import datetime
from logging import Logger

import dash_bootstrap_components as dbc

from .core import DashControl, DashComponent, html
from ..peer.daq import CohortInterface


class TimerTitle(DashComponent):
    def __init__(self, ctl: DashControl, cohort: CohortInterface, logger: Logger):
        super().__init__(ctl.app)
        self.ctl = ctl
        self.cohort = cohort
        self.logger = logger
        self.cohort.register_updater(self.update_time)

    def update_time(self):
        if self.cohort.time is not None:
            self.ctl.push_mods({'time': {'children': [self.cohort.time.isoformat(' ').rsplit('.')[0] + ' Z']}})

    def div(self, title: str):
        font_size_elt = 'font-size'
        if self.uses_react:
            font_size_elt = 'fontSize'
        return html.Div([
            dbc.Row([
                dbc.Col(html.Div([title], style={font_size_elt: 'xx-large'}), width=6),
                dbc.Col(html.Div([datetime.now().replace(second=0).isoformat(' ').rsplit('.')[0] + ' Z'],
                                 id='time', style={font_size_elt: 'xx-large'}), width=4),
            ], justify='between'),
        ], id='heading')
