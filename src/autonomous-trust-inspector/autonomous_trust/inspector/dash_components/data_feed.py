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

from queue import Empty

from flask import Flask
from plotly import graph_objects as go

from .core import DashComponent, html, dcc, DashControl
from ..peer.daq import PeerDataAcq


class DataFeed(DashComponent):
    def __init__(self, ctl: DashControl, peer: PeerDataAcq, number: int):
        super().__init__(ctl.app)
        self.ctl = ctl
        self.number = str(number)
        self.peer = peer
        self.halt = False
        self.idx = 0
        self.fig = go.Figure()
        self.fig.add_trace(go.Scatter(x=[float(self.idx)], y=[0.0] * peer.metadata.data_channels, mode='lines',
                                      name='data_%s' % self.number))

    def rcv(self):
        while not self.halt:
            try:
                data = self.peer.data_stream.get()  # tuple of floats
            except Empty:
                continue
            if data:
                self.idx += 1
                self.fig.update_traces(selector=dict(name='data_%s' % self.number,
                                                     x=[float(self.idx)], y=data, mode='lines'))

    def div(self, title: str, style: dict = None) -> html.Div:
        if style is None:
            style = {'float': 'left', 'padding': 10}
        return html.Div([html.H1(title),
                         dcc.Graph(id='data_graph_%d' % self.peer.index, config=dict(displayModeBar=False),
                                   style=dict(width='50%', height=320))],
                        style=style)
