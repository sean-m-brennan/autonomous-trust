from queue import Empty

from flask import Flask
from dash import Dash, html, dcc
from plotly import graph_objects as go

from .util import DashComponent
from ..peer.daq import PeerDataAcq


class DataFeed(DashComponent):
    def __init__(self, app: Dash, server: Flask, peer: PeerDataAcq, number: int):
        super().__init__(app, server)
        self.server = server
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
                         dcc.Graph(id='data_graph', config=dict(displayModeBar=False),
                                   style=dict(width='50%', height=320))],
                        style=style)
