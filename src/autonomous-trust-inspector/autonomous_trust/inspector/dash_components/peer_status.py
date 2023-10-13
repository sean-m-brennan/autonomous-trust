from itertools import zip_longest

from flask import Flask
from dash import Dash, html, dcc, Output, Input
import dash_bootstrap_components as dbc
import plotly.graph_objects as go

from .util import make_icon, DashComponent, IconSize
from autonomous_trust.services.peer.position import GeoPosition
from ..peer.daq import PeerDataAcq
from .dynamic_map import DynamicMap
from .video_feed import VideoFeed
from .data_feed import DataFeed


class PeerStatus(DashComponent):
    count = 0
    icon_height = 40

    def __init__(self, app: Dash, server: Flask, peer: PeerDataAcq, mapp: DynamicMap, icons: dict[str, str]):
        super().__init__(app, server)
        self.peer = peer
        self.idx = int(PeerStatus.count)
        PeerStatus.count += 1
        self.vid_feed = VideoFeed(self.app, self.server, peer, self.count)
        self.data_feed = DataFeed(self.app, self.server, peer, self.count)
        self.data_type = peer.metadata.data_type
        self.icon_map = icons

        self.net_figs = {}
        self.trust_figs = {}
        self.fig = go.Figure()
        xes, yes = self.update_summary()
        self.fig.add_trace(go.Scatter(x=xes, y=yes))
        self.fig.layout = go.Layout(showlegend=False, autosize=False, hovermode='closest',
                                    xaxis=dict(showgrid=False, showline=False, showticklabels=False, zeroline=False),
                                    yaxis=dict(showgrid=False, showline=False, showticklabels=False, zeroline=False),
                                    margin=dict(l=0, r=0, t=0, b=0),
                                    paper_bgcolor='rgba(0,0,0,0)',
                                    plot_bgcolor='rgba(0,0,0,0)')

        @self.app.callback(Output('micrograph-%d' % self.idx, 'figure'),
                           Input('interval', 'n_intervals'))
        def update_micrograph(_):
            x_vals, y_vals = self.update_summary()
            self.fig.update_traces(go.Scatter(x=x_vals, y=y_vals), overwrite=True)
            return self.fig

        @self.app.callback(Output('follow-target-%d' % self.idx, 'children'),
                           [Input('follow-btn-%d' % self.idx, 'n_clicks')])
        def follow_unit(_):
            mapp.following = self.peer.uuid
            return html.Div()

        for idx, other in enumerate(self.peer.others):
            fig = go.Figure()
            xes, yes = self.update_net(other)
            fig.add_trace(go.Scatter(x=xes, y=yes, name='net-fig-%d' % idx))
            self.net_figs[idx] = fig
            gauge = go.Figure()
            gauge.add_trace(go.Indicator(mode="gauge+number",
                                         domain={'x': [0, 1], 'y': [0, 1]},
                                         title={'text': "Trust level"},
                                         gauge={'axis': {'range': [None, 500]},
                                                'bar': {'color': "royalblue"},
                                                'steps': [
                                                    {'range': [0, 45], 'color': "red"},
                                                    {'range': [55, 65], 'color': "yellow"},
                                                    {'range': [65, 100], 'color': "green"}],
                                                'threshold': {'line': {'color': "white", 'width': 4},
                                                              'thickness': 0.75,
                                                              'value': 50}},
                                         name='trust-gauge-%d' % idx,
                                         value=0.))
            self.trust_figs[idx] = gauge

            @self.app.callback(Output('trust-%d-%d' % (self.idx, idx), 'children'),
                               Input('status-interval', 'n_intervals'))
            def update_trust_levels(_):
                trust_gauge = self.trust_figs[idx]
                trust_gauge.update_traces(selector=dict(name='trust-gauge-%d' % idx),
                                          value=self.peer.reputation, overwrite=True)
                return trust_gauge

            @self.app.callback(Output('net_graph-%d-%d' % (self.idx, idx), 'figure'),
                               Input('status-interval', 'n_intervals'))
            def update_net_graph(_):
                net_fig = self.net_figs[idx]
                x_vals, y_vals = self.update_net(other)
                net_fig.update_traces(selector=dict(name='net-fig-%d' % idx), x=x_vals, y=y_vals, overwrite=True)
                return net_fig

    def update_summary(self):
        xes = list(range(1, len(self.peer.network_history)))
        rev = [sub[::-1] for sub in self.peer.network_history.values()]
        yes = [sum(i) for i in zip_longest(*rev, fillvalue=0)][::-1]
        return xes, yes

    def update_net(self, other):
        xes = list(range(len(self.peer.network_history[other.uuid])))
        yes = self.peer.network_history[other.uuid]
        return xes, yes

    def div(self, width: int = 10, glance: bool = False):
        if glance:
            return html.Div([
                html.Div(id='follow-target-%d' % self.idx),
                dbc.Row([
                    dbc.Col([
                        dbc.Stack([
                            dbc.Button(
                                make_icon(self.icon_map[self.peer.kind], self.peer.kind.capitalize(),
                                          size=IconSize.SMALL),
                                id='follow-btn-%d' % self.idx, color='light'),
                            dcc.Graph(id='micrograph-%d' % self.idx, config=dict(displayModeBar=False),
                                      style=dict(width='65%', height=60)),
                            html.A(
                                dbc.Button(
                                    make_icon('carbon:overflow-menu-vertical',
                                              size=IconSize.SMALL),
                                    id='more-btn-%d' % self.idx, n_clicks=0, color='rgba(0,0,0,0)'),
                                href='/peer_status_%d' % self.idx, target="_blank"),
                        ], gap=2, direction="horizontal"),
                    ]),
                ]),
                dbc.Row([
                    dbc.Col([
                        html.Div([self.peer.uuid], style={'font-size': 'x-small', 'width': '100%'}),
                    ])
                ]),
                html.Hr(style=dict(margin='0 0 0 0', padding='0 0 0 0', width='95%')),
            ])

        # otherwise, content of the modal
        pos = self.peer.position.convert(GeoPosition)
        trust_levels = []
        network = []
        for idx, other in enumerate(self.peer.others):
            trust_levels.append(dbc.Col([html.Div(id='trust-%d-%d' % (self.idx, idx))]))
            network.append(dbc.Col([dcc.Graph(id='net-graph-%d-%d' % (self.idx, idx))]))

        return html.Div([
            dcc.Interval(id='status-interval', interval=1000, n_intervals=0),
            html.Div([
                dbc.Container([
                    dbc.Row([
                        dbc.Col(['%s (%s) - %s' % (self.peer.name, self.peer.nickname, self.peer.uuid)]),
                    ]),
                    dbc.Row([
                        dbc.Col(self.vid_feed.div("%f m above %f, %f" % (pos.alt, pos.lat, pos.lon))),
                    ]),
                    dbc.Row([
                        dbc.Col(self.data_feed.div("%s data" % self.data_type)),
                    ]),
                    dbc.Row(trust_levels),
                    dbc.Row(network),
                ]),
            ], id='status-modal-%d' % self.idx),
        ])
