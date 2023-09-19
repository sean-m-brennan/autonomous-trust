import threading
from itertools import zip_longest

from flask import Flask
from dash import Dash, html, dcc, Output, Input
import dash_bootstrap_components as dbc
import plotly.graph_objects as go

from ...dash_components.util import make_icon, DashComponent, IconSize
from ...video.dash_components import VideoFeed
from ..position import GeoPosition
from ..daq import PeerDataAcq
from .dynamic_map import DynamicMap


class PeerStatus(DashComponent):
    count = 0
    icon_map = {'microdrone': 'carbon:drone',
                'soldier': 'healthicons: military-worker',
                'jet': 'fa-solid: fighter-jet',
                'recon': 'mdi:drone',
                'base': 'military-camp',
                }
    icon_height = 40

    def __init__(self, app: Dash, server: Flask, peer: PeerDataAcq, mapp: DynamicMap):
        super().__init__(app, server)
        self.peer = peer
        self.feed = VideoFeed(self.app, self.server, self.count + 1)
        self.idx = int(PeerStatus.count)
        PeerStatus.count += 1

        self.fig = go.Figure()
        xes, yes = self.update_summary()
        self.fig.add_trace(go.Scatter(x=xes, y=yes))
        self.fig.layout = go.Layout(showlegend=False, autosize=False, hovermode='closest',
                                    xaxis=dict(showgrid=False, showline=False, showticklabels=False, zeroline=False),
                                    yaxis=dict(showgrid=False, showline=False, showticklabels=False, zeroline=False),
                                    margin=dict(l=0, r=0, t=0, b=0),
                                    paper_bgcolor='rgba(0,0,0,0)',
                                    plot_bgcolor='rgba(0,0,0,0)')
        self.status_open = False

        @self.app.callback(Output('micrograph-%d' % self.idx, 'figure'),
                           Input('interval', 'n_intervals'))
        def update_micrograph(_):
            x_vals, y_vals = self.update_summary()
            self.fig.update_traces(go.Scatter(x=x_vals, y=y_vals), overwrite=True)
            return self.fig

        self.net_figs = {}
        for idx, other in enumerate(self.peer.others):
            fig = go.Figure()
            self.net_figs[idx] = fig
            xes, yes = self.update_net(other)
            fig.add_trace(go.Scatter(x=xes, y=yes))

            @self.app.callback(Output('trust-%d-%d' % (self.idx, idx), 'children'),
                               Input('interval', 'n_intervals'))
            def update_trust_levels(_):
                # FIXME gauges?
                trust = self.peer.trust_matrix()
                return trust.get(other, 0)

            @self.app.callback(Output('net_graph-%d-%d' % (self.idx, idx), 'figure'),
                               Input('interval', 'n_intervals'))
            def update_net_graph(_):
                net_fig = self.net_figs[idx]
                x_vals, y_vals = self.update_net(other)
                net_fig.update_traces(go.Scatter(x=x_vals, y=y_vals), overwrite=True)
                return net_fig

        @self.app.callback(Output('status-modal-%d' % self.idx, 'is_open'),
                           [Input('more-btn-%d' % self.idx, 'n_clicks')])
        def open_status(more):
            if more:
                self.status_open = not self.status_open
                if self.status_open:
                    mapp.update_display = False
                else:
                    mapp.update_display = True  # FIXME enable on closed
            return self.status_open

        @self.app.callback(Output('follow-target-%d' % self.idx, 'children'),
                           [Input('follow-btn-%d' % self.idx, 'n_clicks')])
        def follow_unit(_):
            mapp.following = self.peer.uuid
            return html.Div()

        self.thread = threading.Thread(target=self.feed.run, args=('localhost', 9990 + self.feed.index),
                                       kwargs={'encode': True})
        self.thread.start()
        # atexit.register(self.interrupt)  # FIXME breaks

    def update_summary(self):
        xes = list(range(1, len(self.peer.network_history)))
        rev = [sub[::-1] for sub in self.peer.network_history.values()]
        yes = [sum(i) for i in zip_longest(*rev, fillvalue=0)][::-1]
        return xes, yes

    def update_net(self, other):
        xes = list(range(len(self.peer.network_history[other.uuid])))
        yes = self.peer.network_history[other.uuid]
        return xes, yes

    def interrupt(self):
        self.feed.halt = True
        self.thread.join()

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
                            dbc.Button(
                                make_icon('carbon:overflow-menu-vertical',
                                          size=IconSize.SMALL),
                                id='more-btn-%d' % self.idx, n_clicks=0, color='rgba(0,0,0,0)')
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
            dbc.Modal([
                dbc.ModalHeader(dbc.ModalTitle('%s #%s' % (self.peer.kind, self.feed.number))),
                dbc.ModalBody([
                    dbc.Row([
                        dbc.Col(['%s (%s) - %s' % (self.peer.name, self.peer.nickname, self.peer.uuid)]),
                    ]),
                    dbc.Row([
                        # FIXME video feed through (trusted) PeerDaq instead
                        dbc.Col(self.feed.div("%f m above %f, %f" % (pos.alt, pos.lat, pos.lon))),
                    ]),
                    dbc.Row([
                        # FIXME data feed ??
                    ]),
                    dbc.Row(trust_levels),
                    dbc.Row(network),
                ]),
                dbc.ModalFooter(),
            ], id='status-modal-%d' % self.idx,
                keyboard=False, backdrop="static",
                fullscreen='md-down',
                size='xl',
                is_open=False),
        ])
