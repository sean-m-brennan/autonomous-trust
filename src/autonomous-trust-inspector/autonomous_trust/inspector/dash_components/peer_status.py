import random
from itertools import zip_longest
from typing import Any

import dash_bootstrap_components as dbc
import plotly.graph_objects as go

from autonomous_trust.services.peer.position import GeoPosition
from .core import DashControl, DashComponent, html, dcc, Output, Input, State, ctx
from .core import make_icon, IconSize
from ..peer.daq import PeerDataAcq, CohortInterface
from .dynamic_map import DynamicMap
from .video_feed import VideoFeed
from .data_feed import DataFeed


class PeerStatus(DashComponent):
    count = 0
    icon_height = 40

    def __init__(self, ctl: DashControl, peer: PeerDataAcq, cohort: CohortInterface, mapp: DynamicMap,
                 parent: Any, icons: dict[str, str]):
        super().__init__(ctl.app)
        self.ctl = ctl
        self.peer = peer
        self.cohort = cohort
        self.icon_map = icons
        self.parent = parent

        self.idx = int(PeerStatus.count)
        PeerStatus.count += 1
        self.peer_detail_id = 'peer_status_%d' % self.idx

        # FIXME dependent on 'video' in peer.metadata
        self.vid_feed = VideoFeed(self.ctl, self.server, peer, self.idx)
        self.data_feed = DataFeed(self.ctl, self.server, peer, self.idx)
        self.data_type = peer.metadata.data_type

        self.net_figs = {}
        self.trust_figs = {}
        self.fig = go.Figure()
        xes, y1s, y2s, y3s = self.update_summary()
        self.micro_width = 250
        self.micro_height = 60
        self.fig.add_trace(go.Scatter(x=xes, y=y1s, name='network-up', yaxis='y1', marker=dict(size=1)))
        self.fig.add_trace(go.Scatter(x=xes, y=y2s, name='network-dn', yaxis='y2', marker=dict(size=1)))
        self.fig.add_trace(
            go.Scatter(x=xes, y=y3s, name='reputation', yaxis='y3', marker=dict(size=1), line=dict(color='green')))
        self.fig.layout = go.Layout(showlegend=False, autosize=False, hovermode='closest',
                                    xaxis=dict(showgrid=False, showline=False, showticklabels=False, zeroline=False),
                                    yaxis=dict(showgrid=False, showline=False, showticklabels=False, zeroline=False),
                                    yaxis2=dict(showgrid=False, showline=False, showticklabels=False, zeroline=False),
                                    yaxis3=dict(showgrid=False, showline=False, showticklabels=False, zeroline=False,
                                                range=[0, 1]),
                                    margin=dict(l=0, r=0, t=0, b=0),
                                    width=self.micro_width, height=self.micro_height,
                                    paper_bgcolor='rgba(0,0,0,0)',
                                    plot_bgcolor='rgba(0,0,0,0)')

        self.populate()

        self.cohort.register_updater(self.update_micrograph)
        self.cohort.register_updater(self.update_trust_levels)
        self.cohort.register_updater(self.update_net_graphs)

        # FIXME must record all data, render is fully dynamic - only one at a time

        @ctl.callback(Output('offcanvas-%d' % self.idx, 'is_open'),
                      Input('more-btn-%d' % self.idx, "n_clicks"),
                      State('offcanvas-%d' % self.idx, 'is_open'))
        def toggle_peer_detail(clicks, is_open):
            if clicks > 0:
                ctl.push_mods({'peer-detail-%d' % self.idx: {'children': self.full_div()}})
                return not is_open
            return is_open

        @ctl.callback(Output('follow-target-%d' % self.idx, 'children'),
                      Input('follow-btn-%d' % self.idx, 'n_clicks'))
        def follow_unit(_):
            mapp.following = self.peer.uuid
            return html.Div()

        #  end __init__

    def populate(self):
        for idx, other in enumerate(self.peer.others):
            self.add_net_graph(idx, other)
            self.add_trust_gauge(idx)

    def add_trust_gauge(self, idx):
        if idx in self.trust_figs:
            return self.trust_figs[idx]
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
        return gauge

    def add_net_graph(self, idx, other):
        if idx in self.net_figs:
            return self.net_figs[idx]
        fig = go.Figure()
        xes, yes = self.update_net(other)
        fig.add_trace(go.Scatter(x=xes, y=yes, name='net-fig-%d' % idx))
        self.net_figs[idx] = fig
        return fig

    def update_micrograph(self):
        div_id = 'micrograph-%d' % self.idx
        x_vals, y1_vals, y2_vals, y3_vals = self.update_summary()
        self.fig.update_traces(selector=dict(name='network-up'), x=x_vals, y=y1_vals, overwrite=True)
        self.fig.update_traces(selector=dict(name='network-dn'), x=x_vals, y=y2_vals, overwrite=True)
        self.fig.update_traces(selector=dict(name='reputation'), x=x_vals, y=y3_vals, overwrite=True)
        if self.cohort.browser_connected and self.peer.uuid in self.parent.status.keys():
            self.ctl.push_mods({div_id: {'figure': self.fig.to_dict()}})

    def update_trust_levels(self):
        for idx, other in enumerate(self.peer.others):
            div_id = 'trust-%d-%d' % (self.idx, idx)
            try:
                trust_gauge = self.trust_figs[idx]
            except KeyError:
                trust_gauge = self.add_trust_gauge(idx)
            rep = self.peer.reputation_history[-1]
            rep = random.random()  # FIXME
            trust_gauge.update_traces(selector=dict(name='trust-gauge-%d' % idx),
                                      value=rep, overwrite=True)  # FIXME per-other rep (with idx)
            #if self.parent.displayed_detail == self.idx:
            #    self.ctl.push_mods({div_id: {'figure': trust_gauge.to_dict()}})

    def update_net_graphs(self):
        for idx, other in enumerate(self.peer.others):
            div_id = 'net-graph-%d-%d' % (self.idx, idx)
            try:
                net_fig = self.net_figs[idx]
            except KeyError:
                net_fig = self.add_net_graph(idx, other)
            x_vals, y_vals = self.update_net(other)
            net_fig.update_traces(selector=dict(name='net-fig-%d' % idx), x=x_vals, y=y_vals, overwrite=True)
            #if self.parent.displayed_detail == self.idx:
            #    self.ctl.push_mods({div_id: {'figure': net_fig.to_dict()}})

    def update_summary(self):
        net_history = self.peer.network_history
        rev1 = [list(map(lambda x: x.up, list(sub)))[::-1] for sub in net_history.values()]
        y1s = [sum(i) for i in zip_longest(*rev1, fillvalue=0)][::-1]
        rev2 = [list(map(lambda x: x.down, list(sub)))[::-1] for sub in net_history.values()]
        y2s = [sum(i) for i in zip_longest(*rev2, fillvalue=0)][::-1]
        xes = list(range(1, len(y1s)))
        y3s = list(self.peer.reputation_history)
        return xes, y1s, y2s, y3s

    def update_net(self, other):  # FIXME as NetworkStats objects
        net_history = list(self.peer.network_history[other])
        yes = list(map(lambda x: x.sent, net_history))
        xes = list(range(1, len(yes)))
        return xes, yes

    def peer_details(self):
        return dbc.Offcanvas(html.Div([self.full_div()], id='peer-detail-%d' % self.idx),
                             id='offcanvas-%d' % self.idx,
                             is_open=False,
                             style=dict(width='75%'))

    def div(self, glance: bool = False, active: bool = False):
        if glance:
            return self.glance_div(active)
        return self.full_div()

    def glance_div(self, active: bool = False):
        font_size_elt = 'font-size'
        if self.uses_react:
            font_size_elt = 'fontSize'
        display = dict(display='none', visibility='hidden')
        if active:
            display = dict(display='block', visibility='visible')
        return html.Div([
            html.Div(id='follow-target-%d' % self.idx),  # dummy for callback output
            dbc.Row([
                dbc.Col([
                    dbc.Stack([
                        dbc.Button(
                            make_icon(self.icon_map[self.peer.kind], self.peer.kind.capitalize(),
                                      size=IconSize.SMALL),
                            title=self.peer.nickname,
                            id='follow-btn-%d' % self.idx, color='light'),
                        dcc.Graph(id='micrograph-%d' % self.idx, figure=self.fig,
                                  config=dict(displayModeBar=False),
                                  style=dict(width=self.micro_width, height=self.micro_height)),
                        dbc.Button(
                            make_icon('carbon:overflow-menu-vertical',
                                      size=IconSize.SMALL),
                            id='more-btn-%d' % self.idx, n_clicks=0, color='rgba(0,0,0,0)'),
                    ], gap=2, direction="horizontal"),
                ]),
            ]),
            dbc.Row([
                dbc.Col([
                    html.Div([self.peer.uuid], style={font_size_elt: 'x-small', 'width': '100%'}),
                ])
            ]),
            html.Hr(style=dict(margin='0 0 0 0', padding='0 0 0 0', width='95%')),
        ], id=self.peer_detail_id, style=display,
        )

    def full_div(self):
        pos = self.peer.position.convert(GeoPosition)
        trust_levels = []
        network = []
        self.populate()  # in case it isn't
        #print('Num other peers %d' % len(self.peer.others))  # Updating too fast?
        for idx, other in enumerate(self.peer.others):
            # FIXME still not populating
            trust_levels.append(dbc.Col([dcc.Graph(id='trust-%d-%d' % (self.idx, idx),
                                                   figure=self.trust_figs[idx],
                                                   config=dict(displayModeBar=False),
                                                   style=dict(width=self.micro_width, height=self.micro_height)
                                                   )]))
            network.append(dbc.Col([dcc.Graph(id='net-graph-%d-%d' % (self.idx, idx),
                                              figure=self.net_figs[idx],
                                              config=dict(displayModeBar=False),
                                              style=dict(width=self.micro_width, height=self.micro_height)
                                              )]))
        #print('Trust %d' % len(trust_levels))
        #print('Net %d' % len(trust_levels))

        return html.Div([
            html.Div(id='peer-details-target-%d' % self.idx, style={'display': 'none'}),
            html.Div([
                dbc.Container([
                    dbc.Row([
                        dbc.Col(['%s (%s) - %s' % (self.peer.name, self.peer.nickname, self.peer.uuid)]),
                    ]),
                    dbc.Row([
                        # FIXME modification
                        dbc.Col(self.vid_feed.div("%f m above %f, %f" % (pos.alt, pos.lat, pos.lon))),
                    ]),
                    dbc.Row([
                        dbc.Col(self.data_feed.div("%s data" % self.data_type)),
                    ]),
                    dbc.Row(trust_levels),
                    dbc.Row(network),
                ]),
            ]),
        ])
