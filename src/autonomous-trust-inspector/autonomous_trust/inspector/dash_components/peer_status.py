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


# Communication cut-off (default 0.1), synced to the reputation backend via
# the shared AT_REP_COMM_CUTOFF override so the trust gauge's red/excluded
# band matches a re-adjusted deployment.
try:
    _COMM_CUTOFF = float(os.environ.get('AT_REP_COMM_CUTOFF', '') or 0.1)
except (TypeError, ValueError):
    _COMM_CUTOFF = 0.1


class PeerStatus(DashComponent):
    _count = 0
    icon_height = 40

    @classmethod
    def reset_count(cls):
        """Reset the instance counter (e.g. between test runs or layout rebuilds)."""
        cls._count = 0

    def __init__(self, ctl: DashControl, peer: PeerDataAcq, cohort: CohortInterface, mapp: DynamicMap,
                 parent: Any, icons: dict[str, str]):
        super().__init__(ctl.app)
        self.ctl = ctl
        self.peer = peer
        self.cohort = cohort
        self.icon_map = icons
        self.parent = parent

        self.idx = int(PeerStatus._count)
        PeerStatus._count += 1
        self.peer_detail_id = f'peer_status_{self.idx}'

        # Accepted design (2026-08-12), for the same reason as the panel note
        # below: VideoFeed is always instantiated regardless of whether the peer's
        # metadata declares a video source — which it cannot at this point anyway,
        # since a peer is rostered holding `NullPeerData`. The widget renders empty
        # when there is no stream, and the layout slot is reserved at construct
        # time because the Dash layout tree cannot grow components after page load.
        self.vid_feed = VideoFeed(self.ctl, peer, self.idx)
        self.data_feed = DataFeed(self.ctl, peer, self.idx)

        self.net_figs = {}
        self.trust_figs = {}
        # Is this peer's detail drawer on screen, and how many `others` the
        # rendered body was built for. Both are needed because the per-other
        # subplots are pushed by id: pushing a figure cannot populate a div that
        # is not in the DOM, so a peer discovered after the drawer opened needs
        # the body rebuilt rather than a figure update. Kept HERE rather than on
        # the parent: the component already learns its own open/closed state
        # from its own callback. The previously-intended
        # `parent.displayed_detail` does exist on `MapDisplay` (initialised to -1)
        # but is never read or written anywhere else, so the old guard would have
        # compared -1 to an index forever: a silent no-op, not a crash.
        self._detail_open = False
        self._rendered_others = 0
        # Caption text last delivered to the browser, per div id, so an unchanged
        # caption costs no message. Seeded by full_div, which renders the same
        # text through the same helpers.
        self._pushed_titles: dict[str, str] = {}
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
        self.cohort.register_updater(self.update_detail_titles)
        self.cohort.register_updater(self.update_data_feed)

        # ACCEPTED DESIGN (decided 2026-08-12), not a deferral: every peer's
        # detail panel is pre-created at page load, and that is where it stays.
        # Dash freezes the layout tree at load and Flask freezes the route table
        # at app.run(), so panels created on demand would need either dynamic
        # blueprint registration or panel bodies driven entirely from pushed
        # children — significant wiring to remove a constraint nothing is
        # currently hitting, since the pool is sized to MAX_PEERS at startup.
        # Per-peer state IS fully recorded (roster, metadata, stats, reputation,
        # sensor series), so any number of open drawers render independently;
        # what is static is the set of containers, not the data behind them.
        # Pairs with the VideoFeed slot-reservation note above.

        @ctl.callback(Output(f'offcanvas-{self.idx}', 'is_open'),
                      Input(f'more-btn-{self.idx}', "n_clicks"),
                      State(f'offcanvas-{self.idx}', 'is_open'))
        def toggle_peer_detail(clicks, is_open):
            if clicks > 0:
                # `not is_open` is where the drawer is HEADED. The old code
                # pushed a rebuilt body and set active=True on every click,
                # including the closing one, so a peer stayed active — and its
                # video feed kept streaming — for a drawer nobody was looking at.
                return self.set_detail_open(not is_open)
            self.set_detail_open(False)
            return is_open

        @ctl.callback(Output(f'follow-target-{self.idx}', 'children'),
                      Input(f'follow-btn-{self.idx}', 'n_clicks'))
        def follow_unit(_):
            mapp.following = self.peer.uuid
            return html.Div()

        #  end __init__

    def populate(self):
        for idx, other in enumerate(self.peer.others):
            self.add_net_graph(idx, other)
            self.add_trust_gauge(idx)

    def set_detail_open(self, is_open: bool) -> bool:
        """Record that this peer's detail drawer opened or closed, and push a
        fresh body when it opens. Returns the new state, so the Dash callback
        can return it directly.

        `peer.active` follows the drawer because it gates VideoFeed.xmit/rcv:
        a closed drawer must stop the feed, not keep decoding frames for nobody.
        """
        self._detail_open = bool(is_open)
        self.peer.active = bool(is_open)
        if is_open:
            self.ctl.push_mods({f'peer-detail-{self.idx}': {'children': self.full_div()}})
        return self._detail_open

    def _detail_visible(self) -> bool:
        """Whether a push would actually land somewhere a user can see.

        Both halves matter: with no browser attached there is nobody to push to,
        and with the drawer closed the target divs are hidden — pushing a figure
        per other per tick for every peer's closed drawer is the cost this guard
        exists to avoid."""
        return bool(self._detail_open and self.cohort.browser_connected)

    def _resync_detail_body(self) -> bool:
        """Rebuild the detail body when the set of others changed since it was
        rendered, and report whether it did.

        The per-other subplot ids are positional (`trust-<peer>-<n>`), so a newly
        discovered peer has no div to push a figure into; only a rebuilt body
        creates one. The rebuild already carries current figures, so a caller
        that rebuilt should skip its own figure pushes for this tick."""
        if len(self.peer.network_history) == self._rendered_others:
            return False
        self.ctl.push_mods({f'peer-detail-{self.idx}': {'children': self.full_div()}})
        return True

    @property
    def data_type(self):
        """Read live, never captured. A peer is rostered with `NullPeerData`
        (empty `data_type`) and its real metadata arrives later as a `meta`
        delta, so a value copied in `__init__` is the placeholder for the life of
        the component -- the caption read ' data' no matter what the peer sent."""
        return self.peer.metadata.data_type

    def _position_text(self) -> str:
        """The video panel's caption: where this peer is, as of right now.

        Shared with `update_detail_titles` so pushed text cannot drift from
        rendered text.
        """
        try:
            pos = self.peer.position.convert(GeoPosition)
            return f'{pos.alt:f} m above {pos.lat:f}, {pos.lon:f}'
        except (NotImplementedError, AttributeError, TypeError, ValueError):
            # NotImplementedError is the LIVE case, not a defensive nicety: a
            # peer is rostered with `NullPeerData`, whose bare `Position` cannot
            # convert, so opening the drawer before that peer's metadata arrived
            # raised inside the Dash callback and built no body at all.
            # The text says which of the two it is -- a peer that has not
            # reported is a normal early state, not a fault (and 0, 0 would be a
            # lie the operator cannot tell from a real fix off Africa).
            return 'position not yet reported'

    def _data_title(self) -> str:
        if not self.data_type:
            # Distinguishes 'this peer has not said yet' from a type named ''.
            return 'data type not yet reported'
        return f'{self.data_type} data'

    def update_detail_titles(self):
        """Push the drawer's live captions.

        The position under the video feed was rendered once, when the body was
        built, and never updated again, so a moving peer's open drawer kept
        showing where it was when the drawer opened. The data caption was worse:
        it was built from a `data_type` copied before any metadata delta had
        arrived, so it stayed empty for good.

        Only changed text is pushed -- a stationary peer costs nothing, and a
        caption is not worth a message per tick when it did not move.
        """
        if not self._detail_visible():
            return
        for div_id, text in ((self.vid_feed.title_id, self._position_text()),
                             (self.data_feed.title_id, self._data_title())):
            if self._pushed_titles.get(div_id) == text:
                continue
            self._pushed_titles[div_id] = text
            self.ctl.push_mods({div_id: {'children': text}})

    def update_data_feed(self):
        """Record this peer's sensor samples, and render them when watched.

        The drain is unconditional: nothing else consumes `peer.data_stream`, so
        skipping it while the drawer is closed would both lose the history the
        drawer exists to show and let an unbounded pooled Queue grow for as long
        as the peer keeps reporting. Only the PUSH is guarded.
        """
        changed = self.data_feed.drain()
        if changed and self._detail_visible():
            self.ctl.push_mods({self.data_feed.graph_id:
                                {'figure': self.data_feed.fig.to_dict()}})

    def add_trust_gauge(self, idx):
        if idx in self.trust_figs:
            return self.trust_figs[idx]
        gauge = go.Figure()
        # Reputation is on the [0, 1] scale; the gauge value is that
        # reputation directly (see update_trust_levels). Bands: red below
        # the 0.1 communication cut-off (excluded from the network),
        # amber in the low/degraded 0.1–0.5 band, green above the 0.5
        # tier-1 trust floor. The white threshold marker sits on the 0.1
        # cut-off so an excluded peer reads at a glance.
        gauge.add_trace(go.Indicator(mode="gauge+number",
                                     domain={'x': [0, 1], 'y': [0, 1]},
                                     title={'text': "Trust level"},
                                     number={'valueformat': '.2f'},
                                     gauge={'axis': {'range': [0, 1]},
                                            'bar': {'color': "royalblue"},
                                            'steps': [
                                                {'range': [0, _COMM_CUTOFF], 'color': "red"},
                                                {'range': [_COMM_CUTOFF, 0.5], 'color': "orange"},
                                                {'range': [0.5, 1], 'color': "green"}],
                                            'threshold': {'line': {'color': "white", 'width': 4},
                                                          'thickness': 0.75,
                                                          'value': _COMM_CUTOFF}},
                                     name=f'trust-gauge-{idx}',
                                     value=0.))
        self.trust_figs[idx] = gauge
        return gauge

    def add_net_graph(self, idx, other):
        if idx in self.net_figs:
            return self.net_figs[idx]
        fig = go.Figure()
        xes, yes = self.update_net(other)
        fig.add_trace(go.Scatter(x=xes, y=yes, name=f'net-fig-{idx}'))
        self.net_figs[idx] = fig
        return fig

    def update_micrograph(self):
        div_id = f'micrograph-{self.idx}'
        x_vals, y1_vals, y2_vals, y3_vals = self.update_summary()
        self.fig.update_traces(selector=dict(name='network-up'), x=x_vals, y=y1_vals, overwrite=True)
        self.fig.update_traces(selector=dict(name='network-dn'), x=x_vals, y=y2_vals, overwrite=True)
        self.fig.update_traces(selector=dict(name='reputation'), x=x_vals, y=y3_vals, overwrite=True)
        if self.cohort.browser_connected and self.peer.uuid in self.parent.status.keys():
            self.ctl.push_mods({div_id: {'figure': self.fig.to_dict()}})

    def update_trust_levels(self):
        rebuilt = self._resync_detail_body() if self._detail_visible() else False
        for idx, other in enumerate(self.peer.others):
            div_id = f'trust-{self.idx}-{idx}'
            try:
                trust_gauge = self.trust_figs[idx]
            except KeyError:
                trust_gauge = self.add_trust_gauge(idx)
            # Per-other (transitive) trust when available: this
            # peer's own reputation of `other`, keyed by uuid. Falls back to the
            # aggregate reputation stand-in when no per-other view has arrived.
            rep = self.peer.reputation_of(other)
            if rep is None:
                rep = self.peer.reputation_history[-1] if self.peer.reputation_history else 0.0
            trust_gauge.update_traces(selector=dict(name=f'trust-gauge-{idx}'),
                                      value=rep, overwrite=True)
            # The wire-up that was missing: the figure was updated here
            # every tick, but nothing told the browser, so an open drawer showed
            # whatever the figure held when it opened — permanently empty if it
            # opened before any data arrived.
            if not rebuilt and self._detail_visible() and idx < self._rendered_others:
                self.ctl.push_mods({div_id: {'figure': trust_gauge.to_dict()}})

    def update_net_graphs(self):
        rebuilt = self._resync_detail_body() if self._detail_visible() else False
        for idx, other in enumerate(self.peer.others):
            div_id = f'net-graph-{self.idx}-{idx}'
            try:
                net_fig = self.net_figs[idx]
            except KeyError:
                net_fig = self.add_net_graph(idx, other)
            x_vals, y_vals = self.update_net(other)
            net_fig.update_traces(selector=dict(name=f'net-fig-{idx}'), x=x_vals, y=y_vals, overwrite=True)
            if not rebuilt and self._detail_visible() and idx < self._rendered_others:
                self.ctl.push_mods({div_id: {'figure': net_fig.to_dict()}})

    def update_summary(self):
        net_history = self.peer.network_history
        rev1 = [list(map(lambda x: x.up, list(sub)))[::-1] for sub in net_history.values()]
        y1s = [sum(i) for i in zip_longest(*rev1, fillvalue=0)][::-1]
        rev2 = [list(map(lambda x: x.down, list(sub)))[::-1] for sub in net_history.values()]
        y2s = [sum(i) for i in zip_longest(*rev2, fillvalue=0)][::-1]
        # +1: plotly pairs x[i] with y[i] and drops the tail of the longer
        # series, so an x one short of y silently hid the NEWEST sample --
        # exactly the one the micrograph exists to show. Matches update_net's
        # convention below.
        xes = list(range(1, len(y1s) + 1))
        y3s = list(self.peer.reputation_history)
        return xes, y1s, y2s, y3s

    def update_net(self, other):
        net_history: list = list(self.peer.network_history[other])  # list[NetworkStats]
        yes = [stats.sent for stats in net_history]
        xes = list(range(1, len(yes) + 1))
        return xes, yes

    def peer_details(self):
        return dbc.Offcanvas(html.Div([self.full_div()], id=f'peer-detail-{self.idx}'),
                             id=f'offcanvas-{self.idx}',
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
            html.Div(id=f'follow-target-{self.idx}'),  # dummy for callback output
            dbc.Row([
                dbc.Col([
                    dbc.Stack([
                        dbc.Button(
                            make_icon(self.icon_map[self.peer.kind], self.peer.kind.capitalize(),
                                      size=IconSize.SMALL),
                            title=self.peer.nickname,
                            id=f'follow-btn-{self.idx}', color='light'),
                        dcc.Graph(id=f'micrograph-{self.idx}', figure=self.fig,
                                  config=dict(displayModeBar=False),
                                  style=dict(width=self.micro_width, height=self.micro_height)),
                        dbc.Button(
                            make_icon('carbon:overflow-menu-vertical',
                                      size=IconSize.SMALL),
                            id=f'more-btn-{self.idx}', n_clicks=0, color='rgba(0,0,0,0)'),
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
        trust_levels = []
        network = []
        self.populate()  # in case it isn't
        # The shape this body is being built for. _resync_detail_body compares
        # against it to notice a peer discovered while the drawer is open, whose
        # subplot divs do not exist yet.
        self._rendered_others = len(self.peer.network_history)
        for idx, other in enumerate(self.peer.others):
            trust_levels.append(dbc.Col([dcc.Graph(id=f'trust-{self.idx}-{idx}',
                                                   figure=self.trust_figs[idx],
                                                   config=dict(displayModeBar=False),
                                                   style=dict(width=self.micro_width, height=self.micro_height)
                                                   )]))
            network.append(dbc.Col([dcc.Graph(id=f'net-graph-{self.idx}-{idx}',
                                              figure=self.net_figs[idx],
                                              config=dict(displayModeBar=False),
                                              style=dict(width=self.micro_width, height=self.micro_height)
                                              )]))
        #print(f'Trust {len(trust_levels)}')
        #print(f'Net {len(trust_levels)}')

        # The captions this body carries to the browser. Recording them keeps
        # update_detail_titles from re-pushing text the client already has, and
        # keeps the cache honest across a rebuild (which replaces the elements).
        position_text = self._position_text()
        data_title = self._data_title()
        self._pushed_titles = {self.vid_feed.title_id: position_text,
                               self.data_feed.title_id: data_title}

        return html.Div([
            html.Div(id=f'peer-details-target-{self.idx}', style={'display': 'none'}),
            html.Div([
                dbc.Container([
                    dbc.Row([
                        dbc.Col([f'{self.peer.name} ({self.peer.nickname}) - {self.peer.uuid}']),
                    ]),
                    dbc.Row([
                        # The caption is live: `update_detail_titles` pushes it
                        # into `vid_feed.title_id` while the drawer is open, so a
                        # moving peer's position tracks instead of freezing at
                        # whatever it was when the body was built.
                        dbc.Col(self.vid_feed.div(position_text)),
                    ]),
                    dbc.Row([
                        dbc.Col(self.data_feed.div(data_title)),
                    ]),
                    dbc.Row(trust_levels),
                    dbc.Row(network),
                ]),
            ]),
        ])
