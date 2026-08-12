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

from collections import deque
from queue import Empty

from plotly import graph_objects as go

from .core import DashComponent, html, dcc, DashControl
from ..peer.daq import PeerDataAcq, stream_take


class DataFeed(DashComponent):
    """The per-peer sensor plot in the detail drawer.

    Driven by the cohort tick (`PeerStatus.update_data_feed`), not by a thread of
    its own: the old `rcv()` loop was never started by anything -- no route, no
    thread, no caller -- so the peer's data stream was never drained and the plot
    never held a sample. Ticking it also closes a leak, since `data_stream` is an
    unbounded pooled Queue that the receiver keeps filing into.
    """

    #: Samples kept per channel. Longer than the 20-sample micrographs because
    #: this is the plot an operator reads, but still bounded: it is per peer per
    #: channel and lives in the UI process.
    max_samples = 100

    #: Ceiling on samples pulled per tick, so a backlog cannot stall the render
    #: loop; whatever is left is taken on the next tick.
    max_per_tick = 64

    def __init__(self, ctl: DashControl, peer: PeerDataAcq, number: int):
        super().__init__(ctl.app)
        self.ctl = ctl
        self.number = str(number)
        self.peer = peer
        #: Addressable caption -- see VideoFeed.title_id. The data type is not
        #: known when this widget is built (a peer is rostered with
        #: `NullPeerData`), so the caption has to be pushed once it arrives.
        self.title_id = f'data-title-{self.number}'
        #: Keyed on the DRAWER's number, like every other id in the drawer. It
        #: used to be `peer.index`, which is not unique across roster churn (a
        #: departure frees an index that the next arrival re-derives), so two
        #: peers could claim one DOM id -- and Dash does not tolerate duplicates.
        self.graph_id = f'data_graph_{self.number}'
        self.idx = 0
        self._xes: deque[float] = deque(maxlen=self.max_samples)
        self._yes: list[deque] = []
        self.fig = go.Figure()
        self.fig.layout = go.Layout(showlegend=False, hovermode='closest',
                                    margin=dict(l=0, r=0, t=0, b=0),
                                    paper_bgcolor='rgba(0,0,0,0)',
                                    plot_bgcolor='rgba(0,0,0,0)')

    def _trace_name(self, channel: int) -> str:
        return f'data_{self.number}_ch{channel}'

    def _ensure_traces(self, count: int):
        """Grow to `count` channels, one trace each.

        Traces come from the first SAMPLE, not from `metadata.data_channels`: that
        is 0 while the peer still holds `NullPeerData`, so a figure built in
        __init__ had no usable trace for the component's whole life. (The old one
        added a single trace with one x and `data_channels` y values -- a shape
        plotly cannot pair up.)

        A channel that appears late is back-filled with None so its x and y stay
        the same length; plotly renders that as a gap, which is what it is.
        """
        while len(self._yes) < count:
            channel = len(self._yes)
            history = deque(maxlen=self.max_samples)
            history.extend([None] * len(self._xes))
            self._yes.append(history)
            self.fig.add_trace(go.Scatter(x=[], y=[], mode='lines',
                                          name=self._trace_name(channel)))

    def record(self, sample) -> None:
        """Append one reading, scalar or per-channel."""
        values = sample if isinstance(sample, (list, tuple)) else [sample]
        self._ensure_traces(len(values))
        self.idx += 1
        self._xes.append(float(self.idx))
        for channel, history in enumerate(self._yes):
            try:
                history.append(float(values[channel]))
            except (IndexError, TypeError, ValueError):
                # Short or unparseable sample: a gap, not a zero. A zero would
                # read as a measurement.
                history.append(None)

    def drain(self) -> bool:
        """Take what the receiver filed for this peer; report whether the figure
        changed, so the caller can skip a push that would carry nothing.

        Runs on every tick whether or not the drawer is open. Recording while
        nobody is watching is the point -- the plot shows history the moment the
        drawer opens, and an undrained stream would grow without bound.
        """
        changed = False
        for _ in range(self.max_per_tick):
            try:
                # Non-blocking: this runs on the shared UI tick, so it must not
                # wait on one peer's stream while every other peer's render waits
                # on it. (The old loop blocked for wait_sec, which was safe only
                # in the thread that never existed.)
                data = stream_take(self.peer.data_stream, 0)
            except Empty:
                break
            if data is None:
                continue
            self.record(data)
            changed = True
        if changed:
            self._apply()
        return changed

    def _apply(self):
        """Push the recorded history into the figure.

        `x=` / `y=` are real keyword arguments here. They used to be passed INSIDE
        `selector=`, which made the call a no-op twice over: nothing was patched,
        and the selector could not match a trace anyway.
        """
        xes = list(self._xes)
        for channel, history in enumerate(self._yes):
            self.fig.update_traces(selector=dict(name=self._trace_name(channel)),
                                   x=xes, y=list(history), overwrite=True)

    def div(self, title: str, style: dict = None) -> html.Div:
        if style is None:
            style = {'float': 'left', 'padding': 10}
        return html.Div([html.H1(title, id=self.title_id),
                         dcc.Graph(id=self.graph_id, figure=self.fig,
                                   config=dict(displayModeBar=False),
                                   style=dict(width='50%', height=320))],
                        style=style)
