import logging
import os
from collections import OrderedDict

from dash.exceptions import PreventUpdate
import dash_bootstrap_components as dbc

from autonomous_trust.core import Configuration, InitializableConfig
from autonomous_trust.inspector.dash_components import TimerTitle, DynamicMap, PeerStatus
from autonomous_trust.inspector.dash_components import DashControl, html, dcc, Output, Input
from autonomous_trust.inspector.peer.daq import CohortInterface, PeerDataAcq

from . import SimulationControls, SimulationInterface
from .. import default_port


class MapUI(InitializableConfig):
    def __init__(self, sim_host: str = '127.0.0.1', sim_port: int = default_port,
                 size: int = 600, max_resolution: int = 300, style: str = 'dark'):
        self.sim_host = sim_host
        self.sim_port = sim_port
        self.size = size
        self.max_resolution = max_resolution
        self.style = style

    @classmethod
    def initialize(cls, sim_host: str = '127.0.0.1', sim_port: int = default_port,
                   size: int = 600, max_resolution: int = 300, style: str = 'dark'):
        return MapUI(sim_host, sim_port, size, max_resolution, style)


class MapDisplay(object):
    name = 'display'
    icon_map = {'microdrone': 'carbon:drone',
                'soldier': 'healthicons:military-worker',
                'jet': 'fa-solid:fighter-jet',
                'recon': 'mdi:drone',
                'base': 'military-camp',
                }

    def __init__(self, cohort: CohortInterface, force_local: bool = False):
        self.cohort = cohort
        cfg_file = os.path.join(Configuration.get_cfg_dir(), self.name + Configuration.yaml_file_ext)
        self.cfg = Configuration.from_file(cfg_file)
        if force_local:
            self.cfg.sim_host = '127.0.0.1'  # for testing
        self.server_host = None

    def run(self, host: str = '0.0.0.0', port: int = 8050, logger: logging.Logger = None,
            debug: bool = False, verbose: bool = False):
        if logger is None:
            logger = self.cohort.logger
        stylesheets = [dbc.themes.SPACELAB, 'https://api.mapbox.com/mapbox-gl-js/v2.14.1/mapbox-gl.css']
        ctl = DashControl(__name__, 'Autonomous Trust Mission', host, stylesheets=stylesheets,
                          pages_dir='', logger=logger, proxied=True, verbose=verbose)

        @ctl.on('connect')
        def connect(_):
            self.cohort.browser_connected += 1

        @ctl.on('disconnect')
        def disconnect(_):
            self.cohort.browser_connected -= 1

        sim = SimulationInterface(ctl, self.cfg.sim_host, self.cfg.sim_port, [self.cohort],
                                  log_level=self.cohort.log_level, logfile=self.cohort.logfile)
        for iface in [sim, self.cohort]:
            iface.start()

        heading = TimerTitle(ctl, self.cohort, logger)
        dyna_map = DynamicMap(ctl, self.cohort, logger, self.cfg.size, self.cfg.style)
        ctrls = SimulationControls(ctl, sim, self.cohort, logger, dyna_map, self.cfg.max_resolution,
                                   with_interval=True)  # master interval here

        sim.register_reset_handler(dyna_map.acquire_initial_conditions)

        status = OrderedDict()
        active = OrderedDict()
        status_by_idx = {}
        index = 0
        species: list[PeerDataAcq] = sorted(list(set([peer.kind for peer in self.cohort.peers.values()])))
        for kind in reversed(list(species)):
            for peer in [peer for peer in self.cohort.peers.values() if peer.kind == kind]:
                status[peer.uuid] = PeerStatus(ctl, peer, self.cohort, dyna_map, self.icon_map)
                if peer.active:
                    active[peer.uuid] = status[peer.uuid]  # all statuses get created, not all displayed
                status_by_idx[index] = status[peer.uuid]
                index += 1
        if len(active) > 0:
            dyna_map.following = list(active.keys())[0]

        main_div = html.Div([
            heading.div('Coordinator: Mission #demo'),
            html.Br(),

            dbc.Row([
                dbc.Col([dyna_map.div(), ], width=8),
                dbc.Col([html.Div(id='peer-table',
                                  style={"maxHeight": self.cfg.size+100,
                                         "overflowX": "hidden",
                                         "overflowY": "scroll"})], width=4),
            ], justify="start"),
            html.Br(),

            html.Hr(),
            html.Br(),
            ctrls.div(),
        ])

        ctl.app.layout = html.Div([dcc.Location(id="url"), html.Div([main_div], id="page-content")])

        @ctl.callback(Output("page-content", "children"),
                      [Input("url", "pathname")])
        def render_page_content(pathname: str):
            if pathname == '/':
                ctl.active_page = 'main'
                return main_div
            elif pathname.startswith('/peer_status_'):
                ctl.active_page = 'status'
                idx = int(pathname[pathname.rindex('_') + 1:])
                return status_by_idx[idx].div()
            elif pathname.startswith('/video_feed_'):
                ctl.active_page = 'video'
                idx = int(pathname[pathname.rindex('_') + 1:])
                return html.Div(html.Img(src='/video_feed_%d' % (idx + 1), width=640))
            # If the user tries to reach a different page, return a custom 404 message
            ctl.active_page = None
            return html.Div([
                html.H1("404: Not found", className="text-danger"),
                html.Hr(),
                html.P(f"The pathname {pathname} was not recognised..."),
            ], className="p-3 bg-light rounded-3")

        @ctl.callback(Output('peer-table', 'children'),
                      Input('interval', 'n_intervals'))
        def update_peers(_):
            if ctl.active_page != 'main':
                raise PreventUpdate
            if self.cohort.paused:
                raise PreventUpdate
            for peer in self.cohort.peers.values():
                if peer.active and peer.uuid not in active:
                    active[peer.uuid] = status[peer.uuid]
            peer_divs = []
            for peer in list(active.values()):
                peer_divs.append(peer.div(glance=True))
            return html.Div(peer_divs)

        # end __init__

        ctl.run(host, port, debug=debug)
