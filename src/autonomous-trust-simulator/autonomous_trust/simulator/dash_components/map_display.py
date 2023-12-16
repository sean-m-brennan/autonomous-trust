import logging
import os
from collections import OrderedDict

import dash_bootstrap_components as dbc
from dash import Patch, page_container

from autonomous_trust.core import Configuration, InitializableConfig
from autonomous_trust.inspector.dash_components import TimerTitle, DynamicMap, PeerStatus
from autonomous_trust.inspector.dash_components import DashControl, html, dcc
from autonomous_trust.inspector.dash_components import Output, Input
from autonomous_trust.inspector.dash_components.async_update import AsyncUpdate, Trigger
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
    preload = True
    name = 'display'
    icon_map = {'microdrone': 'carbon:drone',
                'soldier': 'healthicons:military-worker',
                'jet': 'fa-solid:fighter-jet',
                'recon': 'mdi:drone',
                'base': 'military-camp',
                }

    def __init__(self, cohort: CohortInterface, force_local: bool = False, with_sim: bool = True):
        self.cohort = cohort
        cfg_file = os.path.join(Configuration.get_cfg_dir(), self.name + Configuration.yaml_file_ext)
        self.cfg = Configuration.from_file(cfg_file)
        if force_local:
            self.cfg.sim_host = '127.0.0.1'  # for testing
        self.with_sim = with_sim
        self.server_host = None
        self.initial = True
        self.displayed_detail = -1
        self.status: OrderedDict[str, PeerStatus] = OrderedDict()
        self.all_stats: OrderedDict[str, PeerStatus] = OrderedDict()
        self.prev_overview_status: OrderedDict[str, PeerStatus] = OrderedDict()
        self.prev_full_status: OrderedDict[str, PeerStatus] = OrderedDict()  # tracked separately
        self.status_by_idx: dict[int, PeerStatus] = {}
        self.index = 0
        self.ctl: DashControl = None  # noqa
        self.dyna_map: DynamicMap = None  # noqa

    def update_status(self, trigger: bool = True):
        added = []
        removed = []
        uuid_list = []
        species: list[PeerDataAcq] = sorted(list(set([peer.kind for peer in self.cohort.peers.values()])))
        for kind in reversed(list(species)):
            for peer in [peer for peer in self.cohort.peers.values() if peer.kind == kind]:
                uuid_list.append(peer.uuid)
                if peer.uuid not in self.all_stats:
                    self.all_stats[peer.uuid] = PeerStatus(self.ctl, peer, self.cohort, self.dyna_map, self,
                                                           self.icon_map)
                    if peer.active:
                        self.status[peer.uuid] = self.all_stats[peer.uuid]
                        self.status_by_idx[self.index] = self.status[peer.uuid]
                        self.index += 1
                        added.append(peer.uuid)
                elif peer.active and peer.uuid not in self.status:
                    self.status[peer.uuid] = self.all_stats[peer.uuid]
                    self.status_by_idx[self.index] = self.status[peer.uuid]
                    self.index += 1
                    added.append(peer.uuid)
        for uuid in self.status:
            if uuid not in uuid_list:
                del self.status[uuid]
                removed.append(uuid)
        if self.dyna_map.following is None and len(self.status) > 0:
            self.dyna_map.following = list(self.status.keys())[0]
        if trigger and (len(added) > 0 or len(removed) > 0):
            if self.preload:
                for uuid in added:
                    self.ctl.push_mods({self.status[uuid].peer_detail_id:
                                        {'style': {'display': 'block', 'visibility': 'visible'}}})
                for uuid in removed:
                    self.ctl.push_mods({self.status[uuid].peer_detail_id:
                                        {'style': {'display': 'none', 'visibility': 'hidden'}}})
            else:
                self.ctl.emit('trigger_event', dict(id='overview_trigger', eventType='overview'))
                self.ctl.emit('trigger_event', dict(id='full_status_trigger', eventType='details'))

    def run(self, host: str = '0.0.0.0', port: int = 8050, logger: logging.Logger = None,
            debug: bool = False, verbose: bool = False):
        if logger is None:
            logger = self.cohort.logger
        stylesheets = [dbc.themes.SPACELAB]
        self.ctl = DashControl(__name__, 'Autonomous Trust Mission', host, stylesheets=stylesheets,
                               #pages_dir='',  # FIXME?
                               logger=logger, proxied=True, verbose=verbose)

        interfaces = [self.cohort]
        sim = None
        if self.with_sim:
            sim = SimulationInterface(self.ctl, self.cfg.sim_host, self.cfg.sim_port, [self.cohort],
                                      log_level=self.cohort.log_level, logfile=self.cohort.logfile)
            interfaces.append(sim)
        for iface in interfaces:
            iface.start()

        # must be initialized after ifaces are started
        heading = TimerTitle(self.ctl, self.cohort, logger)
        self.dyna_map = DynamicMap(self.ctl, self.cohort, logger, self.cfg.size, self.cfg.style)
        self.dyna_map.following = None

        ctrl_elts = []
        if self.with_sim:
            ctrls = SimulationControls(self.ctl, sim, self.cohort, logger, self.dyna_map, self.cfg.max_resolution)
            ctrl_elts += [
                html.Hr(),
                html.Br(),
                ctrls.div(),
            ]

            # end and reset are sim only
            sim.register_end_handler(ctrls.disable_controls)
            sim.register_reset_handler(self.dyna_map.acquire_initial_conditions)
            sim.register_reset_handler(ctrls.enable_controls)

        self.update_status(False)
        # data acquisition
        self.cohort.register_updater(self.update_status)

        inactive = [uuid for uuid in self.all_stats if uuid not in self.status]
        glance_divs = [peer.glance_div(active=uuid not in inactive) for uuid, peer in self.all_stats.items()]
        full_divs = [peer.peer_details() for peer in self.all_stats.values()]
        main_div = html.Div([
                                AsyncUpdate(self.ctl.ws_port),
                                Trigger('overview_trigger', 'overview'),
                                Trigger('full_status_trigger', 'details'),
                                html.Div(id='offcanvas-target'),
                                heading.div('Coordinator: Mission #demo'),
                                html.Br(),

                                dbc.Row([
                                    dbc.Col([self.dyna_map.div(), ], width=8),
                                    dbc.Col([html.Div(glance_divs,
                                                      id='peer-table',
                                                      style={"maxHeight": self.cfg.size + 100,
                                                             "overflowX": "hidden",
                                                             "overflowY": "scroll"})], width=4),
                                ], justify="start"),
                                html.Br(),
                                html.Div(full_divs,
                                         id='statuses'),  # note: this never shows any children
                            ] + ctrl_elts)

        self.ctl.app.layout = html.Div([dcc.Location(id="url"),
                                        #page_container,
                                        html.Div([main_div], id="page-content")])
        # FIXME use dbc.Container instead of Div
        #app.register_page('forecast', path='/forecast', layout=html.Div(['Forecast Page'])

        @self.ctl.callback_connect()
        def connection_change(event, _):
            if 'connect' == event:
                self.cohort.browser_connected += 1
            elif 'disconnect' == event:
                self.cohort.browser_connected -= 1

        #@self.ctl.callback(Output("page-content", "children"),
        #                   [Input("url", "pathname")])
        #def render_page_content(pathname: str):
        #    if pathname == '/':
        #       self.ctl.active_page = 'main'
        #       return main_div
        #   elif pathname.startswith('/peer_status_'):
        #       self.ctl.active_page = 'status'
        #       idx = int(pathname[pathname.rindex('_') + 1:])
        #       return self.status_by_idx[idx].div()
        #   elif pathname.startswith('/video_feed_'):
        #       self.ctl.active_page = 'video'
        #       idx = int(pathname[pathname.rindex('_') + 1:])
        #       return html.Div(html.Img(src='/video_feed_%d' % (idx + 1), width=640))
        #    # If the user tries to reach a different page, return a custom 404 message
        #    self.ctl.active_page = None
        #    return html.Div([
        #       html.H1("404: Not found", className="text-danger"),
        #       html.Hr(),
        #        html.P(f"The pathname {pathname} was not recognised..."),
        #    ], className="p-3 bg-light rounded-3")

        @self.ctl.callback(Output('peer-table', 'children'),
                           Input('overview_trigger', 'triggers'),
                           prevent_initial_call=True)
        def update_overview_divs(_):
            print('Overview')
            patched = Patch()
            current = OrderedDict(self.status)  # freeze content
            add = [current[uuid].glance_div()
                   for uuid in list(current.keys()) if uuid not in self.prev_overview_status]
            sub = [self.prev_overview_status[uuid].glance_div()
                   for uuid in list(self.prev_overview_status.keys()) if uuid not in current]
            for div in add:
                patched.append(div)
            for div in sub:
                patched.remove(div)
            print('Update overview +%d -%d' % (len(add), len(sub)))
            self.prev_overview_status = OrderedDict(current)
            return patched

        @self.ctl.callback(Output('statuses', 'children'),
                           Input('full_status_trigger', 'triggers'),
                           prevent_initial_call=True)
        def update_full_divs(_):
            print('Full')
            patched = Patch()
            current = OrderedDict(self.status)  # freeze content
            add = [current[uuid].peer_details()
                   for uuid in list(current.keys()) if uuid not in self.prev_full_status]
            sub = [self.prev_full_status[uuid].peer_details()
                   for uuid in list(self.prev_full_status.keys()) if uuid not in current]
            for div in add:
                patched.append(div)
            for div in sub:
                patched.remove(div)
            print('Update full +%d -%d' % (len(add), len(sub)))
            self.prev_full_status = OrderedDict(current)
            return patched

        self.ctl.run(host, port, debug=debug)
