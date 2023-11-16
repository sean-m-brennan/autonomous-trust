import logging
import os
from logging.handlers import TimedRotatingFileHandler

import dash
from dash.exceptions import PreventUpdate
import dash_bootstrap_components as dbc
import flask

from autonomous_trust.core import Configuration, InitializableConfig, LogLevel
from autonomous_trust.inspector.dash_components import TimerTitle, DynamicMap, PeerStatus
from autonomous_trust.inspector.peer.daq import CohortInterface

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
                'soldier': 'healthicons: military-worker',
                'jet': 'fa-solid: fighter-jet',
                'recon': 'mdi:drone',
                'base': 'military-camp',
                }

    def __init__(self, cohort: CohortInterface):
        self.cohort = cohort
        cfg_file = os.path.join(Configuration.get_cfg_dir(), self.name + Configuration.yaml_file_ext)
        self.cfg = Configuration.from_file(cfg_file)

    def run(self, host: str = '0.0.0.0', port: int = 8050, logger: logging.Logger = None,
            debug: bool = False, verbose: bool = False):
        if not verbose:
            logging.getLogger('werkzeug').setLevel(logging.WARNING)  # reduce useless callback noise from Flask

        if logger is not None:
            logger.info('Dash v%s with Flask v%s' % (dash.__version__, flask.__version__))
        server = flask.Flask(__name__)
        app = dash.Dash(__name__, server=server, external_stylesheets=[dbc.themes.SPACELAB],
                        title='Autonomous Trust Mission', update_title=None,
                        use_pages=True, pages_folder='',
                        prevent_initial_callbacks=True, suppress_callback_exceptions=True)
        if isinstance(logger, logging.Logger):
            for handler in logger.handlers:
                app.server.logger.addHandler(handler)
        app.use_reloader = False

        sim = SimulationInterface(self.cfg.sim_host, self.cfg.sim_port, [self.cohort],
                                  log_level=self.cohort.log_level, logfile=self.cohort.logfile)
        heading = TimerTitle(app, server, self.cohort, with_interval=False)
        dyna_map = DynamicMap(app, server, self.cohort, self.cfg.size, self.cfg.style)
        ctrls = SimulationControls(app, server, sim, self.cohort, dyna_map, self.cfg.max_resolution,
                                   with_interval=False)
        sim.register_reset_handler(dyna_map.acquire_initial_conditions)
        status = {}
        status_by_idx = {}
        for index, uuid in enumerate(self.cohort.peers.keys()):
            status[uuid] = PeerStatus(app, server, self.cohort.peers[uuid], dyna_map, self.icon_map)
            status_by_idx[index] = status[uuid]

        app.layout = dash.html.Div([dash.dcc.Location(id="url"),
                                    dash.html.Div(id="page-content")])

        main_div = dash.html.Div([
            heading.div('Coordinator: Mission #demo'),
            dash.html.Br(),

            dbc.Row([
                dbc.Col([dyna_map.div(), ], width=8),
                dbc.Col([dash.html.Div(id='peer-table')], width=4),
            ], justify="start"),
            dash.html.Br(),

            dash.html.Hr(),
            dash.html.Br(),
            ctrls.div(),
        ])

        @app.callback(dash.Output("page-content", "children"),
                      [dash.Input("url", "pathname")])
        def render_page_content(pathname: str):
            if pathname == '/':
                return main_div
            elif pathname.startswith('/peer_status_'):
                idx = int(pathname[pathname.rindex('_') + 1:])
                return status_by_idx[idx].div()
            elif pathname.startswith('/video_feed_'):
                idx = int(pathname[pathname.rindex('_') + 1:])
                return dash.html.Div(dash.html.Img(src='/video_feed_%d' % (idx + 1), width=640))
            # If the user tries to reach a different page, return a custom 404 message
            return dash.html.Div([
                dash.html.H1("404: Not found", className="text-danger"),
                dash.html.Hr(),
                dash.html.P(f"The pathname {pathname} was not recognised..."),
            ], className="p-3 bg-light rounded-3")

        @app.callback(dash.Output('peer-table', 'children'),
                      dash.Input('interval', 'n_intervals'))
        def update_peers(_):
            if self.cohort.paused:
                raise PreventUpdate
            peer_divs = []
            for peer in list(status.values()):
                peer_divs.append(peer.div(glance=True))
            return dash.html.Div(peer_divs)

        # end __init__

        app.run(host, port, debug=debug)
