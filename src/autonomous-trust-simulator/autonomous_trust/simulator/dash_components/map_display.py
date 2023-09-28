import logging

from dash.exceptions import PreventUpdate
from flask import Flask
from dash import Dash, html, Output, Input
import dash_bootstrap_components as dbc

from autonomous_trust.inspector.peer.daq import Cohort
from autonomous_trust.inspector.dash_components import TimerTitle, DynamicMap, PeerStatus

from . import SimulationControls, SimulationInterface

log = logging.getLogger('werkzeug')
log.setLevel(logging.WARNING)  # reduce callback noise from Flask


class MapDisplay(object):
    def __init__(self, cohort: Cohort, sim_host: str = '127.0.0.1', sim_port: int = 8778,
                 size: int = 600, max_resolution: int = 300, style: str = 'dark'):
        self.server = Flask(__name__)
        self.app = Dash(__name__, server=self.server, external_stylesheets=[dbc.themes.SPACELAB],
                        prevent_initial_callbacks=True, update_title=None)

        sim = SimulationInterface(sim_host, sim_port, [cohort])
        heading = TimerTitle(self.app, self.server, cohort, with_interval=False)
        dyna_map = DynamicMap(self.app, self.server, cohort, size, style)
        ctrls = SimulationControls(self.app, self.server, sim, cohort, dyna_map, max_resolution, with_interval=False)
        sim.register_reset_handler(dyna_map.acquire_initial_conditions)
        self.status = {}
        for uuid in cohort.peers:
            self.status[uuid] = PeerStatus(self.app, self.server, cohort.peers[uuid], dyna_map)

        self.app.layout = html.Div([
            heading.div('Coordinator: Mission #demo'),
            html.Br(),

            dbc.Row([
                dbc.Col([dyna_map.div(), ], width=8),
                dbc.Col([html.Div(id='peer-table')], width=4),
            ], justify="start"),
            html.Br(),

            html.Hr(),
            html.Br(),
            ctrls.div(),

            html.Div(id='peer-status')  # modals
        ])

        @self.app.callback([Output('peer-table', 'children'),
                            Output('peer-status', 'children')],
                           Input('interval', 'n_intervals'))
        def update_peers(_):
            if cohort.paused:
                raise PreventUpdate
            status = list(self.status.values())
            return self.get_status(status, glance=True), self.get_status(status)

        # end __init__

    @staticmethod
    def get_status(peers: list[PeerStatus], glance=False):
        peer_divs = []
        for peer in peers:
            peer_divs.append(peer.div(glance=glance))
        return html.Div(peer_divs)

    def run(self, host: str = '127.0.0.1', port: int = 8050):
        self.app.run(host, port)
