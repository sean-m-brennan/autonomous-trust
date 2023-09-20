from dash import Dash, html
from flask import Flask

from autonomous_trust.simulator.dash_components import SimulationControls, SimulationInterface
from ..peer.daq import Cohort
from . import DynamicMap, TimerTitle


if __name__ == '__main__':
    host: str = '127.0.0.1'
    port: int = 8050

    webserver = Flask(__name__)
    webapp = Dash(__name__, server=webserver,
                  prevent_initial_callbacks=True, update_title=None)
    cohort = Cohort([])  # FIXME
    heading = TimerTitle(webapp, webserver, cohort, with_interval=False)
    dynamap = DynamicMap(webapp, webserver, cohort)
    sim_iface = SimulationInterface(sync_objects=[cohort])
    ctrls = SimulationControls(webapp, webserver, sim_iface, cohort, dynamap, with_interval=False)
    sim_iface.register_reset_handler(dynamap.acquire_initial_conditions)

    webapp.layout = html.Div([
        heading.div('Coordinator: Mission #demo'),
        html.Br(),
        dynamap.div(),
        html.Br(),
        html.Hr(),
        html.Br(),
        ctrls.div(),
    ])

    # simulator must be started separately
    webapp.run(host, port, debug=True)
