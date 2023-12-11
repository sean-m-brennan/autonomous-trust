import logging
import os

from autonomous_trust.core import Configuration
from .mock_client import SimCohort
from .map_display import MapDisplay


if __name__ == '__main__':
    host: str = '127.0.0.1'
    port: int = 8050
    coord_cfg = os.path.abspath(os.path.join(os.path.dirname(__file__),
                                             '..', '..', '..', 'examples', 'mission', 'coordinator'))
    os.environ[Configuration.ROOT_VARIABLE_NAME] = coord_cfg

    MapDisplay(SimCohort(log_level=logging.DEBUG), force_local=True).run(host, port, debug=True)
