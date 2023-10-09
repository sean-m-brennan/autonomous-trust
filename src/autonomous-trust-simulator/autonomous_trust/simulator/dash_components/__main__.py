import logging

from .mock_client import SimCohort
from .map_display import MapDisplay


if __name__ == '__main__':
    host: str = '127.0.0.1'
    port: int = 8050

    MapDisplay(SimCohort(log_level=logging.INFO)).run(host, port, debug=True)
