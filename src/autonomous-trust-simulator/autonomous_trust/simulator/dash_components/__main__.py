# ******************
#  Copyright 2024 TekFive, Inc. and contributors
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
