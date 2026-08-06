# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
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

"""Environmental data services for the multi-agency disaster-response demo.

Each concrete service exposes a distinct AT capability string so FEMA
fusion and other consumers can discover and request specific streams
via the negotiation protocol:

    weather_stream        -- NOAA weather stations
    seismic_stream        -- USGS seismic monitors
    airquality_stream     -- EPA air-quality monitor
    data_fusion           -- FEMA fusion node (consumer + re-producer)
    situation_report      -- FEMA field stations
    sensor_validation     -- Any peer (cross-source sanity check)

The service layer is generator-agnostic. Peers inject a source callable
via `EnvDataProcess.set_source()` (or config); the demo scenario wires
in the appropriate generator from evaluation/scenarios/.

Compromised sensors use `CompromisedGenerator` from .compromise which
transforms otherwise-honest readings according to a CompromiseConfig.
"""

from .base import EnvDataConfig, EnvDataProcess
from .compromise import (
    CompromiseConfig,
    CompromisedGenerator,
    compromise_from_env,
    COMPROMISE_MODE_TEMP_DRIFT,
    COMPROMISE_MODE_WIND_SPIKES,
    COMPROMISE_MODE_PRESSURE_FLATLINE,
    COMPROMISE_MODE_PRECIP_INVERT,
)
from .weather import WeatherStreamProcess
from .seismic import SeismicStreamProcess
from .airquality import AirQualityStreamProcess
from .fusion import DataFusionProcess
from .situation_report import SituationReportProcess
from .sensor_validation import SensorValidationProcess

__all__ = [
    "EnvDataConfig",
    "EnvDataProcess",
    "CompromiseConfig",
    "CompromisedGenerator",
    "compromise_from_env",
    "COMPROMISE_MODE_TEMP_DRIFT",
    "COMPROMISE_MODE_WIND_SPIKES",
    "COMPROMISE_MODE_PRESSURE_FLATLINE",
    "COMPROMISE_MODE_PRECIP_INVERT",
    "WeatherStreamProcess",
    "SeismicStreamProcess",
    "AirQualityStreamProcess",
    "DataFusionProcess",
    "SituationReportProcess",
    "SensorValidationProcess",
]
