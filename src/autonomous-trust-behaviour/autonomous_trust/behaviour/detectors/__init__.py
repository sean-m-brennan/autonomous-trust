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
"""Streaming anomaly detectors (SOW Task 3.2), built via River/PyOD.

* :class:`RiverHalfSpaceTrees` — multivariate isolation score (River).
* :class:`PyODHBOS`            — per-feature explainable histogram score (PyOD,
                                 made streaming via a sliding-window refit).
* :class:`StreamingCalibrator` — online raw-score → [0, 1] calibration.
"""
from .base import AnomalyDetector
from .river_hst import RiverHalfSpaceTrees
from .pyod_hbos import PyODHBOS
from .calibrator import StreamingCalibrator

__all__ = ['AnomalyDetector', 'RiverHalfSpaceTrees', 'PyODHBOS',
           'StreamingCalibrator']
