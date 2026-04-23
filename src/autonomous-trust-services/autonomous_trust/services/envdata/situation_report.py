# ******************
#  Copyright 2025 Sean M. Brennan and contributors
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

"""FEMA situation-report stream service.

Text-blob cadence is slow (default 20s); payload carries the report body
in Reading.metadata['text'] with a numeric hash in Reading.value so
downstream aggregators can still treat it uniformly.
"""

from autonomous_trust.core import ProcMeta

from .base import EnvDataProcess


class SituationReportProcess(EnvDataProcess, metaclass=ProcMeta,
                             proc_name='situation-report',
                             description='FEMA situation report stream',
                             cfg_name='situation-report'):
    capability_name = 'situation_report'
