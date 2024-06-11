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

from random import random

from autonomous_trust.core import ProcMeta
from autonomous_trust.services.data.server import DataProcess, DataConfig


class SimDataSrc(DataConfig):
    @classmethod
    def initialize(cls, idx: int = 0, channels: int = 3):
        data_map = {}
        if idx in data_map:
            return SimDataSrc(channels)
        return None


class DataSimSource(DataProcess, metaclass=ProcMeta,
                    proc_name='data-source', description='Data stream service'):
    def acquire(self):
        return [random() for _ in range(self.cfg.channels)]
