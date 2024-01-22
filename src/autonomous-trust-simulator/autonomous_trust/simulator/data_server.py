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
