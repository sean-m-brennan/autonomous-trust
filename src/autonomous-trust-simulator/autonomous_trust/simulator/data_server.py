from random import random

from autonomous_trust.core import ProcMeta
from autonomous_trust.services.data.server import DataSource, DataSrc


class SimDataSrc(DataSrc):
    @classmethod
    def initialize(cls, idx: int, channels: int):
        data_map = {}
        if idx in data_map:
            return SimDataSrc(channels)
        return None


class DataSimSource(DataSource, metaclass=ProcMeta,
                    proc_name='data-source', description='Data stream service'):
    def acquire(self):
        return [random() for _ in range(self.cfg.channels)]
