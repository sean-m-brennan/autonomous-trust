import json
import random
from enum import Enum


class Serializable(object):
    def to_json(self):
        json.dumps(self, default=lambda obj: obj.__dict__)


class Variability(Enum):
    """Centered about zero"""
    BROWNIAN = lambda: random.normalvariate(mu=0.0, sigma=2.0)  # noqa
    GAUSSIAN = random.gauss
    UNIFORM = lambda: random.uniform(-1.0, 1.0)  # noqa

    def __call__(self, *args) -> float:
        return self.value(*args)
