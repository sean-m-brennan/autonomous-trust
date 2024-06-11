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

import random
import time
import uuid

import numpy as np


class Ident:
    idx = 1

    def __init__(self, name):
        self.name = '%s#%s' % (name, str(Ident.idx).zfill(3))
        self.uuid = uuid.uuid4()
        Ident.idx += 1

    def __repr__(self):
        return self.name


class DataService:
    def __init__(self, categories: dict[int, str], size: int = 4):
        self.ident = Ident(self.__class__.__name__)
        self.categories = categories
        self.n = size
        self.data = self.observables(size)

    def report(self) -> list[set[int]]:
        raise NotImplementedError

    def send_data(self) -> tuple[int, ...]:
        return tuple(self.data)

    def send_report(self) -> tuple[list[set[int]], Ident, float]:
        start = time.perf_counter()
        result = self.report()
        elapsed = time.perf_counter() - start
        return result, self.ident, elapsed

    @staticmethod
    def prob(n: int) -> list[float]:
        p = [1. / (2 ** (i + 1)) for i in range(n-1)]
        return p + [p[-1]]

    @classmethod
    def observables(cls, n: int = 4, s: int = 100000, p=None) -> list[int]:
        """Return category indices sampled from a given distribution"""
        if p is None:
            p = cls.prob(n)
        return np.random.choice(range(1, n + 1), s, p=p)


class ExactService(DataService):
    def report(self):
        output = []
        for x in self.data:
            output.append({self.categories[x]})
        return output


class CloseEnoughService(DataService):
    def report(self):
        output = []
        for x in self.data:
            if x != self.n:
                output.append({self.categories[x]})
            output.append({self.categories[x]})
        return output


class BlindService(DataService):
    def report(self):
        output = []
        for _ in range(len(self.data)):
            output.append({self.categories[self.n]})
        return output


class FaultyService(DataService):
    def report(self):
        output = []
        for x in self.data:
            if x == self.n or random.random() < 0.2:
                output.append({self.categories[x]})
            else:
                continue
        return output


class BiasedService(DataService):
    def report(self):
        output = []
        for x in self.data:
            if x == 1 or x == self.n:
                output.append({self.categories[1]})
                output.append({self.categories[self.n]})
            else:
                output.append({self.categories[x]})
        return output


class DeceitService(DataService):
    def report(self):
        output = []
        for x in self.data:
            output.append({self.categories[self.n - x + 1]})
        return output


ALL_SERVICES = [ExactService, CloseEnoughService, BlindService, FaultyService, BiasedService, DeceitService]
