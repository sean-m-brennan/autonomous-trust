import random
import time
import uuid


def x(n: int = 4):
    """Implements a categorical distribution"""
    r = random.random()
    for idx, frac in zip(range(n, 1, -1), [((2**i)-1)/(2**i) for i in range(n-1, 0, -1)]):
        if r > frac:
            return idx
    return 1


def observables(n: int = 4, s: int = 100000):
    return [x(n) for _ in range(s)]


class Ident:
    idx = 1

    def __init__(self, name):
        self.name = '%s#%s' % (name, str(Ident.idx).zfill(3))
        self.uuid = uuid.uuid4()
        Ident.idx += 1

    def __repr__(self):
        return self.name


class DataService:
    n = 4

    def __init__(self):
        self.ident = Ident(self.__class__.__name__)

    def report(self):
        raise NotImplementedError

    def send(self):
        start = time.perf_counter()
        result = self.report()
        elapsed = time.perf_counter() - start
        return result, self.ident, elapsed


class ExactService(DataService):
    def report(self):
        output = []
        for x in observables(self.n):
            output.append({x})
        return output


class BlindService(DataService):
    def report(self):
        output = []
        for _ in range(len(observables(self.n))):
            output.append({self.n})
        return output


class FaultyService(DataService):
    def report(self):
        output = []
        for x in observables(self.n):
            if x == self.n or random.random() < 0.2:
                output.append({x})
            else:
                continue
        return output


class BiasedService(DataService):
    def report(self):
        output = []
        for x in observables(self.n):
            if x == 1 or x == self.n:
                output.append({1, self.n})
            else:
                output.append({x})
        return output
