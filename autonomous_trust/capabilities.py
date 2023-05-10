from collections.abc import Mapping
import multiprocessing

from .config import Configuration


class Capability(Configuration):
    def __init__(self, name, function=None, arg_names=None, keywords=None):
        self.name = name
        self.function = function  # this will be None for remote handling
        self.arg_names = arg_names
        self.keywords = keywords

    def execute(self, task, pid_q):
        pid = multiprocessing.current_process()
        pid_q.put_nowait(pid)
        return self.function(*task.paramters.args, **task.parameters.kwargs)

    def __eq__(self, other):
        return self.name == other.name


class Capabilities(Mapping):
    def __init__(self):
        self._listing = {}

    def __len__(self):
        return len(self._listing)

    def __iter__(self):
        return self._listing.__iter__()

    def __getitem__(self, key):
        return self._listing[key]

    def register_ability(self, name, function, arg_names=None, keywords=None):
        self._listing[name] = Capability(name, function, arg_names, keywords)
