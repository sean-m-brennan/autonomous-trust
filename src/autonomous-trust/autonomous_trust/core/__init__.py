try:
    import importlib.metadata  # noqa
    __version__ = importlib.metadata.version("autonomous_trust")
except ImportError:
    __version__ = 0

from .automate import AutonomousTrust  # noqa

from .processes import yaml, ProcessTracker, Process, ProcMeta, LogLevel
from .config import Configuration, InitializableConfig, EmptyObject, to_yaml_string, from_yaml_string
from .system import CfgIds, QueueType
