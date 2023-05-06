try:
    import importlib.metadata  # noqa
    __version__ = importlib.metadata.version("autonomous_trust")
except ImportError:
    __version__ = 0

from .automate import AutonomousTrust  # noqa

from .processes import *  # noqa
from .config import *  # noqa
