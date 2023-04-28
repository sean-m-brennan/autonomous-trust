import os
import importlib.metadata

__version__ = importlib.metadata.version("autonomous_trust")

from .automate import main  # noqa

from . import config  # noqa
from . import network  # noqa
from . import identity  # noqa
from . import reputation  # noqa
from . import viz  # noqa

dev_root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
