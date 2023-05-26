import os

from autonomous_trust import LogLevel
from autonomous_trust.config.generate import random_config

from .inspector import Inspector


if __name__ == '__main__':
    random_config(os.path.join(os.path.dirname(__file__)), 'inspector')  # FIXME static identity?
    Inspector(log_level=LogLevel.DEBUG).run_forever()
