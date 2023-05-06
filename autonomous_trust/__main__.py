#!/usr/bin/env -S python3 -m

import argparse

from .system import dev_root_dir
from .automate import AutonomousTrust
from .config import Configuration
from .config.generate import random_config
from .processes import LogLevel


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('ident', type=int, nargs='?', default=None,
                        help='optional integer for separating multiple node configs')
    parser.add_argument('--remote-debug', type=str, nargs='?', default=None,
                        help='activate remote debugging connection, in the form: ip_address:port')
    args = parser.parse_args()

    if args.remote_debug is not None:
        ip, port = args.remote_debug.split(':', 1)
        print('Remote debugging to %s:%s' % (ip, port))
        import pydevd_pycharm
        pydevd_pycharm.settrace(ip, port=int(port), stdoutToServer=True, stderrToServer=True)

    random_config(dev_root_dir, args.ident)
    AutonomousTrust(multiproc=True, log_level=LogLevel.DEBUG, logfile=Configuration.log_stdout).run_forever()
