#!/usr/bin/env -S python3 -m

import os
import sys
import argparse
from . import dev_root_dir
from .automate import main
from .config.configuration import Configuration
from .processes import LogLevel
from .config.generate import generate_identity


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

    if Configuration.VARIABLE_NAME in os.environ.keys():
        cfg_dir = Configuration.get_cfg_dir()
    else:
        cfg_dir = os.path.join(dev_root_dir, Configuration.CFG_PATH)
        if args.ident is not None:
            cfg_dir = os.path.join(dev_root_dir, args.ident, Configuration.CFG_PATH)
    if not os.path.isdir(cfg_dir):
        os.makedirs(cfg_dir, exist_ok=True)
        generate_identity(cfg_dir, randomize=True, seed=args.ident)
    os.environ[Configuration.VARIABLE_NAME] = cfg_dir
    main(multiproc=True, log_level=LogLevel.DEBUG, logfile=Configuration.log_stdout)
