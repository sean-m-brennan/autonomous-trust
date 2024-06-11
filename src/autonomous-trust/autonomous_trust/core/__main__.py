#!/usr/bin/env -S python3 -m
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

import argparse

from .system import dev_root_dir, CfgIds
from .automate import AutonomousTrust
from .config import Configuration
from .config.generate import random_config
from .processes import LogLevel


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('ident', type=int, nargs='?', default=None,
                        help='optional integer for separating multiple node configs')
    parser.add_argument('--remote-debug', type=str, nargs='?', default=None,
                        help='activate remote debugging connection, in the form: ip_address:port')
    parser.add_argument('--exclude-logs', type=str, action='append',
                        help='exclude named classes from logging')
    parser.add_argument('--test', action='store_true',
                        help='run limited testing application')
    parser.add_argument('--live', action='store_true',
                        help='run in production environ')
    args = parser.parse_args()

    if args.remote_debug is not None:
        ip, port = args.remote_debug.split(':', 1)
        print('Remote debugging to %s:%s' % (ip, port))
        import pydevd_pycharm
        pydevd_pycharm.settrace(ip, port=int(port), stdoutToServer=True, stderrToServer=True)

    if args.live:
        random_config(Configuration.get_cfg_dir(), args.ident)
    else:
        random_config(dev_root_dir, args.ident)
    to_log = None
    if args.exclude_logs is not None:
        to_log = [cls for cls in list(CfgIds) if cls not in args.exclude_logs]
    AutonomousTrust(multiproc=True, log_level=LogLevel.DEBUG, logfile=Configuration.log_stdout,
                    log_classes=to_log, testing=args.test).run_forever()


if __name__ == '__main__':
    main()
