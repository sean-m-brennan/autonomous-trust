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
import logging

from .simulator import Simulator
from . import default_steps, default_port

parser = argparse.ArgumentParser()
parser.add_argument('config')
parser.add_argument('--steps', nargs='?', default=default_steps)
parser.add_argument('--log', nargs='?', default=None)
parser.add_argument('--log-level', nargs='?', default='warning')
parser.add_argument('--resolve-fqdn', action='store_true')
parser.add_argument('--resolve-short-name', action='store_true')
parser.add_argument('--port', nargs='?', default=default_port)
args = parser.parse_args()

log_level = logging.WARNING
if args.log_level.lower() == 'debug':
    log_level = logging.DEBUG
elif args.log_level.lower() == 'info':
    log_level = logging.INFO
elif args.log_level.lower() == 'error':
    log_level = logging.ERROR
elif args.log_level.lower() == 'critical':
    log_level = logging.CRITICAL
resolve = args.resolve_fqdn or args.resolve_short_name

Simulator(args.config, max_time_steps=args.steps, log_level=log_level, logfile=args.log,
          resolve=resolve, short=args.resolve_short_name).run(args.port)
