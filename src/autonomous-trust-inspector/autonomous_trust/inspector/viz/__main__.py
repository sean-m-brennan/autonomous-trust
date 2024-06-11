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

import os
import argparse
from .server import VizServer

default_port = 8000
initial_size = 12


if __name__ == '__main__':
    this_dir = os.path.abspath(os.path.dirname(__file__))

    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--directory', type=str, default=this_dir)
    parser.add_argument('-p', '--port', type=int, default=default_port)
    parser.add_argument('--debug', action='store_true', default=False)
    parser.add_argument('--size', type=int, default=initial_size)
    args = parser.parse_args()

    VizServer(args.directory, args.port, args.debug, args.size).run()
