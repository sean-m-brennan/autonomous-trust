#!/usr/bin/env -S python3 -m

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
