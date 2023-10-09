import argparse

from .simulator import Simulator
from . import default_steps, default_port

parser = argparse.ArgumentParser()
parser.add_argument('config')
parser.add_argument('--steps', nargs='?', default=default_steps)
parser.add_argument('--port', nargs='?', default=default_port)
args = parser.parse_args()

Simulator(args.config, max_time_steps=args.steps).run(args.port)
