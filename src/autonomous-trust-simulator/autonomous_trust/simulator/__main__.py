import argparse

from .simulator import Simulator

parser = argparse.ArgumentParser()
parser.add_argument('config')
parser.add_argument('port', nargs='?', default=8888)
args = parser.parse_args()

Simulator(args.config).run(args.port)
