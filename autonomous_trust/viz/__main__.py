#!/usr/bin/env -S python3 -m

import os
import argparse
import asyncio
import quart
from .. import network_graph as ng
from .. import social_graphs

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

    print(' * Directory on host: %s' % args.directory)
    app = quart.Quart(__package__.split('.')[0],
                      static_url_path='', static_folder=args.directory)
    app.debug = True


    @app.route("/")
    async def page():
        return await quart.send_from_directory(args.directory, "index.html")


    @app.websocket('/ws')
    async def ws():
        graph = None
        while True:
            msg = await quart.websocket.receive()
            if graph is None:
                for impl in ng.Graphs.Implementation:
                    if msg == impl.value:
                        graph = ng.Graphs.get_graph(impl.value, args.size, args.debug)
                        print(' * Simulating %s network graph' % msg)
            if msg == 'done':
                print(' * Simulation done')
                break
            seconds, data = graph.get_update()
            await quart.websocket.send(data)
            await asyncio.sleep(seconds)


    app.run(port=args.port)
