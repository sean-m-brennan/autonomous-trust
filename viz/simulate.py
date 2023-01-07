#!/usr/bin/env python3

import os
import argparse
import asyncio
import quart
import network_graph as ng


default_port = 8000

parser = argparse.ArgumentParser()
parser.add_argument('-d', '--directory', type=str, default=os.getcwd())
parser.add_argument('-p', '--port', type=int, default=default_port)
args = parser.parse_args()
    
print(' * Directory on host: %s' % args.directory)
app = quart.Quart(__name__.split('.')[0],
                  static_url_path='', static_folder=args.directory)
app.debug = True

@app.route("/")
async def page():
    return await quart.send_from_directory(args.directory, "index.html")


@app.websocket('/ws')
async def ws():
    # two bells of arg1 nodes, connected with arg2 nodes between
    graph = ng.RandomNetwork(6, 0)
    while True:
        msg = await quart.websocket.receive()
        seconds, data = graph.get_update()
        await quart.websocket.send(data)
        await asyncio.sleep(seconds)


app.run(port=args.port)
