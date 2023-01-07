#!/usr/bin/env python3

import asyncio
import quart
import network_graph as ng


port = 8000
appq = quart.Quart(__name__, static_url_path='', static_folder=".")


@appq.route("/")
async def presentation():
    return await quart.send_from_directory(".", "index.html")


@appq.websocket('/ws')
async def ws():
    # two bells of arg1 nodes, connected with arg2 nodes between
    graph = ng.RandomNetwork(6, 0)
    while True:
        msg = await quart.websocket.receive()
        seconds, data = graph.get_update()
        await quart.websocket.send(data)
        await asyncio.sleep(seconds)


appq.run(port=port)
