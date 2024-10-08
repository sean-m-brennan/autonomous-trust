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
import asyncio
import quart

from . import network_graph as ng
from . import social_graphs  # noqa  required import
from .middleware import SassASGIMiddleware

default_port = 8000
initial_size = 12


class VizServer(object):
    def __init__(self, directory, port, debug=False, size=12, data_q=None, finished=None):
        if finished is None:
            finished = lambda: None  # noqa
        self.finished = finished
        self.port = port
        print(' * Directory on host: %s' % directory)
        #appname = __package__.split('.')[0]  # FIXME wrong for Quart, wrong also for SassASGI?
        appname = __name__
        self.app = quart.Quart(appname, static_url_path='', static_folder=directory, template_folder=directory)
        self.app.debug = True

        os.environ['PATH_INFO'] = '/scss/tekfive.scss'
        self.app.asgi_app = SassASGIMiddleware(self.app, {appname: (os.path.join(directory, 'scss'),
                                                                    os.path.join(directory, 'css'), '/css', True)})

        @self.app.route("/")
        async def page():
            return await quart.render_template("index.html")  # noqa

        @self.app.websocket('/ws')
        async def ws():
            graph = None
            while True:
                if data_q is not None:
                    graph = ng.Graphs.get_graph('live', size, debug, data_q=data_q)
                    print(' * Visualizing live network graph')
                else:
                    msg = await quart.websocket.receive()
                    if graph is None:
                        for impl in ng.Graphs.Implementation:  # noqa
                            if msg == impl.value:
                                graph = ng.Graphs.get_graph(impl.value, size, debug)
                                print(' * Simulating %s network graph' % msg)
                    if graph is None:
                        raise RuntimeError('ERROR: no graph for %s' % msg)
                    if msg == 'done':
                        print(' * Simulation done')
                        break

                seconds, data, stop = graph.get_update()
                if stop:
                    break
                if data is not None:
                    await quart.websocket.send(data)
                await asyncio.sleep(seconds)

    def run(self):
        self.app.run(port=self.port)

    def stop(self):
        self.finished()
        self.app.shutdown()
