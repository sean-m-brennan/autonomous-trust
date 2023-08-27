import os
from queue import Empty
import asyncio
import quart

from autonomous_trust.core import AutonomousTrust, Process, ProcMeta, LogLevel
from autonomous_trust.core.config import Configuration, CfgIds, to_yaml_string
from autonomous_trust.core.config.generate import random_config
from autonomous_trust.core.system import queue_cadence
from autonomous_trust.core.network import Network, Message
from autonomous_trust.core.reputation.protocol import ReputationProtocol

from autonomous_trust.inspector.viz.server import VizServer
from autonomous_trust.inspector.viz.live_graph import LiveData
from autonomous_trust.inspector.viz.middleware import SassASGIMiddleware
from autonomous_trust.inspector.viz import network_graph as ng  # FIXME replace with map


class MissionProcess(Process, metaclass=ProcMeta,
                     proc_name='monitor', description='Silent system activity monitor'):
    command_deck = [item.value for item in CfgIds] + ['package_hash', 'log-level', 'processes']

    def __init__(self, configurations, subsystems, log_q, dependencies):
        super().__init__(configurations, subsystems, log_q, dependencies=dependencies)

    def process(self, queues, signal):
        while self.keep_running(signal):
            try:
                cmd = queues[self.name].get(block=True, timeout=self.q_cadence)
                if isinstance(cmd, str):
                    if cmd in self.command_deck:
                        obj = self.configs[cmd]
                        msg_str = str(obj)  # FIXME convert to json
                        # send straight to viz server
                        queues['main'].put(msg_str, block=True, timeout=self.q_cadence)
            except Empty:
                pass


class MissionVisualizer(VizServer):
    def __init__(self, directory, port, debug=False, size=12, data_q=None, finished=None):
        if finished is None:
            finished = lambda: None  # noqa
        self.finished = finished
        self.port = port
        print(' * Directory on host: %s' % directory)
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
                    if msg == 'done':
                        print(' * Simulation done')
                        break

                seconds, data, stop = graph.get_update()
                if stop:
                    break
                if data is not None:
                    await quart.websocket.send(data)
                await asyncio.sleep(seconds)


class MissionCoordinator(AutonomousTrust):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.add_worker(MissionProcess, self.system_dependencies)
        self.viz = None
        self.data_queue = self.queue_type()

    def init_tasking(self, queues):
        viz_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'viz'))
        self.viz = VizServer(viz_dir, 8000, data_q=self.data_queue, finished=self.cleanup)
        self.viz.run()

    def autonomous_tasking(self, queues):
        if self.tasking_tick(1):  # every 30 sec
            for peer in self.peers.all:
                query = Message(CfgIds.reputation, ReputationProtocol.rep_req,
                                to_yaml_string((peer, self.proc_name)), self.identity)
                queues[CfgIds.reputation].put(query, block=True, timeout=queue_cadence)
                ping = Message(CfgIds.network, Network.ping, 5, peer, return_to=self.name)
                queues[CfgIds.network].put(ping, block=True, timeout=queue_cadence)
        if self.tasking_tick(2, 5.0):  # every 5 sec
            # FIXME peer connections?? (i.e. peers of peers of ...)
            for peer_id in self.latest_reputation:
                self.data_queue.put((LiveData.reputation, self.latest_reputation[peer_id]),
                                    block=True, timeout=queue_cadence)
            for message in list(self.unhandled_messages):
                if message.function == Network.ping:
                    self.unhandled_messages.remove(message)
                    self.data_queue.put((LiveData.latencies, message.obj),
                                        block=True, timeout=queue_cadence)
            self._report_unhandled()

    def cleanup(self):
        self.viz.stop()


if __name__ == '__main__':
    random_config(os.path.join(os.path.dirname(__file__)), 'mission')  # FIXME fixed config
    MissionCoordinator(log_level=LogLevel.INFO, logfile=Configuration.log_stdout).run_forever()
