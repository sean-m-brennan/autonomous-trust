from datetime import datetime, timedelta
from queue import Full, Empty

import psutil

from autonomous_trust.core import Process, ProcMeta, Configuration, CfgIds, to_yaml_string
from autonomous_trust.core.identity import Identity
from autonomous_trust.core.network import Message, Network
from autonomous_trust.core.protocol import Protocol


class NetworkStats(Configuration):
    def __init__(self, up: float, down: float, sent: int, recv: int, err_out: int, err_in: int):
        self.up = up
        self.down = down
        self.sent = sent
        self.recv = recv
        self.err_out = err_out
        self.err_in = err_in


class NetStatsProtocol(Protocol):
    request = 'request'
    stats = 'stats'


class NetworkSource(object):
    query_cadence = 1

    def __init__(self, proc_name, cadence):
        self.name = proc_name
        self.q_cadence = cadence
        self.latest = {}
        self.net_queue = None
        self.last_acq = datetime.now() - timedelta(seconds=60)

    def recv(self, net_stats):
        self.latest = net_stats

    def acquire(self, uuid: str = None) -> tuple[float, float, int, int, int, int]:
        """Returns a tuple of up rate, down rate, bytes sent, bytes recvd, errors out, errors in"""
        now = datetime.now()
        if (now - self.last_acq).total_seconds() > self.query_cadence:
            msg = Message(self.name, Network.stats_req, None)
            self.net_queue.put(msg, block=True, timeout=self.q_cadence)
        if uuid is None:
            uuid = '0'
        return self.latest.get(uuid, (0., 0., 0, 0, 0, 0))


class NetStatsSource(Process, metaclass=ProcMeta,
                     proc_name='net-stats-source', description='Network statistics service'):
    def __init__(self, configurations, subsystems, log_queue, dependencies):
        super().__init__(configurations, subsystems, log_queue, dependencies=dependencies)
        self.protocol = NetStatsProtocol(self.name, self.logger, configurations[CfgIds.peers])
        self.protocol.register_handler(NetStatsProtocol.request, self.handle_requests)
        self.clients: dict[str, tuple[bool, str, Identity]] = {}
        self.network_source = NetworkSource(self.name, self.q_cadence)
        self.latest = self.acquire_totals()

    @staticmethod
    def acquire_totals():
        net_io = psutil.net_io_counters()
        return datetime.utcnow(), net_io.bytes_sent, net_io.bytes_recv, net_io.errout, net_io.errin

    def compute_rate(self):  # for totals
        current = self.acquire_totals()
        elapsed = (current[0] - self.latest[0]).total_seconds()
        up, down = (current[1] - self.latest[1]) / elapsed, (current[2] - self.latest[2]) / elapsed
        self.latest = current
        return up, down

    def handle_requests(self, _, message):
        if message.function == NetStatsProtocol.request:
            uuid = message.from_whom.uuid
            if uuid not in self.clients:
                self.clients[uuid] = message.from_whom
            return True
        return False

    def process(self, queues, signal):
        self.network_source.net_queue = queues[CfgIds.network]
        while self.keep_running(signal):
            try:
                message = queues[self.name].get(block=True, timeout=self.q_cadence)
            except Empty:
                message = None
            if message:
                if not self.protocol.run_message_handlers(queues, message):
                    if message.function == Network.stats_resp:
                        self.network_source.recv(message.obj)
                    elif isinstance(message, Message):
                        self.logger.error('Unhandled message %s' % message.function)
                    else:
                        self.logger.error('Unhandled message of type %s' % message.__class__.__name__)  # noqa

            statistics = {'total': NetworkStats(*self.compute_rate(), *(self.latest[1:]))}
            try:
                for peer in self.clients:
                    statistics[peer] = NetworkStats(*self.network_source.acquire(peer))
            except NotImplementedError:
                pass

            # ship it to consumer UI
            obj = to_yaml_string(statistics)
            for peer in self.clients:
                msg = Message(self.name, NetStatsProtocol.stats, obj, peer)
                try:
                    queues[CfgIds.network].put(msg, block=True, timeout=self.q_cadence)
                except Full:
                    pass

            self.sleep_until(self.cadence)
