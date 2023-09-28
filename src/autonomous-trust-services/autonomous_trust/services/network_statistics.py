from datetime import datetime
from queue import Full, Empty

import psutil

from autonomous_trust.core import Process, ProcMeta, Configuration, CfgIds, to_yaml_string
from autonomous_trust.core.identity import Identity
from autonomous_trust.core.network import Message
from autonomous_trust.core.protocol import Protocol


class NetworkStats(Configuration):
    def __init__(self, up: float, down: float, sent: float, recv: float, err_out: int, err_in: int):
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
    def acquire(self, uuid: str) -> tuple[float, float]:
        raise NotImplementedError  # FIXME can NetworkProcess track stats?


class NetStatsSource(Process, metaclass=ProcMeta,
                     proc_name='net-stats-source', description='Network statistics service'):
    def __init__(self, configurations, subsystems, log_queue, dependencies, **kwargs):
        super().__init__(configurations, subsystems, log_queue, dependencies=dependencies)
        self.protocol = NetStatsProtocol(self.name, self.logger, configurations[CfgIds.peers])
        self.protocol.register_handler(NetStatsProtocol.request, self.handle_requests)
        self.clients: dict[str, tuple[bool, str, Identity]] = {}
        self.network_source = kwargs.get('network_source', NetworkSource())
        self.latest = self.acquire_totals()

    @staticmethod
    def acquire_totals():
        net_io = psutil.net_io_counters()
        return datetime.utcnow(), net_io.bytes_sent, net_io.bytes_recv, net_io.errout, net_io.errin

    def compute_rate(self):
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
        while self.keep_running(signal):
            try:
                message = queues[self.name].get(block=True, timeout=self.q_cadence)
            except Empty:
                message = None
            if message:
                if not self.protocol.run_message_handlers(queues, message):
                    if isinstance(message, Message):
                        self.logger.error('Unhandled message %s' % message.function)
                    else:
                        self.logger.error('Unhandled message of type %s' % message.__class__.__name__)  # noqa

            statistics = {'total': NetworkStats(*self.compute_rate(), *self.latest)}
            try:
                for peer in self.clients:
                    statistics[peer] = NetworkStats(*self.network_source.acquire(peer))
            except NotImplementedError:
                pass
            obj = to_yaml_string(statistics)
            for peer in self.clients:
                msg = Message('daq', NetStatsProtocol.stats, obj, peer)
                try:
                    queues[CfgIds.network].put(msg, block=True, timeout=self.q_cadence)
                except Full:
                    pass

            self.sleep_until(self.cadence)
