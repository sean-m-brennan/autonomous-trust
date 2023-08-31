import socket
import time

from . import net_util as net
from .peer.peer import Peer
from .radio.routing import Router
from .sim_data import SimConfig, SimState, Map, Matrix


class Simulator(net.SelectServer):
    header_fmt = Router.header_fmt

    def __init__(self, cfg_file_path: str, max_time_steps: int = 100, cadence: int = 1):
        super().__init__()
        self.max_time_steps = max_time_steps
        self.cadence = cadence

        with open(cfg_file_path, 'r') as cfg_file:
            self.cfg = SimConfig.load(cfg_file.read())
        self.peers: dict[str, Peer] = {}
        for peer_info in self.cfg.peers:
            self.peers[peer_info.uuid] = Peer(self.max_time_steps, self.cadence, peer_info.path)
        self.state = SimState()
        self.pre_state: dict[int, tuple[Map, Matrix]] = {}

        # precompute network changes
        for tick in range(1, self.max_time_steps+1):
            mapp = {}
            matrix = {}
            for peer in self.cfg.peers:
                mapp[peer.uuid] = self.peers[peer.uuid].move(tick)
            for peer in self.cfg.peers:
                matrix[peer.uuid] = {}
                for other in self.cfg.peers:
                    if peer == other:
                        continue
                    matrix[peer.uuid][other.uuid] = peer.can_reach(other)
            self.pre_state[tick] = (mapp, matrix)
        self.tick = 0

    def recv_data(self, sock: socket.socket):
        sock.recv(1024)  # should be empty
        message = self.prepend_header(self.header_fmt, self.state.to_json())
        sock.sendall(message)

    def send_data(self, sock: socket.socket):
        pass  # do nothing

    def process(self, **kwargs):
        while not self.halt and self.tick <= self.max_time_steps:
            self.state = SimState(*self.pre_state[self.tick])
            self.tick += 1
            time.sleep(self.cadence)


if __name__ == '__main__':  # FIXME remove
    Simulator('config.cfg').run(8888)  # FIXME create config
