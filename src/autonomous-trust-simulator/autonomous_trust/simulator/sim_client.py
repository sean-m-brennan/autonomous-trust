import struct
from typing import Optional, Callable

from . import net_util as net
from .sim_data import SimState


class SimClient(net.Client):
    seq_fmt = '!L'

    def __init__(self, callback: Optional[Callable[[SimState], None]] = None, debug: bool = False):
        super().__init__(debug)
        self.callback = callback
        self.tick = 0

    def recv_data(self, **kwargs) -> Optional[SimState]:  # asynchronous
        if self.connected:
            t_data = struct.pack(self.seq_fmt, self.tick)
            self.sock.send(t_data)  # query server
            self.tick += 1
            try:
                hdr, serialized = self.recv_all()
                info = serialized.decode()
                if info == 'end':
                    self.tick = 0
                    if self.callback is not None:
                        self.callback(SimState(blank=True))
                    return
                state = SimState.from_yaml_string(info)
                if self.callback is not None:
                    self.callback(state)
            except net.ReceiveError:
                self.halt = True  # assume server halted
        return
