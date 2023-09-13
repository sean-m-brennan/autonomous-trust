import time
from typing import Optional, Callable

from . import net_util as net
from .sim_data import SimState


class SimClient(net.Client):
    header_fmt = '!Q'

    def __init__(self, callback: Optional[Callable[[SimState], None]] = None, debug: bool = False):
        super().__init__(debug)
        self.callback = callback

    def recv_data(self, **kwargs) -> Optional[SimState]:
        if not self.is_socket_closed():
            self.sock.send('1'.encode())  # trigger server
            _, serialized = self.recv_all(self.header_fmt)
            if serialized is None:
                return
            data = SimState.from_yaml_string(serialized.decode())
            if self.callback is not None:
                self.callback(data)
            return data
        time.sleep(0.5)
        return
