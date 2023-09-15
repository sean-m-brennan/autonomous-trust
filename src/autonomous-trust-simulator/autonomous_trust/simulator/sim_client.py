import logging
import struct
import threading
from typing import Optional, Callable

from . import net_util as net
from .sim_data import SimState


class SimClient(net.Client):
    seq_fmt = '!LL'

    def __init__(self, callback: Optional[Callable[[SimState], None]] = None, logger: logging.Logger = None):
        super().__init__(logger)
        self.callback = callback
        self._tick = 0
        self._cadence = 1
        self._resolution = 0
        self.lock = threading.Lock()

    @property
    def tick(self):
        return self._tick

    @tick.setter
    def tick(self, val: int):
        with self.lock:
            self._tick = val

    @property
    def cadence(self):
        return self._cadence

    @cadence.setter
    def cadence(self, val: int):
        with self.lock:
            self._cadence = val

    @property
    def resolution(self):
        return self._resolution

    @resolution.setter
    def resolution(self, val: int):
        with self.lock:
            self._resolution = val

    def recv_data(self, **kwargs) -> Optional[SimState]:  # asynchronous
        if self.connected:
            with self.lock:
                t_data = struct.pack(self.seq_fmt, self._tick, self._resolution)
                self._tick += self._cadence
            self.sock.send(t_data)  # query server

            try:
                hdr, serialized = self.recv_all()
                info = serialized.decode()
                if info == 'end':
                    if self.logger is not None:
                        self.logger.info('Reset simulation')
                    self.tick = 0
                    if self.callback is not None:
                        self.callback(SimState(blank=True))
                    return
                state = SimState.from_yaml_string(info)
                if self.callback is not None:
                    self.callback(state)
            except net.ReceiveError:
                if self.logger is not None:
                    self.logger.warning('ReceiveError: server disconnect')
                self.halt = True  # assume server halted
        return
