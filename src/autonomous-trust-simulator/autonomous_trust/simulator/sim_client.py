import logging
import struct
import threading
from typing import Optional, Callable

from . import sim_net as net
from .sim_data import SimState


class SimClient(net.Client):
    seq_fmt = '!LL'

    def __init__(self, callback: Optional[Callable[[SimState], None]] = None, logger: logging.Logger = None):
        super().__init__(logger)
        self.callback = callback
        if callback is None:
            self.callback = lambda _: None
        self._tick = 0
        self._cadence = 1
        self._resolution = 0
        # FIXME lock within multiprocessing does not work
        #self.lock = threading.Lock()

    def idle(self):
        self.callback(SimState(blank=True))  # put into paused state

    @property
    def tick(self):
        return self._tick

    @tick.setter
    def tick(self, val: int):
        #with self.lock:
            self._tick = val

    @property
    def cadence(self):
        return self._cadence

    @cadence.setter
    def cadence(self, val: int):
        #with self.lock:
            self._cadence = val

    @property
    def resolution(self):
        return self._resolution

    @resolution.setter
    def resolution(self, val: int):
        #with self.lock:
            self._resolution = val

    def recv_data(self, **kwargs) -> Optional[SimState]:  # asynchronous
        if self.is_connected:
            #with self.lock:
            t_data = struct.pack(self.seq_fmt, self._tick, self._resolution)
            self._tick += self._cadence
            try:
                self.sock.send(t_data)  # query server
            except ConnectionError:
                if self.logger is not None:
                    self.logger.info('Lost connection to Simulator')
                return  # should auto-reconnect

            try:
                hdr, serialized = self.recv_all()
                info = serialized.decode()
                if info == 'end':
                    if self.logger is not None:
                        self.logger.info('Reset simulation')
                    self.tick = 0
                    self.callback(SimState(blank=True))
                    return
                state = SimState.from_yaml_string(info)
                self.callback(state)
            except net.ReceiveError:
                if self.logger is not None:
                    self.logger.warning('ReceiveError: server disconnect')
                self.halt = True  # assume server halted
        return
