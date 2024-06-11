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

import logging
import struct
import threading
from datetime import datetime, timedelta
from typing import Optional, Callable

from . import sim_net as net
from .sim_data import SimState


class SimClient(net.Client):
    seq_fmt = '!LL'

    def __init__(self, callback: Optional[Callable[[SimState], None]] = None, logger: logging.Logger = None,
                 passive: bool = True):
        super().__init__(logger)
        self.callback = callback
        if callback is None:
            self.callback = lambda _: None
        self._passive = passive
        self._tick = 1
        self._cadence = 1
        self._resolution = 0
        # FIXME lock within multiprocessing does not work
        #self.lock = threading.Lock()
        self.last = None

    @property
    def tick(self):
        return self._tick

    @property
    def cadence(self):
        return self._cadence

    @cadence.setter
    def cadence(self, val: int):  # FIXME remove
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
            tick = self._tick
            res = self._resolution
            if self._passive:
                res = tick = 0
            t_data = struct.pack(self.seq_fmt, tick, res)
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
                    if not self._passive:
                        self._tick = 0
                    self.callback(SimState(blank=True))
                    return
                state = SimState.from_yaml_string(info)
                #self.logger.debug('** Block')  # FIXME
                self.callback(state)
                #self.logger.debug('** Unblock')
                if not self._passive:
                    self._tick += self._cadence  # successful, so can progress
                now = datetime.now()
                if self.last is not None:
                    interval: timedelta = self.last - now
                    if interval > timedelta(seconds=1):
                        self.logger.debug('Data retrieval too slow: %f', interval.total_seconds())
                self.last = now
            except net.ReceiveError as err:
                if self.logger is not None:
                    self.logger.warning('ReceiveError: server disconnect (%s)' % err)
                self.halt = True  # assume server halted
        else:
            self.logger.debug('Not connected')
        return
