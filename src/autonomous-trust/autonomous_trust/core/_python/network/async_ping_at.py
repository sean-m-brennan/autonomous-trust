# ******************
#  Copyright 2023 TekFive, Inc., Sean M. Brennan, and contributors
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

import asyncio

from .ping_at import PingATStats, local_address_toward, ping_at_rcv_port, ping_at_snd_port
from ..system import now


class _PingATServerProtocol(object):
    def __init__(self):
        self._error = None
        self._transport = None

    def connection_made(self, transport):
        self._transport = transport

    def connection_lost(self, transport):
        pass

    def datagram_received(self, data, addr):
        try:
            seq_num = int.from_bytes(data, 'big')
            data = (seq_num + 1).to_bytes(4, 'big')
        except OverflowError:
            data = (1).to_bytes(4, 'big')
        self._transport.sendto(data, addr)

    def error_received(self, exc):
        self._error = exc

    def raise_error(self):
        if self._error is None:
            return
        error = self._error
        self._error = None
        raise error


class _PingATClientProtocol(_PingATServerProtocol):
    def __init__(self, max_q=0):
        super().__init__()
        self._packets = asyncio.Queue(max_q)

    def connection_lost(self, transport):
        self._packets.put_nowait(None)

    def datagram_received(self, data, addr):
        self._packets.put_nowait((data, addr))

    def error_received(self, err):
        super().error_received(err)
        self._packets.put_nowait(None)

    def sendto(self, data):
        self._transport.sendto(data)
        self.raise_error()

    async def recvfrom(self):
        return await self._packets.get()


class _PingATServer(object):
    def __init__(self, transport, protocol):
        self.transport = transport
        self.protocol = protocol

    def close(self):
        self.transport.close()


async def AsyncPingATServer(host='0.0.0.0'):  # noqa
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(lambda: _PingATServerProtocol(),  # noqa
                                                              local_addr=(host, ping_at_rcv_port))
    return _PingATServer(transport, protocol)


async def async_ping_at(host: str, seq_num: int = None, count: int = 1, timeout: float = 1.0,
                        local_address: str = None) -> PingATStats:
    """Async twin of ping_at(); see it for the local_address contract.

    `local_addr` here binds the reply socket to a specific address rather than
    the wildcard, so co-located nodes separated only by address do not receive
    each other's ping replies. asyncio's datagram endpoint does not set
    SO_REUSEADDR, so a genuine collision raises OSError from create_datagram_endpoint.
    """
    if seq_num is None:
        seq_num = 1
    try:
        data = seq_num.to_bytes(4, 'big')
    except OverflowError:
        data = (1).to_bytes(4, 'big')
    if local_address is None:
        local_address = local_address_toward(host)
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(lambda: _PingATClientProtocol(),  # noqa
                                                              local_addr=(local_address or '0.0.0.0',
                                                                          ping_at_snd_port),
                                                              remote_addr=(host, ping_at_rcv_port))
    times = {}
    start = now()
    end = now()
    for s_num in range(1, count+1):
        init = now()
        protocol.sendto(data)
        try:
            packet = await asyncio.wait_for(protocol.recvfrom(), timeout=timeout)
        except asyncio.TimeoutError:
            packet = None
        end = now()
        if packet is None:
            times[s_num] = None
            continue
        data = packet[0]
        protocol.raise_error()
        elapsed = (end-init).total_seconds()
        times[seq_num] = elapsed
        remainder = 1.0 - elapsed
        if remainder > 0:
            await asyncio.sleep(remainder)
    transport.close()
    return PingATStats(host, times, (end-start))
