import asyncio

from .ping import PingStats, ping_rcv_port, ping_snd_port
from ..system import now


class _PingServerProtocol(object):
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


class _PingClientProtocol(_PingServerProtocol):
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


class _PingServer(object):
    def __init__(self, transport, protocol):
        self.transport = transport
        self.protocol = protocol

    def close(self):
        self.transport.close()


async def AsyncPingServer(host='0.0.0.0'):  # noqa
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(lambda: _PingServerProtocol(),  # noqa
                                                              local_addr=(host, ping_rcv_port))
    return _PingServer(transport, protocol)


async def async_ping(host: str, seq_num: int = None, count: int = 1, timeout: float = 1.0) -> PingStats:
    if seq_num is None:
        seq_num = 1
    try:
        data = seq_num.to_bytes(4, 'big')
    except OverflowError:
        data = (1).to_bytes(4, 'big')
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(lambda: _PingClientProtocol(),  # noqa
                                                              local_addr=('0.0.0.0', ping_snd_port),
                                                              remote_addr=(host, ping_rcv_port))
    times = {}
    start = now()
    end = now()
    for seq_num in range(1, count+1):
        init = now()
        protocol.sendto(data)
        try:
            packet = await asyncio.wait_for(protocol.recvfrom(), timeout=timeout)
        except asyncio.TimeoutError:
            packet = None
        end = now()
        if packet is None:
            times[seq_num] = None
            continue
        data = packet[0]
        protocol.raise_error()
        times[seq_num] = (end-init).total_seconds()
        await asyncio.sleep(1)  # FIXME remainder instead
    transport.close()
    return PingStats(host, times, (end-start))
