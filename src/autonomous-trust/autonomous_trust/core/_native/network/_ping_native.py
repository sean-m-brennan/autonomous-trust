# ******************
#  Copyright 2025 Sean M. Brennan and contributors
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

"""Wrapper for C ``ping()`` and ``ping_stats_t``."""

from datetime import timedelta

from .._ffi import ffi, lib

# Re-export Python PingServer (no native C equivalent)
from ..._python.network.ping import PingServer  # noqa: F401


PING_COUNT = 4
PING_TIMEOUT_MS = 2000


class PingStats:
    """Wrapper around C ``ping_stats_t``."""

    __slots__ = ('_ptr',)

    def __init__(self, *, _ptr=None):
        if _ptr is None:
            _ptr = ffi.new('ping_stats_t *')
        self._ptr = _ptr

    @property
    def host(self) -> str:
        return ffi.string(self._ptr.host).decode('ascii')

    @property
    def rtt_ms(self) -> list[float]:
        return [self._ptr.rtt_ms[i] for i in range(PING_COUNT)]

    @property
    def min_rtt(self) -> timedelta:
        return timedelta(milliseconds=self._ptr.min_rtt)

    @property
    def max_rtt(self) -> timedelta:
        return timedelta(milliseconds=self._ptr.max_rtt)

    @property
    def avg_rtt(self) -> timedelta:
        return timedelta(milliseconds=self._ptr.avg_rtt)

    @property
    def loss(self) -> float:
        return self._ptr.loss

    @property
    def sent(self) -> int:
        return self._ptr.sent

    @property
    def received(self) -> int:
        return self._ptr.received

    def __repr__(self):
        return (f'PingStats(host={self.host!r}, '
                f'avg={self._ptr.avg_rtt:.2f}ms, '
                f'loss={self.loss:.1%})')


def ping(host: str, count: int = 1) -> PingStats:
    """Ping a host and return statistics (C implementation)."""
    stats = ffi.new('ping_stats_t *')
    host_buf = ffi.new('char[]', host.encode('ascii'))
    # 2nd arg is the ping count; the cdef/wrapper previously omitted it, so the
    # C side read a garbage count. Default 1 matches the pure-Python ping().
    rc = lib.ping(host_buf, count, stats)
    if rc != 0:
        raise RuntimeError(f"ping failed with rc={rc}")
    return PingStats(_ptr=stats)
