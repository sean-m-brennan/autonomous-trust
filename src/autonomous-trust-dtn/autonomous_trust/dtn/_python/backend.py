# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
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
"""Bundle Protocol backends: the Python twin of src/c/extensions/dtn/
dtn_backend.h. The transport talks to this interface only.

C picks its backend when it is built (``AT_NET_DTN_BACKEND``); Python picks it
when the transport opens, from ``AT_DTN_BACKEND``:

* ``stub`` (the default, as in C) -- no BP agent; sends are dropped, receives
  time out;
* ``ud3tnv2`` -- µD3TN over AAP 2.0 (:mod:`.aap2`), reached at
  ``AT_DTN_UD3TN_SOCKET``.

``ion`` and ``ud3tn`` (AAP v1) exist in C only, and are refused here by name.
"""
import os
import time

BACKEND_ENV = 'AT_DTN_BACKEND'
DEFAULT_BACKEND = 'stub'
C_ONLY = ('ion', 'ud3tn')


class BackendError(RuntimeError):
    """A backend could not be chosen, opened or used."""


class Bundle(object):
    """One inbound bundle: its payload, the sender's EID, and the service of
    the local endpoint it arrived on (which picks the channel)."""
    __slots__ = ('payload', 'src_eid', 'service')

    def __init__(self, payload: bytes, src_eid: str, service: str):
        self.payload = payload
        self.src_eid = src_eid
        self.service = service

    def __repr__(self):
        return 'Bundle(%d bytes from %s on %s)' % (len(self.payload), self.src_eid, self.service)


class Backend(object):
    """One BP agent connection. ``endpoints`` is ``[(eid, service), ...]``; the
    first is the primary, the source EID of every send."""
    name = 'abstract'

    def init(self, endpoints, logger) -> None:
        raise NotImplementedError

    def shutdown(self) -> None:
        raise NotImplementedError

    def send(self, dest_eid: str, payload: bytes, lifetime_sec: int) -> None:
        """Hand one bundle to the local agent; raises :class:`BackendError`."""
        raise NotImplementedError

    def recv(self, timeout_s: float) -> Bundle | None:
        """The next inbound bundle on any endpoint, or None after
        ``timeout_s``."""
        raise NotImplementedError


class StubBackend(Backend):
    """No BP agent, as C's dtn_backend_stub.c: every send succeeds and goes
    nowhere, and a receive waits out its timeout and returns nothing."""
    name = 'stub'

    def init(self, endpoints, logger) -> None:
        for idx, (eid, service) in enumerate(endpoints):
            logger.info('DTN[stub]: init endpoint[%d] eid=%s service=%s (no real BP agent)',
                        idx, eid, service)

    def shutdown(self) -> None:
        pass

    def send(self, dest_eid, payload, lifetime_sec) -> None:
        pass

    def recv(self, timeout_s) -> Bundle | None:
        if timeout_s > 0:
            time.sleep(timeout_s)
        return None


def backend_name() -> str:
    return os.environ.get(BACKEND_ENV, '').strip().lower() or DEFAULT_BACKEND


def make_backend(name: str | None = None) -> Backend:
    """The backend ``name`` (default: ``AT_DTN_BACKEND``, else ``stub``)."""
    name = name or backend_name()
    if name == 'stub':
        return StubBackend()
    if name == 'ud3tnv2':
        from .aap2 import Aap2Backend
        return Aap2Backend()
    if name in C_ONLY:
        raise BackendError('%s=%s: the %s backend exists only in the C runtime (libat_dtn); '
                           'Python has stub and ud3tnv2' % (BACKEND_ENV, name, name))
    raise BackendError('%s=%s: unknown DTN backend (want stub or ud3tnv2)' % (BACKEND_ENV, name))
