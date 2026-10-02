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
"""µD3TN over AAP 2.0: the Python twin of src/c/extensions/dtn/
dtn_backend_ud3tnv2.c, speaking the same protocol the same way.

Framing, per socket: ``varint(len) | AAPMessage`` and ``varint(len) |
AAPResponse``. A BundleADU's payload follows its message as raw bytes, outside
the protobuf envelope.

Topology: one SENDER connection registered to the primary endpoint (the source
EID of every send), and one SUBSCRIBER connection per endpoint, each with a
reader thread that queues what the daemon pushes and answers SUCCESS.

Handshake, on every socket: the daemon writes a bare 0x2F (its AAP v1 reject
marker), then a Welcome; we ACK it, send a ConnectionConfig, and expect
SUCCESS.

The daemon is at ``AT_DTN_UD3TN_SOCKET`` (``unix:/path`` or ``tcp:host:port``;
default ``unix:./ud3tn.aap2.socket``), the variable C reads.

The schema is the vendored ``aap2.proto`` (src/c/extensions/dtn/proto/), whose
Python bindings ``scripts/build-py.sh`` generates beside this module as
``aap2_pb2.py``. Three differences from C, all about a daemon that misbehaves:
a send waits at most :data:`SEND_TIMEOUT_S` for its response, where C waits
indefinitely while holding the send lock; a receive with no live reader waits
out its timeout instead of returning at once; and a pushed bundle over
:data:`MAX_PAYLOAD` closes that subscriber, where C acknowledges it and reads
its unread payload as the next frame.
"""
import collections
import os
import socket
import threading

from .backend import Backend, BackendError, Bundle

SOCKET_ENV = 'AT_DTN_UD3TN_SOCKET'
DEFAULT_SOCKET = 'unix:./ud3tn.aap2.socket'

V1_REJECT_BYTE = 0x2F
MAX_MESSAGE = 1024 * 1024          # protobuf envelope cap (C's AAP2_MAX_MESSAGE)
MAX_PAYLOAD = 16 * 1024 * 1024     # C's AAP2_MAX_PAYLOAD
INBOUND_QUEUE_CAP = 64             # oldest dropped beyond this, as in C
MAX_ENDPOINTS = 4
SEND_TIMEOUT_S = 30.0


def _pb():
    try:
        from . import aap2_pb2
    except ImportError as err:
        raise BackendError('the AAP 2.0 bindings (aap2_pb2.py) are not generated; run '
                           'scripts/build-py.sh proto-only (%s)' % err) from err
    return aap2_pb2


# ---------- framing ----------

def encode_varint(value: int) -> bytes:
    """Proto3 varint: seven bits a byte, low first, high bit = more."""
    if value < 0:
        raise ValueError('varint of a negative number')
    out = bytearray()
    while value >= 0x80:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def _read_exact(sock, count: int) -> bytes:
    buf = bytearray()
    while len(buf) < count:
        chunk = sock.recv(count - len(buf))
        if not chunk:
            raise BackendError('AAP 2.0 connection closed')
        buf += chunk
    return bytes(buf)


def read_varint(sock) -> int:
    value = 0
    shift = 0
    for _ in range(10):
        byte = _read_exact(sock, 1)[0]
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value
        shift += 7
    raise BackendError('AAP 2.0 varint longer than ten bytes')


def frame(message) -> bytes:
    """``message`` serialized behind its varint length."""
    body = message.SerializeToString()
    if len(body) > MAX_MESSAGE:
        raise BackendError('AAP 2.0 message of %d bytes exceeds %d' % (len(body), MAX_MESSAGE))
    return encode_varint(len(body)) + body


def _read_envelope(sock) -> bytes:
    size = read_varint(sock)
    if size == 0 or size > MAX_MESSAGE:
        raise BackendError('AAP 2.0 envelope of %d bytes refused' % size)
    return _read_exact(sock, size)


def read_message(sock):
    msg = _pb().AAPMessage()
    msg.ParseFromString(_read_envelope(sock))
    return msg


def read_response(sock):
    resp = _pb().AAPResponse()
    resp.ParseFromString(_read_envelope(sock))
    return resp


def write_response(sock, status: int) -> None:
    sock.sendall(frame(_pb().AAPResponse(response_status=status)))


# ---------- connection ----------

def connect(url: str | None):
    """A connected stream socket for ``url`` (``unix:``, ``tcp:``, or a bare
    unix path), in blocking mode whatever the process default is."""
    url = url or DEFAULT_SOCKET
    try:
        if url.startswith('tcp:'):
            rest = url[4:]
            host, sep, port = rest.rpartition(':')
            if not sep or not host:
                raise BackendError('malformed tcp: URL %r' % url)
            if host.startswith('[') and host.endswith(']'):
                host = host[1:-1]
            sock = socket.create_connection((host, int(port)), timeout=None)
        else:
            path = url[5:] if url.startswith('unix:') else url
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(None)
            try:
                sock.connect(path)
            except OSError:
                sock.close()
                raise
    except (OSError, ValueError) as err:
        raise BackendError('DTN[ud3tnv2]: connect(%s): %s' % (url, err)) from err
    sock.settimeout(None)
    return sock


def handshake(sock, eid: str, is_subscriber: bool, logger=None) -> None:
    """Greeting, Welcome, ACK, ConnectionConfig, SUCCESS -- or BackendError."""
    pb = _pb()
    greeting = _read_exact(sock, 1)[0]
    if greeting != V1_REJECT_BYTE:
        raise BackendError('DTN[ud3tnv2]: expected AAP 2.0 greeting 0x%02x, got 0x%02x '
                           '(is the daemon in v1 mode?)' % (V1_REJECT_BYTE, greeting))
    welcome = read_message(sock)
    if welcome.WhichOneof('msg') != 'welcome':
        raise BackendError('DTN[ud3tnv2]: first frame was not Welcome (%s)'
                           % welcome.WhichOneof('msg'))
    if logger is not None and welcome.welcome.node_id:
        logger.info('DTN[ud3tnv2]: connected to node_id=%s', welcome.welcome.node_id)
    write_response(sock, pb.RESPONSE_STATUS_ACK)
    cfg = pb.AAPMessage(config=pb.ConnectionConfig(
        is_subscriber=is_subscriber, auth_type=pb.AUTH_TYPE_DEFAULT,
        endpoint_id=eid, keepalive_seconds=0))
    sock.sendall(frame(cfg))
    resp = read_response(sock)
    if resp.response_status != pb.RESPONSE_STATUS_SUCCESS:
        raise BackendError('DTN[ud3tnv2]: ConnectionConfig rejected (status=%d) for eid=%s'
                           % (resp.response_status, eid))


class Aap2Backend(Backend):
    name = 'ud3tnv2'

    def __init__(self):
        self._sender = None
        self._primary = None
        self._send_lock = threading.Lock()
        self._subs = []          # [(socket, eid, service)]
        self._readers = []
        self._queue = collections.deque()
        self._cond = threading.Condition()
        self._live_readers = 0
        self._stop = False
        self._logger = None

    def init(self, endpoints, logger) -> None:
        if not 0 < len(endpoints) <= MAX_ENDPOINTS:
            raise BackendError('DTN[ud3tnv2]: invalid endpoint count %d (max %d)'
                               % (len(endpoints), MAX_ENDPOINTS))
        if self._sender is not None or self._subs:
            raise BackendError('DTN[ud3tnv2]: already initialized')
        self._logger = logger
        self._stop = False
        url = os.environ.get(SOCKET_ENV) or None
        try:
            self._primary = endpoints[0][0]
            self._sender = connect(url)
            handshake(self._sender, self._primary, False, logger)
            self._sender.settimeout(SEND_TIMEOUT_S)
            for eid, service in endpoints:
                sock = connect(url)
                self._subs.append((sock, eid, service))
                handshake(sock, eid, True, logger)
        except (BackendError, OSError) as err:
            self.shutdown()
            raise err if isinstance(err, BackendError) else BackendError(str(err))
        for idx in range(len(self._subs)):
            thread = threading.Thread(target=self._reader, args=(idx,), daemon=True,
                                      name='dtn-aap2-%d' % idx)
            with self._cond:
                self._live_readers += 1
            thread.start()
            self._readers.append(thread)
        logger.info('DTN[ud3tnv2]: ready -- sender=%s + %d subscribers on %s',
                    self._primary, len(self._subs), url or DEFAULT_SOCKET)
        for idx, (_, eid, service) in enumerate(self._subs):
            logger.info('DTN[ud3tnv2]:   [%d] %s -> %s', idx, eid, service)

    def _enqueue(self, bundle: Bundle) -> None:
        with self._cond:
            if len(self._queue) >= INBOUND_QUEUE_CAP:
                self._queue.popleft()
            self._queue.append(bundle)
            self._cond.notify()

    def _reader(self, idx: int) -> None:
        pb = _pb()
        sock, _, service = self._subs[idx]
        try:
            while not self._stop:
                msg = read_message(sock)
                if msg.WhichOneof('msg') == 'adu':
                    adu = msg.adu
                    if adu.payload_length > MAX_PAYLOAD:
                        if self._logger is not None:
                            self._logger.error('DTN[ud3tnv2]: inbound payload too large (%d)',
                                               adu.payload_length)
                        break  # the stream is unframed from here
                    payload = _read_exact(sock, adu.payload_length) if adu.payload_length else b''
                    self._enqueue(Bundle(payload, adu.src_eid, service))
                # A keepalive, or anything a subscriber should not be sent, is
                # acknowledged and otherwise ignored, as in C.
                write_response(sock, pb.RESPONSE_STATUS_SUCCESS)
        except (BackendError, OSError) as err:
            if not self._stop and self._logger is not None:
                self._logger.warning('DTN[ud3tnv2]: reader for %s stopped: %s', service, err)
        finally:
            with self._cond:
                self._live_readers -= 1
                self._cond.notify_all()

    def shutdown(self) -> None:
        with self._cond:
            self._stop = True
            self._cond.notify_all()
        for sock, _, _ in self._subs:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        if self._sender is not None:
            try:
                self._sender.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        for thread in self._readers:
            thread.join(timeout=5)
        for sock, _, _ in self._subs:
            sock.close()
        if self._sender is not None:
            self._sender.close()
        self._sender = None
        self._subs = []
        self._readers = []
        with self._cond:
            self._queue.clear()
            self._live_readers = 0

    def send(self, dest_eid, payload, lifetime_sec) -> None:
        # AAP 2.0's BundleADU has no lifetime; the daemon's default applies (C
        # ignores it too).
        pb = _pb()
        if self._sender is None or len(payload) > MAX_PAYLOAD:
            raise BackendError('DTN[ud3tnv2]: not open, or payload over %d bytes' % MAX_PAYLOAD)
        msg = pb.AAPMessage(adu=pb.BundleADU(src_eid=self._primary, dst_eid=dest_eid,
                                             payload_length=len(payload)))
        with self._send_lock:
            try:
                self._sender.sendall(frame(msg) + bytes(payload))
                resp = read_response(self._sender)
            except OSError as err:
                raise BackendError('DTN[ud3tnv2]: send to %s: %s' % (dest_eid, err)) from err
        if resp.response_status != pb.RESPONSE_STATUS_SUCCESS:
            raise BackendError('DTN[ud3tnv2]: send to %s got status=%d'
                               % (dest_eid, resp.response_status))

    def recv(self, timeout_s) -> Bundle | None:
        with self._cond:
            if not self._queue and not self._stop:
                self._cond.wait_for(lambda: self._queue or self._stop, timeout=timeout_s)
            if self._queue:
                return self._queue.popleft()
            if self._stop:
                raise BackendError('DTN[ud3tnv2]: backend shut down')
            return None
