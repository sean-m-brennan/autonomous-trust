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
"""The µD3TN AAP 2.0 backend against a fake daemon that speaks the protocol as
dtn_backend_ud3tnv2.c's header describes it: the 0x2F greeting, Welcome, ACK,
ConnectionConfig, SUCCESS; then ADUs with their payload outside the envelope."""
import logging
import os
import socket
import tempfile
import threading

import pytest

from autonomous_trust.dtn import aap2
from autonomous_trust.dtn.backend import BackendError

pb = pytest.importorskip('autonomous_trust.dtn._python.aap2_pb2',
                         reason='AAP 2.0 bindings not generated (scripts/build-py.sh proto-only)')

LOG = logging.getLogger('aap2-test')


class FakeDaemon(object):
    """Routes each ADU a sender submits to the subscribers on its dst_eid."""

    def __init__(self, path, greeting=aap2.V1_REJECT_BYTE, config_status=None):
        self.path = path
        self.greeting = greeting
        self.config_status = config_status or pb.RESPONSE_STATUS_SUCCESS
        self.subscribers = {}           # eid -> socket
        self.configs = []               # (eid, is_subscriber)
        self.submitted = []             # (src, dst, payload)
        self.lock = threading.Lock()
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(path)
        self.server.listen(8)
        self.thread = threading.Thread(target=self._accept, daemon=True)
        self.thread.start()

    def _accept(self):
        while True:
            try:
                conn, _ = self.server.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        try:
            conn.sendall(bytes([self.greeting]))
            conn.sendall(aap2.frame(pb.AAPMessage(welcome=pb.Welcome(node_id='dtn://fake/'))))
            assert aap2.read_response(conn).response_status == pb.RESPONSE_STATUS_ACK
            cfg = aap2.read_message(conn).config
            with self.lock:
                self.configs.append((cfg.endpoint_id, cfg.is_subscriber))
            aap2.write_response(conn, self.config_status)
            if cfg.is_subscriber:
                with self.lock:
                    self.subscribers[cfg.endpoint_id] = conn
                return
            while True:
                msg = aap2.read_message(conn)
                adu = msg.adu
                payload = aap2._read_exact(conn, adu.payload_length) if adu.payload_length else b''
                with self.lock:
                    self.submitted.append((adu.src_eid, adu.dst_eid, payload))
                    sub = self.subscribers.get(adu.dst_eid)
                if sub is not None:
                    push = pb.AAPMessage(adu=pb.BundleADU(src_eid=adu.src_eid, dst_eid=adu.dst_eid,
                                                          payload_length=len(payload)))
                    sub.sendall(aap2.frame(push) + payload)
                aap2.write_response(conn, pb.RESPONSE_STATUS_SUCCESS)
        except (BackendError, OSError, AssertionError):
            conn.close()

    def close(self):
        self.server.close()


@pytest.fixture
def sock_dir():
    with tempfile.TemporaryDirectory(prefix='aap2') as tmp:
        yield tmp


ENDPOINTS = [('dtn://at-aaaaaaaa/peer', '/peer'),
             ('dtn://at-group-41542d626f6f7400/bcast', '/bcast'),
             ('dtn://at-group-41542d626f6f7400/group', '/group')]


def test_varint_round_trip():
    a, b = socket.socketpair()
    with a, b:
        for value in (0, 1, 127, 128, 300, 2 ** 32, 2 ** 63):
            a.sendall(aap2.encode_varint(value))
            assert aap2.read_varint(b) == value


def test_handshake_send_and_receive(sock_dir, monkeypatch):
    path = os.path.join(sock_dir, 'd.sock')
    daemon = FakeDaemon(path)
    monkeypatch.setenv(aap2.SOCKET_ENV, 'unix:' + path)
    backend = aap2.Aap2Backend()
    backend.init(ENDPOINTS, LOG)
    try:
        assert daemon.configs[0] == ('dtn://at-aaaaaaaa/peer', False)
        assert sorted(daemon.configs[1:]) == sorted((e, True) for e, _ in ENDPOINTS)
        backend.send('dtn://at-group-41542d626f6f7400/bcast', b'\x00hello\xff', 86400)
        assert daemon.submitted == [('dtn://at-aaaaaaaa/peer',
                                     'dtn://at-group-41542d626f6f7400/bcast', b'\x00hello\xff')]
        bundle = backend.recv(2.0)
        assert (bundle.payload, bundle.src_eid, bundle.service) == (
            b'\x00hello\xff', 'dtn://at-aaaaaaaa/peer', '/bcast')
        backend.send('dtn://at-aaaaaaaa/peer', b'', 60)   # empty payload: no trailing bytes
        assert backend.recv(2.0).payload == b''
        assert backend.recv(0.05) is None
    finally:
        backend.shutdown()
        daemon.close()
    with pytest.raises(BackendError):
        backend.recv(0.01)


def test_daemon_in_v1_mode_is_refused(sock_dir, monkeypatch):
    path = os.path.join(sock_dir, 'v1.sock')
    daemon = FakeDaemon(path, greeting=0x01)
    monkeypatch.setenv(aap2.SOCKET_ENV, path)   # a bare path is a unix socket
    with pytest.raises(BackendError, match='greeting'):
        aap2.Aap2Backend().init(ENDPOINTS, LOG)
    daemon.close()


def test_rejected_registration(sock_dir, monkeypatch):
    path = os.path.join(sock_dir, 'no.sock')
    daemon = FakeDaemon(path, config_status=pb.RESPONSE_STATUS_UNAUTHORIZED)
    monkeypatch.setenv(aap2.SOCKET_ENV, 'unix:' + path)
    with pytest.raises(BackendError, match='rejected'):
        aap2.Aap2Backend().init(ENDPOINTS, LOG)
    daemon.close()


def test_no_daemon(sock_dir, monkeypatch):
    monkeypatch.setenv(aap2.SOCKET_ENV, 'unix:' + os.path.join(sock_dir, 'absent.sock'))
    with pytest.raises(BackendError, match='connect'):
        aap2.Aap2Backend().init(ENDPOINTS, LOG)


def test_endpoint_count_is_bounded():
    with pytest.raises(BackendError, match='endpoint count'):
        aap2.Aap2Backend().init([], LOG)
    with pytest.raises(BackendError, match='endpoint count'):
        aap2.Aap2Backend().init(ENDPOINTS * 2, LOG)


def test_malformed_tcp_url(monkeypatch):
    monkeypatch.setenv(aap2.SOCKET_ENV, 'tcp:nohostport')
    with pytest.raises(BackendError, match='malformed'):
        aap2.Aap2Backend().init(ENDPOINTS, LOG)


def test_oversize_envelope_refused():
    a, b = socket.socketpair()
    with a, b:
        a.sendall(aap2.encode_varint(aap2.MAX_MESSAGE + 1))
        with pytest.raises(BackendError, match='refused'):
            aap2.read_message(b)
        a.sendall(aap2.encode_varint(0))
        with pytest.raises(BackendError, match='refused'):
            aap2.read_message(b)
