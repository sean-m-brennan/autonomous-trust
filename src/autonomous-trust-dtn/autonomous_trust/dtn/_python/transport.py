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
"""The DTN / Bundle Protocol network transport: the Python twin of
src/c/extensions/dtn/net_transport_dtn.c (C's ``dtn_bp``).

Selected like the UDP and TCP transports, by class path::

    AT_TRANSPORT=autonomous_trust.dtn.transport.DTNNetworkProcess

AT's three channels map onto bundle destinations (:mod:`.eid`):

=============  ==========================================  ===============
channel        sent to                                     Python method
=============  ==========================================  ===============
peer           ``dtn://at-<peer uuid8>/peer``              ``send_peer``
broadcast      ``dtn://at-group-<hash8>/bcast``            ``send_any``
group          ``dtn://at-group-<hash8>/group``            ``send_group``
=============  ==========================================  ===============

All inbound bundles come from one backend receive and are routed by the service
of the endpoint they arrived on. A bundle for another channel's receiver waits
in that channel's single pending slot; a second one overwrites it, as in C.

Two behaviours are C's, recorded rather than changed: the endpoints are
registered once, when the transport opens, so a node that joins a group later
keeps receiving on the EIDs it opened with while it SENDS to its group's; and
an inbound bundle's address is its source EID, which matches a peer only when
that peer's provisioned address is the EID.

One difference is the shape of Python's group send. The core calls
``send_group(msg, member)`` once per member with the same sealed frame, where C
makes one group send; a DTN group send goes to the group EID, so this transport
sends a frame once and skips the repeats.
"""
import sys
import threading
import time

from autonomous_trust.core.network import NetworkProcess, NetworkProtocol

from . import eid as _eid
from .backend import BackendError, make_backend

# The error the core's send and receive loops catch, taken from the module that
# defines NetworkProcess so it is the same class on either backend.
TransmissionError = sys.modules[NetworkProcess.__module__].TransmissionError

#: Bundle lifetime: how long the DTN may store and carry a frame (C's 24 h).
DEFAULT_BUNDLE_LIFETIME_SEC = 86400

#: C's dtn_link_class_ms: bundles can sit at a forwarder for minutes.
LINK_CLASS_MS = 60 * 1000


class DTNNetworkProcess(NetworkProcess):
    """AT over a Bundle Protocol agent. The backend (``AT_DTN_BACKEND``) opens
    in the worker, where its threads and sockets live."""
    net_proto = NetworkProtocol.NONE
    kind = 'dtn_bp'

    def __init__(self, configurations, subsystems, log_q, acceptance_func=None, **kwargs):
        super().__init__(configurations, subsystems, log_q, acceptance_func, **kwargs)
        self.default_lifetime_sec = DEFAULT_BUNDLE_LIFETIME_SEC
        self.endpoints = []
        self._backend = None
        self._slots = None
        self._slot_lock = None
        self._last_group_frame = None

    # --- lifecycle ------------------------------------------------------

    def _init_transport(self):
        super()._init_transport()
        self.open_transport()

    def open_transport(self, backend=None):
        """Register the three endpoints with the backend (``AT_DTN_BACKEND``
        unless one is given) and get ready to send and receive."""
        self._slot_lock = threading.Lock()
        self._slots = {ch: None for ch in _eid.CHANNELS}
        node_uuid = getattr(self.myself, 'uuid', None)
        if not node_uuid:
            self.logger.warning('DTN: no identity at open; using placeholder EID')
        group_uuid = self._group_uuid()
        self.endpoints = _eid.endpoints(node_uuid, group_uuid)
        backend = backend if backend is not None else make_backend()
        try:
            backend.init(self.endpoints, self.logger)
        except BackendError as err:
            self.logger.error("DTN: backend '%s' init failed: %s", backend.name, err)
            raise
        self._backend = backend
        self.logger.info('DTN: ready, backend=%s peer=%s bcast=%s group=%s (group_joined=%s)',
                         backend.name, self.endpoints[0][0], self.endpoints[1][0],
                         self.endpoints[2][0],
                         'yes' if _eid.group_hash(group_uuid)[1] else 'no (pre-join)')

    def close_connections(self):
        if self._backend is not None:
            backend, self._backend = self._backend, None
            backend.shutdown()
        super().close_connections()

    def link_class_ms(self, target=None):
        return LINK_CLASS_MS

    # --- addressing -----------------------------------------------------

    def _group_uuid(self):
        grp = self.group
        return getattr(grp, 'uuid', None) if grp is not None else None

    def _uuid_for_address(self, address):
        """The uuid of the peer whose address is exactly ``address``."""
        listing = getattr(self.peers, 'listing', None) or {}
        peer = listing.get(address)
        return getattr(peer, 'uuid', None) if peer is not None else None

    def peer_eid(self, target):
        return _eid.peer_eid(target, self._uuid_for_address)

    # --- send -----------------------------------------------------------

    def _send(self, dest_eid, msg):
        if self._backend is None:
            raise TransmissionError('DTN transport is not open')
        if not isinstance(msg, (bytes, bytearray)):
            msg = msg.encode(self.enc)
        try:
            self._backend.send(dest_eid, bytes(msg), self.default_lifetime_sec)
        except BackendError as err:
            raise TransmissionError(str(err)) from err

    def send_peer(self, msg, host):
        try:
            dest = self.peer_eid(host)
        except _eid.EIDError as err:
            raise TransmissionError('DTN: no EID for %r: %s' % (host, err)) from err
        self._send(dest, msg)

    def send_group(self, msg, host):
        # One frame, one bundle: see the module docstring.
        if msg is self._last_group_frame:
            return
        self._send(_eid.broadcast_eid(_eid.CHAN_GROUP, self._group_uuid()), msg)
        self._last_group_frame = msg

    def send_any(self, msg):
        self._send(_eid.broadcast_eid(_eid.CHAN_BROADCAST, self._group_uuid()), msg)

    # --- receive --------------------------------------------------------

    def _deliver(self, bundle):
        if self.reject_message(bundle.src_eid):
            return None, bundle.src_eid, None
        return bundle.payload, bundle.src_eid, None

    def _recv(self, channel):
        """One frame for ``channel`` as ``(payload, src_eid, None)``; raises
        TimeoutError when there is none, as a socket receive does."""
        if self._backend is None:
            time.sleep(self.socket_timeout)
            raise TimeoutError
        with self._slot_lock:
            pending = self._slots[channel]
            self._slots[channel] = None
        if pending is not None:
            return self._deliver(pending)
        try:
            bundle = self._backend.recv(self.socket_timeout)
        except BackendError as err:
            if self.stop:
                raise TimeoutError from err
            raise TransmissionError(str(err)) from err
        if bundle is None:
            raise TimeoutError
        got = _eid.service_to_channel(bundle.service)
        if got == channel:
            return self._deliver(bundle)
        if got is not None:
            with self._slot_lock:
                self._slots[got] = bundle
        else:
            self.logger.debug("DTN: dropped bundle for unknown service '%s'", bundle.service)
        raise TimeoutError

    def recv_peer(self):
        return self._recv(_eid.CHAN_PEER)

    def recv_group(self):
        return self._recv(_eid.CHAN_GROUP)

    def recv_any(self):
        return self._recv(_eid.CHAN_BROADCAST)
