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
"""Rendezvous relay: reach a contact that is behind NAT (FIRST_CONTACT_PLAN §4.2).

A relay is any AT node that opts in (``AT_RELAY=1``); it
listens on TCP ``AT_RELAY_PORT`` and forwards frames between nodes that each
hold one outbound connection to it -- an outbound TCP flow is what a NAT keeps
open. The relay forwards SEALED frames: the ordinary AT envelope, end-to-end
encrypted between the two peers (bar the first-contact hello and ack, which are
plaintext by necessity, exactly as on UDP). It cannot read them, and it cannot
forge who sent them, because it stamps ``from`` itself from the sender's
registration.

Wire protocol, one JSON object per frame, each frame a 4-byte big-endian
length then the bytes (AT's TCP framing)::

    client -> relay   {"op": "hello", "uuid": U, "pubkey": <hex ed25519>,
                       "nonce": <hex>}
    relay  -> client  {"op": "challenge", "nonce": <hex>,
                       "relay_uuid": R, "relay_pubkey": <hex>, "relay_sig": <hex>}
                        relay_sig = ed25519 over
                        "at-relay-v1|relay|<client nonce>|<nonce>|<R>|<U>"
    client -> relay   {"op": "register", "sig": <hex>}
                        sig = ed25519 over "at-relay-v1|<nonce>|<uuid>"
    relay  -> client  {"op": "registered"}          (or {"op": "error", ...})
    client -> relay   {"op": "send", "to": U2, "frame": <base64>}
    relay  -> U2      {"op": "deliver", "from": U, "frame": <base64>}
    relay  -> client  {"op": "unreachable", "to": U2}
    client -> relay   {"op": "publish", "record": {body, sig}}
    relay  -> client  {"op": "published", "seq": N}  (or {"op": "refused", ...})
    client -> relay   {"op": "lookup", "id": <record id>}
    relay  -> client  {"op": "record", "id": <record id>, "record": {...} | null}

A relay also holds reachability records (contacts/reach.py): a registered node
publishes its OWN record (its key must be the one it registered with), and
anyone registered may look a record up by id. Records live in memory; a node
republishes on every (re)registration, so a restarted relay refills.

Registration proves the client holds the key for the uuid it claims. Without
it anyone could register someone else's uuid and receive their traffic -- the
hellos, which travel in the clear. The relay proves itself in the same step:
it signs the challenge, bound to the client's fresh nonce and both uuids, so a
client knows WHICH relay it is talking to, and a link that names the relay
(``relay://<uuid>@host:port``) is refused by anything else answering at that
address. A uuid is only a label, so a pin names the relay's KEY too:
``relay://<uuid>:<fp>@host:port``, where ``fp`` is :func:`key_fingerprint` of
its signing key. The client nonce and the relay_* fields are additive: an older
peer on either side just skips the proof, and such a relay counts as
unauthenticated.

Both ends gate on reputation: a relay refuses to register a client its node
distrusts (below the reputation cut-off), and a client refuses a relay it
distrusts. Unknown and neutral pass -- first contact is meeting strangers.
The C twin is network/net_relay.{h,c}.
"""
import base64
import binascii
import json
import logging
import os
import secrets
import socket
import struct
import threading
import time

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

_logger = logging.getLogger(__name__)

#: Domain separation for the registration signature, so it can never verify
#: as anything else a node signs. Same string as C's AT_RELAY_DOMAIN.
RELAY_DOMAIN = 'at-relay-v1'

#: Default relay port (AT_RELAY_PORT overrides). Same as C's AT_RELAY_DEFAULT_PORT.
DEFAULT_PORT = 27790

#: Largest frame either side accepts. Bigger than any AT envelope; a length
#: prefix above it is a broken or hostile peer, and the connection is dropped
#: rather than a buffer allocated for it. Same as C's AT_RELAY_MAX_FRAME.
MAX_FRAME = 4 * 1024 * 1024

#: Seconds a connecting client has to finish registering.
HANDSHAKE_TIMEOUT = 10.0

#: URI scheme of a relay rendezvous hint in an invitation.
SCHEME = 'relay://'

#: Most reachability records one relay holds. Past it, expired records go
#: first, then the soonest to expire. Same as C's AT_RELAY_MAX_RECORDS.
MAX_RECORDS = 4096


def relay_enabled() -> bool:
    """True iff this node serves as a relay (``AT_RELAY``)."""
    return os.environ.get('AT_RELAY', '').strip().lower() in ('1', 'true', 'yes', 'on')


def relay_port() -> int:
    try:
        return int(os.environ.get('AT_RELAY_PORT', '') or DEFAULT_PORT)
    except ValueError:
        return DEFAULT_PORT


#: Most relays one node registers with, or one peer's route names. Same as
#: C's AT_RELAY_MAX.
MAX_RELAYS = 4


def own_relay_hints():
    """This node's own relays as ``[((host, port), pin or None), ...]`` in
    preference order, from ``AT_USE_RELAY`` (comma-separated hints; an entry
    may pin its relay as ``<uuid>:<fp>@host:port``). Unusable entries and
    repeats are skipped (and logged); at most :data:`MAX_RELAYS` are kept.

    With ``AT_USE_RELAY`` unset or empty and first contact on
    (``AT_FIRST_CONTACT``), the signed seed list stands in (relay_seeds.py):
    an operator's explicit choice always wins, and off means off."""
    env = os.environ.get('AT_USE_RELAY', '')
    if not env.strip():
        return _seed_hints()
    found = []
    for item in env.split(','):
        if not item.strip():
            continue
        endpoint, pin = parse_hint(item)
        if endpoint is None:
            _logger.warning('AT_USE_RELAY: %r is not [uuid:fp@]host:port; skipped',
                            item.strip())
        elif endpoint not in [ep for ep, _pin in found]:
            found.append((endpoint, pin))
    if len(found) > MAX_RELAYS:
        _logger.warning('AT_USE_RELAY names %d relays; using the first %d',
                        len(found), MAX_RELAYS)
    return found[:MAX_RELAYS]


_seed_cache = {'key': None, 'hints': []}


def _seed_hints():
    """The seed list's relays when first contact is on, else []. Re-read only
    when one of its files (or the release key) changes, so a refused file is
    logged once, not on every route lookup."""
    if os.environ.get('AT_FIRST_CONTACT', '').strip().lower() not in ('1', 'true', 'yes', 'on'):
        return []
    from . import relay_seeds as _seeds
    from ..config.configuration import Configuration
    data_dir = Configuration.get_data_dir()
    paths = (_seeds.seeds_path(), os.path.join(data_dir, _seeds.LOCAL_FILE),
             os.path.join(data_dir, _seeds.SEEN_FILE),
             os.path.join(Configuration.get_cfg_dir(), 'identity' + Configuration.file_ext))
    if _seed_cache['key'] != _stamp(paths, _seeds.RELEASE_KEY):
        _seed_cache['hints'] = _seeds.load()
        # Stamped AFTER the load: raising the seq floor rewrites a stamped file.
        _seed_cache['key'] = _stamp(paths, _seeds.RELEASE_KEY)
    return list(_seed_cache['hints'])


def _stamp(paths, release_key):
    stamp = []
    for path in paths:
        try:
            st = os.stat(path)
            stamp.append((path, st.st_mtime_ns, st.st_size))
        except OSError:
            stamp.append((path, None, None))
    return tuple(stamp), release_key


def own_relays():
    """This node's own relays as ``[(host, port), ...]``, in preference order
    (:func:`own_relay_hints` without the pins)."""
    return [endpoint for endpoint, _pin in own_relay_hints()]


def merge_endpoints(first, then):
    """``first`` followed by whatever of ``then`` it lacks, deduplicated, at
    most :data:`MAX_RELAYS`: a route's preference order."""
    merged = []
    for endpoint in list(first) + list(then):
        if endpoint is not None and endpoint not in merged:
            merged.append(endpoint)
    return merged[:MAX_RELAYS]


#: Bytes of SHA-256 kept in a key fingerprint. Same as C's AT_RELAY_FP_BYTES.
FP_BYTES = 16


def key_fingerprint(pubkey_hex) -> str:
    """The fingerprint a pin carries: the first :data:`FP_BYTES` of SHA-256
    over the raw ed25519 signing key, hex. '' if the key is not hex."""
    import hashlib
    try:
        raw = binascii.unhexlify(pubkey_hex)
    except (binascii.Error, TypeError, ValueError):
        return ''
    return hashlib.sha256(raw).hexdigest()[:2 * FP_BYTES]


def parse_hint(text):
    """``[relay://][<uuid>:<fp>@]host:port`` -> ``((host, port), pin)``, where
    ``pin`` is ``(uuid, fp)`` or None; ``(None, None)`` if it is not a hint (a
    malformed pin included: a pin that cannot be checked is refused, not
    dropped, or a typo would silently unpin a link)."""
    text = (text or '').strip()
    if text.startswith(SCHEME):
        text = text[len(SCHEME):]
    pin = None
    if '@' in text:
        head, _, text = text.partition('@')
        uuid, _, fp = head.strip().lower().partition(':')
        if not _is_uuid(uuid) or len(fp) != 2 * FP_BYTES \
                or any(c not in '0123456789abcdef' for c in fp):
            return None, None
        pin = (uuid, fp)
    endpoint = parse_endpoint(text)
    return (endpoint, pin) if endpoint is not None else (None, None)


def _is_uuid(text):
    import uuid as _uuid
    try:
        _uuid.UUID(text)
    except (ValueError, TypeError, AttributeError):
        return False
    return True


def parse_endpoint(text):
    """``host:port``, ``[v6]:port`` or a ``relay://`` hint (pinned or not) ->
    ``(host, port)``, or None if it is not one."""
    text = (text or '').strip()
    if text.startswith(SCHEME):
        text = text[len(SCHEME):]
    if '@' in text:
        text = text.partition('@')[2]
    text = text.rstrip('/')
    if not text:
        return None
    if text.startswith('['):
        host, _, rest = text[1:].partition(']')
        port = rest[1:] if rest.startswith(':') else ''
    else:
        host, _, port = text.rpartition(':')
    try:
        port_n = int(port)
    except ValueError:
        return None
    if not host or not 0 < port_n < 65536:
        return None
    return host, port_n


def hint_for(endpoint, pin=None) -> str:
    """The invitation rendezvous hint naming relay ``(host, port)``, pinned to
    ``pin`` = ``(uuid, fp)`` when the relay's identity is known."""
    host, port = endpoint
    prefix = '%s:%s@' % (str(pin[0]).lower(), pin[1]) if pin else ''
    return '%s%s%s:%d' % (SCHEME, prefix,
                          '[%s]' % host if ':' in host else host, port)


def registration_text(nonce_hex, uuid_str) -> bytes:
    return ('%s|%s|%s' % (RELAY_DOMAIN, nonce_hex, str(uuid_str).lower())).encode('ascii')


def relay_proof_text(client_nonce, nonce, relay_uuid, client_uuid) -> bytes:
    """What a relay signs to prove itself. The client's fresh nonce makes it
    unreplayable, and naming the client binds it to this one registration.
    Starts "relay|" so it can never verify as a client's registration_text."""
    return ('%s|relay|%s|%s|%s|%s' % (RELAY_DOMAIN, client_nonce, nonce,
                                      str(relay_uuid).lower(),
                                      str(client_uuid).lower())).encode('ascii')


def _signing_hex(identity):
    from ..identity.identity import public_identity_to_canonical
    return public_identity_to_canonical(identity.publish())['signature']['hex_seed']


# -- framing -----------------------------------------------------------------
def send_frame(sock, obj) -> None:
    data = json.dumps(obj, separators=(',', ':')).encode('utf-8')
    sock.sendall(struct.pack('!I', len(data)) + data)


def _recv_exact(sock, n):
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError('relay connection closed')
        buf += chunk
    return buf


def recv_frame(sock):
    """The next frame as a dict. Raises ConnectionError on EOF, an oversized
    length, or a frame that is not a JSON object."""
    (length,) = struct.unpack('!I', _recv_exact(sock, 4))
    if length > MAX_FRAME:
        raise ConnectionError('relay frame of %d bytes refused' % length)
    try:
        obj = json.loads(_recv_exact(sock, length).decode('utf-8'))
    except (UnicodeDecodeError, ValueError) as err:
        raise ConnectionError('relay frame is not JSON (%s)' % err) from err
    if not isinstance(obj, dict):
        raise ConnectionError('relay frame is not a JSON object')
    return obj


# -- the relay ---------------------------------------------------------------
class RelayServer:
    """Forward sealed frames between registered clients.

    One thread accepts; one thread per connection reads. A uuid registered
    twice keeps the newer connection (the node reconnected); the older one is
    closed."""

    def __init__(self, host, port, logger=None, identity=None, distrusted=None,
                 registry=None):
        """``identity`` (this node's) signs each challenge, proving the relay;
        ``distrusted(uuid, pubkey_hex) -> bool`` refuses a client to register
        (the key is proven, so a distrusted node gains nothing by a new uuid);
        ``registry`` (a registry.Registry) makes this relay a directory
        registry too -- without one, every ``dir_*`` op is refused."""
        self.logger = logger or _logger
        self.identity = identity
        self.distrusted = distrusted
        self.registry = registry
        self._records = {}          # record id -> ReachRecord
        self._clients = {}          # uuid -> socket
        self._send_locks = {}       # socket -> Lock (writes are not atomic)
        self._lock = threading.Lock()
        self._sock = socket.socket(socket.AF_INET6 if ':' in host else socket.AF_INET,
                                   socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Explicit, never inherited: another part of the node (ping_at) sets a
        # PROCESS-WIDE socket default timeout, and a listener that picked it
        # up would time out of accept() and stop accepting for good.
        self._sock.settimeout(None)
        self._sock.bind((host, port))
        self._sock.listen(64)
        self.address = self._sock.getsockname()[:2]
        self._stopped = False
        threading.Thread(target=self._accept_loop, daemon=True,
                         name='relay-accept').start()
        self.logger.info('Relay: serving on %s:%d', *self.address)

    def stop(self):
        self._stopped = True
        try:
            self._sock.close()
        except OSError:
            pass
        with self._lock:
            socks = list(self._send_locks)
        for s in socks:
            try:
                s.close()
            except OSError:
                pass

    def registered(self):
        with self._lock:
            return set(self._clients)

    def evict(self, uuid):
        """Drop ``uuid``'s registration now (it has become distrusted)."""
        with self._lock:
            conn = self._clients.pop(str(uuid).lower(), None)
        if conn is not None:
            self.logger.info('Relay: evicted %s (distrusted)', str(uuid)[:8])
            # shutdown, not just close: close() from this thread does not wake
            # the connection's reader, blocked in recv(), so the client would
            # never see the drop.
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                conn.close()
            except OSError:
                pass

    def _accept_loop(self):
        while not self._stopped:
            try:
                conn, _addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True,
                             name='relay-conn').start()

    def _write(self, conn, obj):
        lock = self._send_locks.get(conn)
        if lock is None:
            return
        with lock:
            send_frame(conn, obj)

    def _register(self, conn):
        """Run the challenge; return the proven uuid, or None."""
        hello = recv_frame(conn)
        uuid, pubkey = hello.get('uuid'), hello.get('pubkey')
        if hello.get('op') != 'hello' or not isinstance(uuid, str) \
                or not isinstance(pubkey, str):
            send_frame(conn, {'op': 'error', 'reason': 'expected hello'})
            return None
        nonce = secrets.token_hex(16)
        challenge = {'op': 'challenge', 'nonce': nonce}
        client_nonce = hello.get('nonce')
        if self.identity is not None and isinstance(client_nonce, str) and client_nonce:
            me = str(self.identity.uuid).lower()
            signed = self.identity.sign(relay_proof_text(client_nonce, nonce, me, uuid))
            challenge.update({'relay_uuid': me,
                              'relay_pubkey': _signing_hex(self.identity),
                              'relay_sig': signed.signature.decode('ascii')})
        send_frame(conn, challenge)
        reg = recv_frame(conn)
        try:
            VerifyKey(binascii.unhexlify(pubkey)).verify(
                registration_text(nonce, uuid), binascii.unhexlify(reg.get('sig', '')))
        except (BadSignatureError, binascii.Error, ValueError, TypeError):
            self.logger.warning('Relay: registration for %s refused: bad '
                                'signature', uuid[:8])
            send_frame(conn, {'op': 'error', 'reason': 'bad signature'})
            return None
        if self.distrusted is not None and self.distrusted(uuid.lower(), pubkey.lower()):
            self.logger.warning('Relay: registration for %s refused: distrusted',
                                uuid[:8])
            send_frame(conn, {'op': 'error', 'reason': 'distrusted'})
            return None
        return uuid.lower(), pubkey.lower()

    def _publish(self, uuid, pubkey, wire):
        """Store ``uuid``'s own record. Returns the reply frame."""
        from ..contacts.reach import InvalidRecord, ReachRecord
        try:
            record = ReachRecord.from_wire(wire).verify()
        except InvalidRecord as err:
            return {'op': 'refused', 'reason': str(err)}
        # Only the holder files its own record: a registrant proved its key,
        # and the record must be signed by that same key, for that same uuid.
        if record.key != pubkey or record.uuid != uuid:
            return {'op': 'refused', 'reason': 'not your record'}
        rid = record.record_id
        with self._lock:
            held = self._records.get(rid)
            if held is not None and record.seq == held.seq \
                    and record.body_str == held.body_str:
                # The same record again: a node refiles at every registration.
                return {'op': 'published', 'seq': record.seq}
            if held is not None and record.seq <= held.seq:
                return {'op': 'refused', 'reason': 'stale (seq %d <= %d)'
                        % (record.seq, held.seq)}
            if held is None and len(self._records) >= MAX_RECORDS:
                self._evict_record_locked()
            self._records[rid] = record
        return {'op': 'published', 'seq': record.seq}

    def _evict_record_locked(self):
        now = time.time()
        expired = [rid for rid, r in self._records.items() if r.is_expired(now)]
        for rid in expired:
            del self._records[rid]
        if len(self._records) >= MAX_RECORDS:
            soonest = min(self._records, key=lambda rid: self._records[rid].expiry or float('inf'))
            del self._records[soonest]

    def _lookup(self, rid):
        with self._lock:
            record = self._records.get(str(rid or '').lower())
        if record is not None and record.is_expired():
            record = None
        return {'op': 'record', 'id': str(rid or '').lower(),
                'record': record.to_wire() if record is not None else None}

    def _directory(self, uuid, pubkey, op, req):
        """A registry op from registrant ``uuid``. Returns the reply frame."""
        handle = req.get('handle') if isinstance(req.get('handle'), str) else ''
        if self.registry is None:
            return {'op': 'dir_refused', 'handle': handle, 'reason': 'not_registry'}
        if op == 'dir_publish':
            return self.registry.publish(uuid, pubkey, req.get('entry'))
        if op == 'dir_withdraw':
            return self.registry.withdraw(uuid, pubkey, handle)
        if op == 'dir_lookup':
            return self.registry.lookup(uuid, handle)
        return {'op': 'dir_refused', 'handle': handle, 'reason': 'unknown_op'}

    def _serve(self, conn):
        uuid = None
        try:
            # Bounded while registering; blocking once registered, since a
            # registered client may say nothing for as long as it likes.
            conn.settimeout(HANDSHAKE_TIMEOUT)
            proven = self._register(conn)
            if proven is None:
                return
            uuid, pubkey = proven
            conn.settimeout(None)
            with self._lock:
                old = self._clients.get(uuid)
                self._clients[uuid] = conn
                self._send_locks[conn] = threading.Lock()
            if old is not None and old is not conn:
                try:
                    old.close()
                except OSError:
                    pass
            self._write(conn, {'op': 'registered'})
            self.logger.info('Relay: %s registered', uuid[:8])
            while not self._stopped:
                req = recv_frame(conn)
                op = req.get('op')
                if op == 'publish':
                    self._write(conn, self._publish(uuid, pubkey, req.get('record')))
                    continue
                if op == 'lookup':
                    self._write(conn, self._lookup(req.get('id')))
                    continue
                if isinstance(op, str) and op.startswith('dir_'):
                    self._write(conn, self._directory(uuid, pubkey, op, req))
                    continue
                if op != 'send':
                    continue
                to = str(req.get('to', '')).lower()
                with self._lock:
                    target = self._clients.get(to)
                if target is None:
                    self._write(conn, {'op': 'unreachable', 'to': to})
                    continue
                try:
                    # `from` is OURS: the sender's proven registration, never
                    # anything the frame claims.
                    self._write(target, {'op': 'deliver', 'from': uuid,
                                         'frame': req.get('frame', '')})
                except OSError:
                    self._write(conn, {'op': 'unreachable', 'to': to})
        except (ConnectionError, OSError):
            pass
        finally:
            with self._lock:
                if uuid is not None and self._clients.get(uuid) is conn:
                    del self._clients[uuid]
                self._send_locks.pop(conn, None)
            try:
                conn.close()
            except OSError:
                pass


# -- a node's link to a relay ------------------------------------------------
class RelayClient:
    """One node's registered, outbound connection to one relay.

    ``on_deliver(from_uuid, frame_bytes)`` runs on the reader thread for each
    frame the relay delivers, and ``on_unreachable(to_uuid)`` (if given) for
    each peer the relay says it cannot reach. Connects lazily and reconnects on
    the next send after a drop."""

    def __init__(self, endpoint, identity, on_deliver, logger=None, timeout=5.0,
                 on_unreachable=None, pin=None, distrusted=None, on_record=None,
                 on_dir=None):
        """``pin`` = ``(uuid, fp)`` names which relay must answer (refused
        otherwise, and refused if it cannot prove itself at all);
        ``distrusted(uuid, pubkey_hex) -> bool`` refuses a relay that proved
        to be someone we distrust."""
        self.endpoint = endpoint
        self.identity = identity
        self.on_deliver = on_deliver
        self.on_unreachable = on_unreachable
        # on_record(record_id, wire or None): a lookup's answer, on the reader.
        self.on_record = on_record
        # on_dir(frame): every dir_* answer (a registry's), on the reader.
        self.on_dir = on_dir
        self.pin = (pin[0].lower(), pin[1].lower()) if pin else None
        self.distrusted = distrusted
        self.relay_uuid = None      # proven by the relay's signed challenge
        self.relay_key = None       # ...and the key it proved with (hex)
        self.refused = ''           # why the last connect was refused, if it was
        self.logger = logger or _logger
        self.timeout = timeout
        self._sock = None
        self._lock = threading.Lock()
        self.unreachable = set()    # uuids the relay last said it cannot reach

    @property
    def connected(self):
        return self._sock is not None

    @property
    def proven_pin(self):
        """``(uuid, fp)`` of the relay as it last proved itself, or None."""
        if self.relay_uuid is None:
            return None
        return self.relay_uuid, key_fingerprint(self.relay_key)

    def _pubkey_hex(self):
        return _signing_hex(self.identity)

    def _check_relay(self, challenge, client_nonce, my_uuid):
        """The relay's proven ``(uuid, pubkey_hex)``, or None if it offered no
        proof. Raises ConnectionError for a bad proof, a pin it does not match,
        or a relay we distrust."""
        where = '%s:%d' % self.endpoint
        ruuid, rkey = challenge.get('relay_uuid'), challenge.get('relay_pubkey')
        proven = None
        if ruuid is not None:
            try:
                VerifyKey(binascii.unhexlify(rkey or '')).verify(
                    relay_proof_text(client_nonce, challenge.get('nonce', ''),
                                     ruuid, my_uuid),
                    binascii.unhexlify(challenge.get('relay_sig', '')))
            except (BadSignatureError, binascii.Error, ValueError, TypeError):
                raise ConnectionError('relay %s: its proof of identity does not '
                                      'verify' % where)
            proven = (str(ruuid).lower(), str(rkey).lower())
        if self.pin is not None:
            if proven is None:
                raise ConnectionError('relay %s offered no proof of identity, and '
                                      'the link names relay %s' % (where, self.pin[0][:8]))
            if proven[0] != self.pin[0] or key_fingerprint(proven[1]) != self.pin[1]:
                raise ConnectionError('relay %s is not the relay the link names '
                                      '(expected %s, proved %s with another key)'
                                      % (where, self.pin[0][:8], proven[0][:8]))
        if proven is not None and self.distrusted is not None \
                and self.distrusted(*proven):
            raise ConnectionError('relay %s (%s) is distrusted' % (where, proven[0][:8]))
        return proven

    def connect(self):
        """Connect and register; returns True when registered."""
        with self._lock:
            if self._sock is not None:
                return True
            host, port = self.endpoint
            sock = socket.create_connection((host, port), timeout=self.timeout)
            try:
                uuid = str(self.identity.uuid).lower()
                client_nonce = secrets.token_hex(16)
                send_frame(sock, {'op': 'hello', 'uuid': uuid,
                                  'pubkey': self._pubkey_hex(),
                                  'nonce': client_nonce})
                challenge = recv_frame(sock)
                if challenge.get('op') != 'challenge':
                    raise ConnectionError('relay did not challenge: %r' % challenge)
                proven = self._check_relay(challenge, client_nonce, uuid)
                signed = self.identity.sign(
                    registration_text(challenge.get('nonce', ''), uuid))
                # Identity.sign uses HexEncoder: .signature is already hex.
                send_frame(sock, {'op': 'register',
                                  'sig': signed.signature.decode('ascii')})
                answer = recv_frame(sock)
                if answer.get('op') != 'registered':
                    raise ConnectionError('relay refused registration: %r' % answer)
            except Exception as err:
                sock.close()
                self.refused = str(err)
                raise
            sock.settimeout(None)
            self._sock = sock
            self.relay_uuid, self.relay_key = proven if proven else (None, None)
            self.refused = ''
        threading.Thread(target=self._reader, args=(sock,), daemon=True,
                         name='relay-client').start()
        self.logger.info('Relay: registered with %s:%d%s', *self.endpoint,
                         ' (relay %s, proven)' % proven[0][:8] if proven
                         else ' (relay unauthenticated)')
        return True

    def send(self, to_uuid, frame: bytes) -> None:
        """Send ``frame`` to ``to_uuid`` through the relay. Raises OSError /
        ConnectionError if the relay cannot be reached."""
        self.connect()
        payload = {'op': 'send', 'to': str(to_uuid).lower(),
                   'frame': base64.b64encode(frame).decode('ascii')}
        with self._lock:
            sock = self._sock
            if sock is None:
                raise ConnectionError('relay connection lost')
            try:
                send_frame(sock, payload)
            except OSError:
                self._drop(sock)
                raise

    def _request(self, payload):
        self.connect()
        with self._lock:
            sock = self._sock
            if sock is None:
                raise ConnectionError('relay connection lost')
            try:
                send_frame(sock, payload)
            except OSError:
                self._drop(sock)
                raise

    def publish(self, record) -> None:
        """File our own reachability record here (``record`` a ReachRecord or
        its wire dict). The answer is logged by the reader."""
        wire = record.to_wire() if hasattr(record, 'to_wire') else record
        self._request({'op': 'publish', 'record': wire})

    def lookup(self, rid) -> None:
        """Ask for the record filed under ``rid``; on_record gets the answer."""
        self._request({'op': 'lookup', 'id': str(rid).lower()})

    def dir_publish(self, entry) -> None:
        """File our directory entry (a DirectoryEntry or its wire dict) here."""
        wire = entry.to_wire() if hasattr(entry, 'to_wire') else entry
        self._request({'op': 'dir_publish', 'entry': wire})

    def dir_withdraw(self, handle) -> None:
        self._request({'op': 'dir_withdraw', 'handle': str(handle)})

    def dir_lookup(self, handle) -> None:
        """Ask this registry for ``handle``; on_dir gets the answer."""
        self._request({'op': 'dir_lookup', 'handle': str(handle)})

    def close(self):
        with self._lock:
            sock, self._sock = self._sock, None
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    def _drop(self, sock):
        if self._sock is sock:
            self._sock = None
        try:
            sock.close()
        except OSError:
            pass

    def _reader(self, sock):
        try:
            while True:
                msg = recv_frame(sock)
                op = msg.get('op')
                if op == 'deliver':
                    try:
                        frame = base64.b64decode(msg.get('frame', ''), validate=True)
                    except (binascii.Error, ValueError):
                        continue
                    self.on_deliver(str(msg.get('from', '')).lower(), frame)
                elif op == 'record':
                    if self.on_record is not None:
                        self.on_record(str(msg.get('id', '')).lower(), msg.get('record'))
                elif op == 'published':
                    self.logger.info('Relay %s:%d holds our reachability record '
                                     '(seq %s)', *self.endpoint, msg.get('seq'))
                elif op == 'refused':
                    self.logger.warning('Relay %s:%d refused our reachability '
                                        'record: %s', *self.endpoint, msg.get('reason'))
                elif isinstance(op, str) and op.startswith('dir_'):
                    if op == 'dir_refused':
                        self.logger.warning('Relay %s:%d refused directory %s: %s',
                                            *self.endpoint, msg.get('handle'),
                                            msg.get('reason'))
                    if self.on_dir is not None:
                        self.on_dir(msg)
                elif op == 'unreachable':
                    to = str(msg.get('to', '')).lower()
                    self.unreachable.add(to)
                    self.logger.info('Relay %s:%d cannot reach %s (not '
                                     'registered there)', *self.endpoint, to[:8])
                    if self.on_unreachable is not None:
                        self.on_unreachable(to)
        except (ConnectionError, OSError):
            pass
        finally:
            with self._lock:
                self._drop(sock)
