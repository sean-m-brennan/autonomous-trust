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
"""Signed relay seed list (FIRST_CONTACT_PLAN §10.1, second half).

A node finds relays from an invitation first and from this list second: the
community-run relays a fresh install registers with when its operator named
none (``AT_USE_RELAY`` unset) and first contact is on. It is a default mirror
list, not a root of trust -- a relay still proves itself and is still
reputation-gated (relay.py) -- so what the signature buys is only that nobody
but the release signer chose the defaults.

Two files, both ``{"body": <exact signed JSON string>, "sig": <hex>}``:

    shipped  <cfg_dir>/relay_seeds.cfg.json  (or ``$AT_RELAY_SEEDS``)
             sig = release key over "at-seeds-v1|" + body
             body = {"v": 1, "typename": "at-seeds", "seq": N,
                     "relays": [relay://[<uuid>:<fp>@]host:port, ...]}
    local    <data_dir>/relay_seeds_local.cfg.json
             sig = this node's own identity key over "at-seeds-local-v1|" + body
             body = {"v": 1, "typename": "at-seeds-local",
                     "add": [hint, ...], "remove": [hint, ...]}

The shipped list changes only with a new build. Its ``seq`` never goes back:
the highest one this node has accepted is kept in
``<data_dir>/relay_seeds_seen.cfg.json``, and a lower one (an older build's
list reinstalled over a newer) is refused. The local edits are the operator's:
additions come first (their choice beats the default), removals drop a shipped
entry by endpoint. A file that fails its check is ignored with a warning, never
half-applied; a shipped list with one unparseable entry is refused whole, since
that is a signing mistake, not a relay to skip.

Same formats, prefixes and rules as C's ``network/net_relay_seeds.{h,c}``.
"""
import json
import logging
import os

from nacl.encoding import HexEncoder
from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

from autonomous_trust.core.config.configuration import Configuration, atomic_write
from . import relay as _relay

_logger = logging.getLogger(__name__)

#: The release key (hex ed25519) that signs the shipped list. Empty until the
#: project's release keypair is minted: with no key, no shipped list is
#: trusted, and only the local additions apply. Same as C's
#: AT_RELAY_SEEDS_RELEASE_KEY.
RELEASE_KEY = ''

SEEDS_DOMAIN = 'at-seeds-v1|'
LOCAL_DOMAIN = 'at-seeds-local-v1|'
SEEDS_TYPENAME = 'at-seeds'
LOCAL_TYPENAME = 'at-seeds-local'
SEEDS_VERSION = 1

SEEDS_FILE = 'relay_seeds.cfg.json'
LOCAL_FILE = 'relay_seeds_local.cfg.json'
SEEN_FILE = 'relay_seeds_seen.cfg.json'
SEEDS_ENV = 'AT_RELAY_SEEDS'

#: Most entries one list (or one side of the local edits) may hold. Past it
#: the file is refused, not truncated. Same as C's AT_RELAY_SEEDS_MAX.
MAX_ENTRIES = 64


def _is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


class InvalidSeeds(ValueError):
    """A seed list or local-edits file that is malformed or wrongly signed."""


def _split(text):
    try:
        obj = json.loads(text) if isinstance(text, (str, bytes)) else text
        body_str, sig_hex = obj['body'], obj['sig']
        if not isinstance(body_str, str) or not isinstance(sig_hex, str):
            raise TypeError('body and sig must be strings')
        body = json.loads(body_str)
    except (ValueError, TypeError, KeyError) as exc:
        raise InvalidSeeds('malformed signed file') from exc
    if not isinstance(body, dict):
        raise InvalidSeeds('body is not an object')
    return body, body_str, sig_hex


def _check_sig(key_hex, domain, body_str, sig_hex):
    try:
        VerifyKey(HexEncoder.decode(key_hex.encode('ascii'))).verify(
            (domain + body_str).encode('utf-8'),
            HexEncoder.decode(sig_hex.encode('ascii')))
    except (BadSignatureError, ValueError, TypeError) as exc:
        raise InvalidSeeds('signature does not match the key') from exc


def _hints(body, field):
    items = body.get(field, [])
    if not isinstance(items, list) or len(items) > MAX_ENTRIES:
        raise InvalidSeeds('%s must be a list of at most %d hints' % (field, MAX_ENTRIES))
    parsed = []
    for item in items:
        endpoint, pin = _relay.parse_hint(item) if isinstance(item, str) else (None, None)
        if endpoint is None:
            raise InvalidSeeds('%s: %r is not a relay hint' % (field, item))
        parsed.append((endpoint, pin))
    return parsed


def verify_seeds(text, release_key_hex):
    """The shipped list ``text`` -> ``(seq, [(endpoint, pin), ...])``, or raise
    :class:`InvalidSeeds`. Does not apply the ``seq`` floor."""
    if not release_key_hex:
        raise InvalidSeeds('no release key is configured')
    body, body_str, sig_hex = _split(text)
    _check_sig(release_key_hex, SEEDS_DOMAIN, body_str, sig_hex)
    seq = body.get('seq')
    if body.get('typename') != SEEDS_TYPENAME or not _is_int(body.get('v')) \
            or body['v'] != SEEDS_VERSION or not _is_int(seq) or seq < 1:
        raise InvalidSeeds('not a version-%d AT seed list' % SEEDS_VERSION)
    return seq, _hints(body, 'relays')


def verify_local(text, node_key_hex):
    """The local edits ``text`` -> ``(adds, removes)``, each
    ``[(endpoint, pin), ...]``, or raise :class:`InvalidSeeds`."""
    if not node_key_hex:
        raise InvalidSeeds("this node's key is unknown")
    body, body_str, sig_hex = _split(text)
    _check_sig(node_key_hex, LOCAL_DOMAIN, body_str, sig_hex)
    if body.get('typename') != LOCAL_TYPENAME or not _is_int(body.get('v')) \
            or body['v'] != SEEDS_VERSION:
        raise InvalidSeeds('not a version-%d AT seed-list edit' % SEEDS_VERSION)
    return _hints(body, 'add'), _hints(body, 'remove')


def _sign(signing_key, domain, body):
    body_str = json.dumps(body, separators=(',', ':'), ensure_ascii=True)
    sig = signing_key.sign((domain + body_str).encode('utf-8')).signature
    return json.dumps({'body': body_str, 'sig': HexEncoder.encode(sig).decode('ascii')},
                      separators=(',', ':'), ensure_ascii=True)


def sign_seeds(release_seed_hex, seq, relays) -> str:
    """The shipped-list file for ``relays`` (hint strings), signed with the
    release key's private seed. For the release tooling only."""
    for hint in relays:
        if _relay.parse_hint(hint)[0] is None:
            raise InvalidSeeds('%r is not a relay hint' % hint)
    return _sign(SigningKey(HexEncoder.decode(release_seed_hex.encode('ascii'))),
                 SEEDS_DOMAIN, {'v': SEEDS_VERSION, 'typename': SEEDS_TYPENAME,
                                'seq': int(seq), 'relays': list(relays)})


def sign_local(node_seed_hex, add=(), remove=()) -> str:
    """The local-edits file, signed with this node's own private seed."""
    for hint in list(add) + list(remove):
        if _relay.parse_hint(hint)[0] is None:
            raise InvalidSeeds('%r is not a relay hint' % hint)
    return _sign(SigningKey(HexEncoder.decode(node_seed_hex.encode('ascii'))),
                 LOCAL_DOMAIN, {'v': SEEDS_VERSION, 'typename': LOCAL_TYPENAME,
                                'add': list(add), 'remove': list(remove)})


def merge(shipped, adds, removes):
    """Local additions, then the shipped entries not removed, one per
    endpoint, at most :data:`relay.MAX_RELAYS`."""
    gone = {endpoint for endpoint, _pin in removes}
    out = []
    for endpoint, pin in list(adds) + [s for s in shipped if s[0] not in gone]:
        if endpoint not in [ep for ep, _pin in out]:
            out.append((endpoint, pin))
    return out[:_relay.MAX_RELAYS]


def seeds_path():
    return os.environ.get(SEEDS_ENV, '').strip() \
        or os.path.join(Configuration.get_cfg_dir(), SEEDS_FILE)


def node_seed_hex():
    """This node's private signing seed (hex) from its identity.cfg.json, or ''.

    Either runtime's file: C writes ``signature.hex_seed`` as the hex string;
    Python's encoder writes ``_signature.hex_seed`` as tagged bytes
    (``{"__type__": "bytes", "__value__": <base64 of the hex>}``)."""
    import base64
    path = os.path.join(Configuration.get_cfg_dir(), 'identity' + Configuration.file_ext)
    try:
        with open(path) as f:
            ident = json.load(f)
    except (OSError, ValueError):
        return ''
    if not isinstance(ident, dict):
        return ''
    sig = ident.get('signature') or ident.get('_signature')
    seed = sig.get('hex_seed') if isinstance(sig, dict) else None
    if isinstance(seed, dict) and seed.get('__type__') == 'bytes':
        try:
            seed = base64.b64decode(seed.get('__value__', ''), validate=True).decode('ascii')
        except (ValueError, TypeError, UnicodeDecodeError):
            return ''
    return seed if isinstance(seed, str) else ''


def _public_hex(seed_hex):
    try:
        return SigningKey(HexEncoder.decode(seed_hex.encode('ascii'))).verify_key \
            .encode(HexEncoder).decode('ascii')
    except (ValueError, TypeError):
        return ''


def _read(path):
    try:
        with open(path) as f:
            return f.read()
    except FileNotFoundError:
        return None
    except OSError as exc:
        _logger.warning('Relay seeds: cannot read %s (%s); ignored', path, exc)
        return None


def _seen_seq(data_dir):
    try:
        with open(os.path.join(data_dir, SEEN_FILE)) as f:
            seq = json.load(f).get('seq', 0)
        return seq if _is_int(seq) else 0
    except (OSError, ValueError, AttributeError):
        return 0


def _raise_seen(data_dir, seq):
    try:
        os.makedirs(data_dir, exist_ok=True)
        with atomic_write(os.path.join(data_dir, SEEN_FILE)) as f:
            json.dump({'seq': seq}, f)
    except OSError as exc:
        _logger.warning('Relay seeds: cannot record seq %d in %s (%s)',
                        seq, data_dir, exc)


def load(release_key_hex=None):
    """This node's effective seed relays, ``[(endpoint, pin), ...]``, from the
    shipped list and the local edits. Every refusal is logged and leaves that
    file out; nothing here raises."""
    key = RELEASE_KEY if release_key_hex is None else release_key_hex
    data_dir = Configuration.get_data_dir()
    shipped = []
    path = seeds_path()
    text = _read(path)
    if text is not None:
        try:
            seq, shipped = verify_seeds(text, key)
            floor = _seen_seq(data_dir)
            if seq < floor:
                _logger.warning('Relay seeds: %s is seq %d, older than the seq %d '
                                'this node already accepted; refused', path, seq, floor)
                shipped = []
            elif seq > floor:
                _raise_seen(data_dir, seq)
        except InvalidSeeds as exc:
            _logger.warning('Relay seeds: %s refused: %s', path, exc)
            shipped = []
    adds, removes = [], []
    local_path = os.path.join(data_dir, LOCAL_FILE)
    text = _read(local_path)
    if text is not None:
        try:
            adds, removes = verify_local(text, _public_hex(node_seed_hex()))
        except InvalidSeeds as exc:
            _logger.warning('Relay seeds: local edits %s refused: %s', local_path, exc)
    return merge(shipped, adds, removes)
