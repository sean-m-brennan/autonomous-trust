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
"""Community relay rosters (FIRST_CONTACT_PLAN §4.2 / §4.5, "an Ethne
rendezvous polity option").

A community that runs rendezvous relays -- an Ethne polity is the case this was
built for, but nothing here knows what a polity is -- publishes the relays it
stands behind as a signed roster. A node whose operator chose to trust that
community's key uses them. Like the seed list (relay_seeds.py) a roster is a
list of where to look, not a root of trust: a roster relay still proves itself
and is still reputation-gated (relay.py).

    roster   <cfg_dir>/relay_rosters/*.cfg.json  (or the dir in ``$AT_RELAY_ROSTERS``)
             {"body": <exact signed JSON string>, "sig": <hex>}
             sig = issuer key over "at-relay-roster-v1|" + body
             body = {"v": 1, "typename": "at-relay-roster", "issuer": <hex key>,
                     "seq": N, "relays": ["relay://<uuid>:<fp>@host:port", ...],
                     "areas": {"<a relays entry>": ["u4pr", ...], ...}}   (optional)
    issuers  ``$AT_RELAY_ROSTER_ISSUERS`` (comma-separated hex keys), then
             <cfg_dir>/relay_roster_issuers.cfg.json = {"issuers": [hex, ...]}
    seen     <data_dir>/relay_rosters_seen.cfg.json = {<issuer hex>: seq}

Every rule the seed list has, plus three of a roster's own:

- **Only a pinned issuer.** A roster names its issuer and is signed by it; one
  whose issuer the operator did not pin is ignored. The issuer list is plain
  configuration, like the rest of <cfg_dir>, which also holds the node's key.
- **Every entry pinned.** A community vouches for relays by key, so an entry
  without ``<uuid>:<fp>@`` refuses the whole roster.
- **A higher seq replaces the issuer's previous roster whole**, so a community
  removes a relay by publishing without it; an empty roster is valid. The
  highest seq accepted per issuer is kept, and a lower one is refused.

``areas`` says which of the relays are area hubs (network/hub.py), and for
which geohash areas. It is optional, and absent when no relay serves one, so a
roster without hubs keeps the bytes it always had. Present, it must be an
object whose every key is one of ``relays`` exactly and whose every value is a
list of 1 to :data:`MAX_AREAS` areas; anything else refuses the whole roster,
as an unpinned entry does.

When two files carry the same issuer the highest seq wins. Relays come in the
order the issuers were pinned, each roster in its own order, one per endpoint,
except that a hub serving an area one of this node's own buckets lies in comes
first; at most :data:`relay.MAX_RELAYS`. Same formats, prefixes and rules as
C's ``network/net_relay_rosters.{h,c}``.
"""
import json
import logging
import os

from nacl.encoding import HexEncoder
from nacl.signing import SigningKey

from ..config.configuration import Configuration, atomic_write
from . import relay as _relay
from .relay_seeds import InvalidSeeds, _check_sig, _hints, _is_int, _read, _split

_logger = logging.getLogger(__name__)

ROSTER_DOMAIN = 'at-relay-roster-v1|'
ROSTER_TYPENAME = 'at-relay-roster'
ROSTER_VERSION = 1

ROSTERS_DIR = 'relay_rosters'
ROSTERS_ENV = 'AT_RELAY_ROSTERS'
ISSUERS_FILE = 'relay_roster_issuers.cfg.json'
ISSUERS_ENV = 'AT_RELAY_ROSTER_ISSUERS'
SEEN_FILE = 'relay_rosters_seen.cfg.json'

#: Most issuers one node pins; past it the rest are ignored. Same as C's
#: AT_RELAY_ROSTER_ISSUERS_MAX.
MAX_ISSUERS = 16
#: Most roster files read from the directory. Same as C's AT_RELAY_ROSTER_FILES_MAX.
MAX_FILES = 32
#: Most areas one roster relay is listed as serving. Same as C's.
MAX_AREAS = 8


class InvalidRoster(InvalidSeeds):
    """A roster that is malformed, wrongly signed, or from an unpinned issuer."""


def _is_key_hex(s):
    return isinstance(s, str) and len(s) == 64 and \
        all(c in '0123456789abcdef' for c in s)


def verify_roster(text, issuers):
    """The roster ``text`` -> ``(issuer, seq, [(endpoint, pin), ...])``, or raise
    :class:`InvalidRoster`. ``issuers`` is the pinned issuer keys (hex). Does
    not apply the seq floor."""
    issuer, seq, relays, _areas = verify_roster_areas(text, issuers)
    return issuer, seq, relays


def _areas(body):
    """The roster's ``areas``, as ``{relays entry: [area, ...]}``; {} if absent."""
    from ..contacts.area_card import normalize_area
    if 'areas' not in body:
        return {}
    areas = body['areas']
    hints = body.get('relays', [])
    if not isinstance(areas, dict):
        raise InvalidRoster('areas must be an object')
    out = {}
    for hint, listed in areas.items():
        if hint not in hints:
            raise InvalidRoster('areas names %r, which is not one of the relays' % hint)
        if not isinstance(listed, list) or not 0 < len(listed) <= MAX_AREAS \
                or any(normalize_area(a) != a for a in listed):
            raise InvalidRoster('areas for %r must be 1 to %d geohash areas' % (hint, MAX_AREAS))
        out[hint] = list(listed)
    return out


def verify_roster_areas(text, issuers):
    """:func:`verify_roster`, plus the hubs' areas: ``(issuer, seq, relays,
    {endpoint: [area, ...]})``."""
    try:
        body, body_str, sig_hex = _split(text)
    except InvalidSeeds as exc:
        raise InvalidRoster(str(exc)) from exc
    issuer = body.get('issuer')
    if not _is_key_hex(issuer):
        raise InvalidRoster('no issuer key')
    if issuer not in issuers:
        raise InvalidRoster('issuer %s… is not pinned' % issuer[:16])
    try:
        _check_sig(issuer, ROSTER_DOMAIN, body_str, sig_hex)
    except InvalidSeeds as exc:
        raise InvalidRoster(str(exc)) from exc
    seq = body.get('seq')
    if body.get('typename') != ROSTER_TYPENAME or not _is_int(body.get('v')) \
            or body['v'] != ROSTER_VERSION or not _is_int(seq) or seq < 1:
        raise InvalidRoster('not a version-%d AT relay roster' % ROSTER_VERSION)
    try:
        relays = _hints(body, 'relays')
    except InvalidSeeds as exc:
        raise InvalidRoster(str(exc)) from exc
    if any(pin is None for _endpoint, pin in relays):
        raise InvalidRoster('every roster entry must be pinned to its relay key')
    by_hint = _areas(body)
    areas = {}
    for hint, listed in by_hint.items():
        areas[_relay.parse_hint(hint)[0]] = listed
    return issuer, seq, relays, areas


def sign_roster(issuer_seed_hex, seq, relays, areas=None) -> str:
    """The roster file for ``relays`` (pinned hint strings), signed with the
    issuer's private seed; ``areas`` ({hint: [area, ...]}) names the hubs.
    For a community's own tooling; an Ethne polity emits the same bytes from
    ``en_uplift::rendezvous_roster``."""
    sk = SigningKey(HexEncoder.decode(issuer_seed_hex.encode('ascii')))
    for hint in relays:
        endpoint, pin = _relay.parse_hint(hint)
        if endpoint is None or pin is None:
            raise InvalidRoster('%r is not a pinned relay hint' % hint)
    body = {'v': ROSTER_VERSION, 'typename': ROSTER_TYPENAME,
            'issuer': sk.verify_key.encode(HexEncoder).decode('ascii'),
            'seq': int(seq), 'relays': list(relays)}
    if areas:
        body['areas'] = {hint: list(listed) for hint, listed in areas.items()}
        _areas(body)
    body_str = json.dumps(body, separators=(',', ':'), ensure_ascii=True)
    sig = sk.sign((ROSTER_DOMAIN + body_str).encode('utf-8')).signature
    return json.dumps({'body': body_str, 'sig': HexEncoder.encode(sig).decode('ascii')},
                      separators=(',', ':'), ensure_ascii=True)


def rosters_dir():
    return os.environ.get(ROSTERS_ENV, '').strip() \
        or os.path.join(Configuration.get_cfg_dir(), ROSTERS_DIR)


def issuers_path():
    return os.path.join(Configuration.get_cfg_dir(), ISSUERS_FILE)


def pinned_issuers():
    """The issuer keys this node trusts rosters from, lowercase hex, in pin
    order: ``$AT_RELAY_ROSTER_ISSUERS`` first, then the issuers file. A key
    that is not 32 bytes of hex is skipped (and logged)."""
    found = []
    candidates = [s.strip().lower() for s in os.environ.get(ISSUERS_ENV, '').split(',')
                  if s.strip()]
    text = _read(issuers_path())
    if text is not None:
        try:
            listed = json.loads(text).get('issuers', [])
            if not isinstance(listed, list):
                raise ValueError('issuers is not a list')
            candidates += [str(s).strip().lower() for s in listed]
        except (ValueError, AttributeError) as exc:
            _logger.warning('Relay rosters: %s ignored (%s)', issuers_path(), exc)
    for key in candidates:
        if not _is_key_hex(key):
            _logger.warning('Relay rosters: issuer %r is not a hex ed25519 key; skipped', key)
        elif key not in found:
            found.append(key)
    return found[:MAX_ISSUERS]


def roster_files():
    """The roster files, sorted by name, at most :data:`MAX_FILES`."""
    d = rosters_dir()
    try:
        names = sorted(n for n in os.listdir(d) if n.endswith(Configuration.file_ext))
    except OSError:
        return []
    return [os.path.join(d, n) for n in names[:MAX_FILES]]


def _seen(data_dir):
    try:
        with open(os.path.join(data_dir, SEEN_FILE)) as f:
            seen = json.load(f)
        return {k: v for k, v in seen.items() if _is_key_hex(k) and _is_int(v)} \
            if isinstance(seen, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_seen(data_dir, seen):
    try:
        os.makedirs(data_dir, exist_ok=True)
        with atomic_write(os.path.join(data_dir, SEEN_FILE)) as f:
            json.dump(seen, f, sort_keys=True)
    except OSError as exc:
        _logger.warning('Relay rosters: cannot record seqs in %s (%s)', data_dir, exc)


def load(buckets=()):
    """This node's roster relays, ``[(endpoint, pin), ...]``, from every pinned
    issuer's newest acceptable roster; a hub serving an area that one of
    ``buckets`` (geohash buckets) lies in comes first. Every refusal is logged
    and leaves that file out; nothing here raises."""
    issuers = pinned_issuers()
    if not issuers:
        return []
    best = {}                       # issuer -> (seq, relays, path)
    for path in roster_files():
        text = _read(path)
        if text is None:
            continue
        try:
            issuer, seq, relays, areas = verify_roster_areas(text, issuers)
        except InvalidRoster as exc:
            _logger.warning('Relay rosters: %s refused: %s', path, exc)
            continue
        if issuer not in best or seq > best[issuer][0]:
            best[issuer] = (seq, relays, path, areas)
    data_dir = Configuration.get_data_dir()
    seen = _seen(data_dir)
    raised = False
    out = []
    served = {}
    for issuer in issuers:
        if issuer not in best:
            continue
        seq, relays, path, areas = best[issuer]
        floor = seen.get(issuer, 0)
        if seq < floor:
            _logger.warning('Relay rosters: %s is seq %d from issuer %s…, older than the '
                            'seq %d this node already accepted; refused',
                            path, seq, issuer[:16], floor)
            continue
        if seq > floor:
            seen[issuer] = seq
            raised = True
        for endpoint, pin in relays:
            if endpoint not in [ep for ep, _pin in out]:
                out.append((endpoint, pin))
                served[endpoint] = areas.get(endpoint, [])
    if raised:
        _save_seen(data_dir, seen)

    def near(endpoint):
        return any(b.startswith(a) for a in served[endpoint] for b in buckets)
    # Stable: hubs for our own buckets first, everything else in roster order.
    out = [h for h in out if near(h[0])] + [h for h in out if not near(h[0])]
    return out[:_relay.MAX_RELAYS]


def install(text):
    """File the roster ``text`` and pin its issuer: the local app's choice to
    trust a community (Agora: following it). The roster must verify under its
    own issuer and be no older than one already accepted from it. Returns the
    issuer; raises :class:`InvalidRoster`."""
    try:
        body, _s, _sig = _split(text)
    except InvalidSeeds as exc:
        raise InvalidRoster(str(exc)) from exc
    issuer = body.get('issuer')
    if not _is_key_hex(issuer):
        raise InvalidRoster('no issuer key')
    _issuer, seq, _relays, _areas = verify_roster_areas(text, [issuer])
    if seq < _seen(Configuration.get_data_dir()).get(issuer, 0):
        raise InvalidRoster('older than the roster already accepted from this issuer')
    os.makedirs(rosters_dir(), exist_ok=True)
    with atomic_write(os.path.join(rosters_dir(), issuer[:32] + Configuration.file_ext)) as f:
        f.write(text if isinstance(text, str) else text.decode('utf-8'))
    _set_issuer(issuer, True)
    return issuer


def remove(issuer):
    """Unpin ``issuer`` and delete the roster installed for it. Returns True
    if either was there."""
    issuer = str(issuer).lower()
    if not _is_key_hex(issuer):
        return False
    path = os.path.join(rosters_dir(), issuer[:32] + Configuration.file_ext)
    had = os.path.exists(path)
    try:
        os.remove(path)
    except OSError:
        pass
    return _set_issuer(issuer, False) or had


def _set_issuer(issuer, pinned):
    listed = []
    text = _read(issuers_path())
    if text is not None:
        try:
            listed = [str(k).lower() for k in json.loads(text).get('issuers', [])]
        except (ValueError, AttributeError):
            listed = []
    changed = (issuer in listed) != pinned
    if pinned and issuer not in listed:
        listed.append(issuer)
    if not pinned:
        listed = [k for k in listed if k != issuer]
    if changed:
        os.makedirs(os.path.dirname(issuers_path()), exist_ok=True)
        with atomic_write(issuers_path()) as f:
            json.dump({'issuers': listed}, f)
    return changed
