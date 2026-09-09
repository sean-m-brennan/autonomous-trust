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
"""Out-of-band invitations and first-contact verification (FIRST_CONTACT_PLAN.md
§4.1, §4.4).

This is the default, MITM-proof acquisition path, and it needs no directory and
no relay. Alice's node mints a *signed* invitation carrying her PUBLIC identity;
she hands it to Bob over a channel she already trusts (a QR code in person, or a
link over SMS/Signal/email). Because the public key travels IN the invitation,
a hostile directory has nothing to lie about:

    Invitation := sign_Alice{ published_identity, rendezvous_hint, nonce, expiry }

The signature is computed over the EXACT bytes transmitted (the canonical body
string), and those exact bytes are what a redeemer verifies -- no
re-serialization, so there is no canonicalisation ambiguity to exploit and the
form is straightforward for the C twin to reproduce byte-for-byte later.

What the signature proves depends on the channel, and that distinction is the
whole point (§3): it proves the invitation was minted by the holder of the
embedded identity's private key. Over an in-person/QR channel that is conclusive
-- there was no man in the middle. Over a remote link a MITM could substitute
its OWN self-consistent invitation, which is exactly why a remote contact stays
UNVERIFIED until a safety-number comparison (:func:`verify_contact`) confirms the
key over a second channel the two humans trust.
"""
import base64
import hmac
import json
import time

from nacl.exceptions import BadSignatureError
from nacl.hash import blake2b
from nacl.encoding import RawEncoder, HexEncoder

from ..identity.identity import (public_identity_to_canonical,
                                 public_identity_from_canonical)
from .contact import Contact, Provenance


INVITATION_VERSION = 1
INVITATION_TYPENAME = 'at-invitation'
INVITATION_URI_SCHEME = 'at+contact'
DEFAULT_TTL_SECONDS = 7 * 24 * 3600   # a week; 0 anywhere means "no expiry"

# Iterated hashing of the (already high-entropy) public keys before truncating
# to the displayed digits, so an attacker cannot cheaply grind a key whose
# safety number collides in the digits a human actually compares (the Signal
# fingerprint construction). blake2b is what the codebase already uses
# (system.py) and what libsodium gives the C twin, so this stays reproducible.
SAFETY_NUMBER_ITERATIONS = 1024
_SAFETY_GROUPS = 6            # 5-digit groups PER identity (30 digits each)
_SAFETY_DOMAIN = b'at-safety-number-v1'


class InvalidInvitation(ValueError):
    """An invitation is malformed, expired, or its signature does not match the
    identity it carries."""


class SafetyNumberMismatch(Exception):
    """A presented safety number does not match the computed one -- a possible
    man-in-the-middle at first contact. The contact is NOT promoted to verified."""


# --------------------------------------------------------------------------
# Invitation
# --------------------------------------------------------------------------
class Invitation:
    """A signed out-of-band introduction token.

    Kept off the :class:`Configuration` JSON machinery on purpose: an invitation
    is a self-authenticating wire artefact (canonical public identity + a
    detached signature), not durable local config, and it must serialize to a
    compact, URL/QR-safe blob rather than the ``__type__``-tagged config form.
    """

    def __init__(self, body: dict, body_str: str, sig_hex: str):
        # body_str is the EXACT signed byte source; body is its parse. Keeping
        # both means a redeemer verifies the bytes it received, never a
        # re-serialization of them.
        self.body = body
        self.body_str = body_str
        self.sig_hex = sig_hex

    # -- accessors --------------------------------------------------------
    @property
    def identity(self):
        return public_identity_from_canonical(self.body.get('identity'))

    @property
    def rendezvous(self):
        return list(self.body.get('rendezvous', []))

    @property
    def nonce(self):
        return self.body.get('nonce', '')

    @property
    def expiry(self):
        return int(self.body.get('expiry', 0) or 0)

    def is_expired(self, now=None):
        exp = self.expiry
        if not exp:
            return False
        return (now if now is not None else time.time()) >= exp

    # -- verification -----------------------------------------------------
    def verify_signature(self):
        """Verify the detached signature against the embedded identity.

        Raises :class:`InvalidInvitation` on any failure. Returns the
        reconstructed public identity on success.
        """
        identity = self.identity
        if identity is None:
            raise InvalidInvitation('invitation carries no usable identity')
        # Verify RAW message + RAW signature under the default RawEncoder, the
        # same path Message uses (network/message.py:562-568). Identity.verify's
        # HexEncoder form would require the message itself to be hex; ours is the
        # raw canonical body string, and the signature is transmitted hex, so we
        # hex-decode the signature to raw bytes here.
        try:
            sig_raw = HexEncoder.decode(self.sig_hex.encode('ascii'))
            identity.signature.public.verify(self.body_str.encode('utf-8'), sig_raw)
        except (BadSignatureError, ValueError, TypeError) as exc:
            raise InvalidInvitation('signature does not match embedded identity') from exc
        return identity

    # -- encoding ---------------------------------------------------------
    def encode(self) -> str:
        """Compact, URL/QR-safe base64url blob (no padding)."""
        envelope = json.dumps({'body': self.body_str, 'sig': self.sig_hex},
                              separators=(',', ':'), ensure_ascii=True)
        raw = base64.urlsafe_b64encode(envelope.encode('utf-8'))
        return raw.rstrip(b'=').decode('ascii')

    def to_uri(self) -> str:
        return '%s:%s' % (INVITATION_URI_SCHEME, self.encode())

    @classmethod
    def decode(cls, blob) -> 'Invitation':
        """Parse a blob or ``at+contact:`` URI back into an Invitation.

        Does NOT verify the signature -- call :meth:`verify_signature` or use
        :func:`redeem_invitation`, which verifies before producing a Contact.
        """
        if isinstance(blob, Invitation):
            return blob
        if not isinstance(blob, str):
            raise InvalidInvitation('invitation must be a string blob or URI')
        text = blob.strip()
        if text.startswith(INVITATION_URI_SCHEME + ':'):
            text = text[len(INVITATION_URI_SCHEME) + 1:]
        # restore base64 padding stripped by encode()
        pad = (-len(text)) % 4
        try:
            raw = base64.urlsafe_b64decode(text + ('=' * pad))
            envelope = json.loads(raw.decode('utf-8'))
            body_str = envelope['body']
            sig_hex = envelope['sig']
            body = json.loads(body_str)
        except (ValueError, TypeError, KeyError) as exc:
            raise InvalidInvitation('malformed invitation blob') from exc
        if body.get('typename') != INVITATION_TYPENAME:
            raise InvalidInvitation('not an AT invitation')
        return cls(body, body_str, sig_hex)

    def __repr__(self):
        ident = self.identity
        who = ident.nickname if ident is not None else '?'
        return 'Invitation(from=%s, expiry=%d)' % (who, self.expiry)


# --------------------------------------------------------------------------
# Mint / redeem
# --------------------------------------------------------------------------
def create_invitation(identity, rendezvous=None, expiry=None,
                      ttl_seconds=DEFAULT_TTL_SECONDS, nonce=None) -> Invitation:
    """Mint a signed invitation from *my* identity (§4.1).

    :param identity: this node's own (signable) Identity.
    :param rendezvous: reachability hints (opaque strings in this slice).
    :param expiry: absolute epoch seconds; overrides ``ttl_seconds`` if given.
        0/None with ``ttl_seconds=0`` means no expiry.
    :param ttl_seconds: convenience relative lifetime.
    :param nonce: override the random anti-replay nonce (tests).
    """
    if getattr(identity, '_public_only', True):
        raise ValueError('create_invitation needs your own (signable) identity, '
                         'not a public-only copy')
    if expiry is None:
        expiry = int(time.time()) + int(ttl_seconds) if ttl_seconds else 0
    body = {
        'v': INVITATION_VERSION,
        'typename': INVITATION_TYPENAME,
        # publish() strips private material; canonical form is C-parseable and
        # petname-free (a local Zooko name is never transmitted).
        'identity': public_identity_to_canonical(identity.publish()),
        'rendezvous': list(rendezvous or []),
        'nonce': nonce if nonce is not None else base64.b16encode(_random_nonce()).decode('ascii'),
        'expiry': int(expiry),
    }
    # Sign the EXACT bytes we transmit; sort_keys makes the source deterministic.
    body_str = json.dumps(body, sort_keys=True, separators=(',', ':'), ensure_ascii=True)
    signed = identity.sign(body_str.encode('utf-8'))
    return Invitation(body, body_str, signed.signature.decode('ascii'))


def redeem_invitation(invitation, *, in_person=False, petname='', now=None) -> Contact:
    """Ingest a friend's invitation and produce a :class:`Contact` (§4.1).

    Verifies the signature against the embedded identity and rejects an expired
    token, then records the contact. Verification posture follows the channel
    (§4.4): an in-person/QR exchange is verified on the spot (no MITM was
    possible), while a remote token stays UNVERIFIED until a safety-number
    comparison (:func:`verify_contact`).

    :param in_person: True iff the blob was exchanged over a channel with no
        possible man in the middle (QR scanned face-to-face).
    :param petname: optional local name; a random-suffixed one is derived if empty.
    """
    invite = Invitation.decode(invitation)
    identity = invite.verify_signature()          # raises InvalidInvitation
    if invite.is_expired(now):
        raise InvalidInvitation('invitation has expired')
    provenance = Provenance.in_person if in_person else Provenance.token
    contact = Contact(identity, petname=petname, rendezvous=invite.rendezvous,
                      provenance=provenance, nonce=invite.nonce)
    if in_person:
        # The key arrived over a trusted channel -- already verified (§4.4).
        contact.mark_verified()
    return contact


# --------------------------------------------------------------------------
# Safety-number verification (§4.4)
# --------------------------------------------------------------------------
def _random_nonce(n=16):
    import secrets
    return secrets.token_bytes(n)


def _fingerprint_groups(identity):
    """Per-identity fingerprint as ``_SAFETY_GROUPS`` 5-digit groups.

    Derived only from stable PUBLIC material (uuid + both public keys via the
    cross-runtime canonical form), so both parties -- and the C twin later --
    compute the identical value.
    """
    canon = public_identity_to_canonical(identity)
    material = '|'.join([
        _SAFETY_DOMAIN.decode('ascii'),
        str(canon.get('uuid', '')),
        canon.get('signature', {}).get('hex_seed', ''),
        canon.get('encryptor', {}).get('hex_seed', ''),
    ]).encode('ascii')
    digest = material
    for _ in range(SAFETY_NUMBER_ITERATIONS):
        digest = blake2b(digest, digest_size=32, encoder=RawEncoder)
    groups = []
    for i in range(_SAFETY_GROUPS):
        chunk = digest[i * 4:(i + 1) * 4]
        groups.append('%05d' % (int.from_bytes(chunk, 'big') % 100000))
    return groups


def safety_number(id_a, id_b) -> str:
    """The symmetric safety number the two humans compare (§4.4).

    Returns 12 space-separated 5-digit groups. Order-independent: both nodes,
    regardless of which identity each calls "mine", derive the SAME string,
    because the two per-identity fingerprints are concatenated in sorted order.
    """
    fa = ' '.join(_fingerprint_groups(id_a))
    fb = ' '.join(_fingerprint_groups(id_b))
    first, second = sorted([fa, fb])
    return first + ' ' + second


def _normalize_safety_number(value: str) -> str:
    """Strip whitespace so a user typing groups with odd spacing still matches."""
    return ''.join(str(value).split())


def verify_contact(contact: Contact, presented: str, my_identity, *,
                   seed=None) -> Contact:
    """Confirm a contact's key by safety-number comparison and promote it (§4.4).

    :param presented: the safety number the peer read to you over a trusted
        second channel (the two humans compare out loud / by sight).
    :raises SafetyNumberMismatch: if it does not match -- the contact is left
        UNVERIFIED and no trust edge is seeded.
    """
    expected = safety_number(my_identity, contact.identity)
    if not hmac.compare_digest(_normalize_safety_number(expected),
                               _normalize_safety_number(presented)):
        raise SafetyNumberMismatch(
            'safety number does not match for %r -- possible man-in-the-middle; '
            'contact left unverified' % contact.petname)
    if seed is None:
        contact.mark_verified()
    else:
        contact.mark_verified(seed)
    return contact
