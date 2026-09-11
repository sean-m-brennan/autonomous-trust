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
"""The 1:1 contact record -- the durable, user-owned counterpart to cohort
``Peers`` state.

A :class:`Contact` is what "add a specific human I already know" produces
(``doc/architecture/first-contact.md``; ``FIRST_CONTACT_PLAN.md`` §4.0). It is
deliberately NOT cohort state: ``identity.Peers`` is the live group membership a
node rebuilds every session and prunes on restart, whereas a Contact is a
personal address-book entry that must survive across networks, restarts, and --
later -- across a user's own devices.

The trust root of a Contact is always the cryptographic ``identity`` (public
keys + UUID + online nickname), never the human-memorable identifier that led to
it (FIRST_CONTACT_PLAN.md §3). The ``petname`` is the local Zooko name, assigned
by this node and never transmitted (see :func:`derive_local_petname`).
"""
import os
import time
from enum import Enum

from ..config.configuration import Configuration, register_enum_type
from ..identity.identity import (derive_local_petname,
                                 public_identity_to_canonical,
                                 public_identity_from_canonical)


@register_enum_type
class Provenance(Enum):
    """How a contact was acquired -- audit trail, and the input to the initial
    verification posture (a QR scanned face-to-face is verified on the spot; a
    link that arrived over a remote channel is not, see :mod:`.invitation`)."""
    in_person = 'in_person'    # QR/blob exchanged face-to-face: no MITM possible
    token = 'token'            # signed invite link/code over a remote channel
    directory = 'directory'    # resolved via an (opt-in) directory -- Phase 3


# The reputation edge a contact is seeded with the moment it becomes VERIFIED
# (FIRST_CONTACT_PLAN.md §10.5; the user's settled fork: "slightly elevated when
# verified"). It sits ONE NOTCH above the reputation cold-start neutral and well
# below the earned near-threshold band, so a deliberate human safety-number
# confirmation is recognised without pretending the peer is already trusted:
#
#     0.0 slash floor  <  0.1 COMM_CUTOFF  <  0.2 PREREP_NEUTRAL  <  [0.3 here]
#     <<  0.49/0.51 CTFT per-tx pivots  <  1.0
#
# (bands: reputation/repprocess.py PREREP_NEUTRAL/COMM_CUTOFF). Handing a fresh
# contact ~0.5 for free is exactly the "flat all-to-all trust mesh" the neutral
# band was introduced to avoid, so the bump is small and must still be EARNED
# upward by real interaction. The value recorded here is read back by the
# reputation process (repprocess._apply_contact_seeds and its C twin), which
# applies it as a COLD-START PRIOR only -- never over an earned, warm-started or
# slashed score. Override via AT_FIRST_CONTACT_SEED.
FIRST_CONTACT_VERIFIED_SEED = float(os.environ.get('AT_FIRST_CONTACT_SEED', '0.3'))


class Contact(Configuration):
    """A durable 1:1 contact.

    Round-trips through ``ConfigJSONEncoder``/``config_json_decoder`` like every
    other :class:`Configuration` (``cls(**to_dict())``), so every constructor
    parameter below mirrors a stored attribute name exactly. The nested
    ``identity`` is stored PUBLIC-ONLY: a Contact is always some *other* node, and
    a raw private identity would serialize its signing/encryption seeds
    (identity-in-payload-leaks-private-keys) -- the constructor defends this by
    publishing any identity that still carries private material.
    """

    def __init__(self, identity, petname='', rendezvous=None, verified=False,
                 provenance=Provenance.token, trust_seed=0.0,
                 added_at=0.0, verified_at=0.0, nonce=''):
        super().__init__()
        # The trust root. Force public-only so we can never persist private
        # key material by accident (publish() is idempotent on a public copy).
        if not getattr(identity, '_public_only', True):
            identity = identity.publish()
        self.identity = identity
        # Local Zooko name. Derived once at first construction (empty petname);
        # NEVER re-derived on load, because derive_local_petname appends a random
        # suffix -- a reload must preserve the name the user already sees.
        self.petname = petname or derive_local_petname(getattr(identity, 'nickname', ''))
        # Last-known reachability hints (relay refs / endpoints). Opaque strings
        # in this slice; the rendezvous layer (§4.2) gives them structure later.
        self.rendezvous = list(rendezvous or [])
        # First-contact verification state (§4.4). An unverified contact is
        # usable but must read as unverified everywhere (the user's fork:
        # "message, but visibly unverified"); higher-trust actions gate on this.
        self.verified = bool(verified)
        self.provenance = provenance
        # The reputation seed to apply; 0.0 until verified, then the constant
        # above. Recorded here, not yet pushed into reputation (offline slice).
        self.trust_seed = float(trust_seed)
        self.added_at = float(added_at) or time.time()
        self.verified_at = float(verified_at)
        # The originating invitation nonce, kept for audit / replay-correlation.
        self.nonce = nonce

    @property
    def uuid(self):
        return str(self.identity.uuid)

    @property
    def nickname(self):
        """The peer's ONLINE (wire) name -- the only globally-consistent name."""
        return getattr(self.identity, 'nickname', '') or ''

    def mark_verified(self, seed=FIRST_CONTACT_VERIFIED_SEED):
        """Flip to verified and seed the trust edge (idempotent).

        Called for the in-person path at redemption, and for the remote path
        once a safety-number comparison succeeds (:func:`.invitation.verify_contact`).
        """
        self.verified = True
        if not self.verified_at:
            self.verified_at = time.time()
        self.trust_seed = float(seed)
        return self

    # -- cross-runtime canonical form -------------------------------------
    # The durable store uses this flat, C-parseable shape (identity via the
    # canonical public form public_identity_to_canonical, NOT the default
    # config __type__ encoder, which C cannot parse). This is what makes a
    # contacts.cfg.json written by either runtime loadable by the other.
    def to_canonical(self):
        return {
            'identity': public_identity_to_canonical(self.identity),
            'petname': self.petname,
            'verified': bool(self.verified),
            'provenance': self.provenance.value,
            'trust_seed': float(self.trust_seed),
            'rendezvous': list(self.rendezvous),
            'nonce': self.nonce,
            'added_at': float(self.added_at),
            'verified_at': float(self.verified_at),
        }

    @classmethod
    def from_canonical(cls, d):
        """Rebuild a Contact from the flat cross-runtime form. Returns None on a
        malformed record (no parseable identity)."""
        if not isinstance(d, dict):
            return None
        identity = public_identity_from_canonical(d.get('identity'))
        if identity is None:
            return None
        try:
            provenance = Provenance(d.get('provenance', Provenance.token.value))
        except ValueError:
            provenance = Provenance.token
        # petname is stored (never re-derived on load): a reload must preserve
        # the name the user already sees.
        return cls(identity, petname=d.get('petname', ''),
                   rendezvous=d.get('rendezvous') or [],
                   verified=bool(d.get('verified', False)),
                   provenance=provenance,
                   trust_seed=float(d.get('trust_seed', 0.0) or 0.0),
                   added_at=float(d.get('added_at', 0.0) or 0.0),
                   verified_at=float(d.get('verified_at', 0.0) or 0.0),
                   nonce=d.get('nonce', '') or '')

    def __repr__(self):
        state = 'verified' if self.verified else 'UNVERIFIED'
        return 'Contact(%s [%s] %s via %s)' % (
            self.petname, self.nickname, state, self.provenance.value)
