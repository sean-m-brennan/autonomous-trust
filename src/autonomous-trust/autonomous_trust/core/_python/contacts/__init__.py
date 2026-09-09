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
"""First contact: adding a specific person you already know.

The 1:1 counterpart to cohort admission (``identity/``). Where the identity
protocol admits a newcomer to a *group* by majority vote, first contact binds a
verified key to a durable, user-owned :class:`Contact` between exactly two
parties -- the "here's my friend, connect us" primitive AT lacked
(``FIRST_CONTACT_PLAN.md``; ``doc/architecture/first-contact.md``).

This package is the offline, no-directory, no-relay slice: the contact record
and store, out-of-band signed invitations (QR / invite-link), and safety-number
verification. Live rendezvous relays (§4.2) and the opt-in directory (§4.3) are
later phases.
"""
from .contact import Contact, Provenance, FIRST_CONTACT_VERIFIED_SEED
from .store import Contacts
from .invitation import (Invitation, create_invitation, redeem_invitation,
                        safety_number, verify_contact,
                        InvalidInvitation, SafetyNumberMismatch)

__all__ = [
    'Contact', 'Provenance', 'FIRST_CONTACT_VERIFIED_SEED',
    'Contacts',
    'Invitation', 'create_invitation', 'redeem_invitation',
    'safety_number', 'verify_contact',
    'InvalidInvitation', 'SafetyNumberMismatch',
]
