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
"""The first-contact trust seed, where it lands: reputation.

FIRST_CONTACT_PLAN.md §10.5. A contact the two humans confirmed out of band
starts one notch above the neutral cold-start band (0.3 vs PREREP_NEUTRAL's
0.2) -- enough that a deliberate confirmation counts for something, far short
of earned standing.

The property that matters more than the number is that the seed is a PRIOR: it
may only fill a gap. A verified contact must never be able to raise a peer this
node already scores, and -- the case worth stating outright -- must never
restore a slashed peer, or "verify your way back into good standing" would be a
live attack on the reputation system rather than a convenience.
"""
import queue
from uuid import UUID
from unittest.mock import MagicMock

import pytest

from autonomous_trust.core.config import Configuration
from autonomous_trust.core.contacts import (Contact, Contacts, Provenance,
                                            FIRST_CONTACT_VERIFIED_SEED)
from autonomous_trust.core.identity import Identity
from autonomous_trust.core.processes import ProcessTracker
from autonomous_trust.core.reputation.repprocess import ReputationProcess
from autonomous_trust.core.reputation.reputation import Reputations
from autonomous_trust.core.system import CfgIds


@pytest.fixture
def cfg_root(tmp_path, monkeypatch):
    """A private config/data tree, so the contacts store this test writes is
    the one the process reads (the default is /etc/at)."""
    monkeypatch.setenv(Configuration.ROOT_VARIABLE_NAME, str(tmp_path))
    (tmp_path / 'etc' / 'at').mkdir(parents=True)
    return tmp_path


def _identity(name, addr='10.0.0.9'):
    return Identity.initialize(name, name, addr)


def _store_contact(identity, verified=True, seed=None):
    """Write one contact to the durable store and return its UUID."""
    store = Contacts.load()
    contact = Contact(identity.publish(), provenance=Provenance.token)
    if verified:
        contact.mark_verified() if seed is None else contact.mark_verified(seed)
    store.add(contact)
    store.save()
    return UUID(str(identity.uuid))


def _make_rep_process(reputations=None):
    log_q = queue.Queue()
    procs = []
    for nm in (CfgIds.network, CfgIds.identity, CfgIds.negotiation,
               CfgIds.reputation):
        p = MagicMock()
        p.name = nm
        procs.append(p)
    peer_store = MagicMock()
    peer_store.all = []
    configs = {
        'processes': procs,
        CfgIds.identity: _identity('self-node', '10.0.0.1'),
        CfgIds.peers: peer_store,
        CfgIds.group: MagicMock(),
    }
    if reputations is not None:
        configs[CfgIds.reputation] = reputations
    return ReputationProcess(configs, ProcessTracker(), log_q, suppress_log=True)


def test_a_verified_contact_seeds_its_prior(cfg_root):
    peer = _store_contact(_identity('alice@ex'))
    rp = _make_rep_process()
    assert rp.reputations.current[peer] == FIRST_CONTACT_VERIFIED_SEED
    # One notch up from "no information", not a jump into the trusted band.
    assert rp.reputations.current[peer] > rp.PREREP_NEUTRAL


def test_an_unverified_contact_seeds_nothing(cfg_root):
    """The handshake alone proves possession of a ticket, not identity; only
    the out-of-band safety-number compare earns the bump."""
    peer = _store_contact(_identity('mallory@ex'), verified=False)
    rp = _make_rep_process()
    assert peer not in rp.reputations.current
    assert str(peer) not in rp.reputations.current


def test_a_tampered_store_cannot_seed_an_unverified_contact(cfg_root):
    """Both halves of the record are checked, not just the number.

    contacts.cfg.json is a plain JSON file in the user's data dir, so a seed
    written there by hand -- or by anything that got at the file -- must not be
    honoured on a record that never passed verification. Without the
    ``verified`` filter, editing one float in a text file would buy a peer a
    reputation prior.
    """
    identity = _identity('forged@ex')
    store = Contacts.load()
    store.add(Contact(identity.publish(), provenance=Provenance.token,
                      verified=False,
                      trust_seed=FIRST_CONTACT_VERIFIED_SEED))
    store.save()
    rp = _make_rep_process()
    assert UUID(str(identity.uuid)) not in rp.reputations.current


def _seed_against(cfg_root, existing):
    """Apply the seed to a process that already scores the peer at
    ``existing``, and return what the peer scores afterwards.

    The value is set on the live process rather than passed through the
    warm-start snapshot because boot ALSO applies offline-gap idle decay
    (_seed_idle_from_snapshot), which would move the number for reasons that
    have nothing to do with this seed.
    """
    peer = _store_contact(_identity('known@ex'))
    rp = _make_rep_process()
    rp.reputations.update(peer, existing)
    rp._contact_seed_mtime = None          # force the re-read
    rp._apply_contact_seeds()
    return rp.reputations.current[peer]


def test_an_earned_score_is_never_overwritten(cfg_root):
    assert _seed_against(cfg_root, 0.85) == 0.85


def test_a_slashed_peer_cannot_be_verified_back_into_standing(cfg_root):
    """The seed fills a gap; it does not launder a peer the cohort cut off.
    Verifying a contact must not be a route back above the communication
    cut-off, or safety-number confirmation becomes an attack on reputation."""
    scored = _seed_against(cfg_root, 0.02)
    assert scored == 0.02
    assert scored < ReputationProcess.COMM_CUTOFF


def test_a_contact_verified_after_boot_lands_on_the_next_pass(cfg_root):
    """The refresh half: the identity process rewrites the store whenever a
    verification lands, and process() re-reads it."""
    rp = _make_rep_process()
    peer = _store_contact(_identity('later@ex'))
    assert peer not in rp.reputations.current      # not there at boot
    rp._apply_contact_seeds()
    assert rp.reputations.current[peer] == FIRST_CONTACT_VERIFIED_SEED


def test_an_unchanged_store_is_not_re_read(cfg_root):
    """The mtime guard is what makes a per-pass call affordable. Proven by
    removing the seeded value: a re-read would put it back."""
    peer = _store_contact(_identity('alice@ex'))
    rp = _make_rep_process()
    del rp.reputations.current[peer]
    rp._apply_contact_seeds()
    assert peer not in rp.reputations.current


def test_no_contacts_file_is_not_an_error(cfg_root):
    """The norm for a node that has never added anyone."""
    rp = _make_rep_process()
    assert rp.reputations.current == {}
    rp._apply_contact_seeds()                      # must not raise
