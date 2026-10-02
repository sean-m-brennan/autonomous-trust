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
"""The Phase 7a core hooks (FEATURE_SPLIT_PLAN Phase 7, C1-C4): how first
contact and rendezvous reach negotiation, reputation and the network process
without the core naming them.

Pins: a tier cap only lowers; a seed outside (0, 1] is refused and an earned
score is never overwritten; a unicast goes to the first extension that
reaches the peer, else the transport; an exclusion is recorded by uuid and by
key before the extensions hear of it; and the two in-tree features are what
the built-in list holds.
"""
import types
import uuid as uuid_mod

import pytest

from autonomous_trust.core._python import extensions
from autonomous_trust.core._python.extensions import (
    Extension, NegotiationHooks, NetworkHooks, ReputationHooks, capped_tier,
    network_hooks, reset_extensions)
from autonomous_trust.core._python.network.netprocess import NetworkProcess
from autonomous_trust.core._python.reputation.repprocess import ReputationProcess


@pytest.fixture
def only(monkeypatch):
    """Replace the known extensions with the given ones."""
    def _set(*exts):
        monkeypatch.setattr(extensions, '_builtin', lambda: list(exts))
        monkeypatch.setattr(extensions, '_installed', lambda: [])
        monkeypatch.setattr(extensions, '_source_tree', lambda: [])
        reset_extensions()
    yield _set
    reset_extensions()


def _ext(name, **kw):
    return Extension(name=name, enabled=lambda: True,
                     register_handlers=lambda proc, proc_name: None, **kw)


def test_no_feature_is_built_in():
    """Rendezvous and first contact are their own distributions
    (autonomous_trust.rendezvous, autonomous_trust.first_contact), found like
    any other extension, not built in (FEATURE_SPLIT_PLAN Phase 7)."""
    assert extensions._builtin() == []


# -- C1: negotiation tier cap ---------------------------------------------------
def test_no_cap_is_no_change(only):
    only()
    assert capped_tier(None, 'peer', 4) == 4


def test_caps_compose_and_only_lower(only):
    seen = []

    def to_two(proc, peer, tier):
        seen.append(('two', tier))
        return 2

    def raise_it(proc, peer, tier):
        seen.append(('up', tier))
        return tier + 5          # ignored: a cap never raises

    only(_ext('a', negotiation=NegotiationHooks(capped_tier=to_two)),
         _ext('b', negotiation=NegotiationHooks(capped_tier=raise_it)))
    assert capped_tier(None, 'peer', 4) == 2
    assert seen == [('two', 4), ('up', 2)]


# -- C2: reputation seed providers ----------------------------------------------
def _rep_stub():
    stub = types.SimpleNamespace(logger=types.SimpleNamespace(
        info=lambda *a, **k: None, warning=lambda *a, **k: None))
    stub.reputations = types.SimpleNamespace(current={}, update=None)
    stub.reputations.update = lambda u, v: stub.reputations.current.__setitem__(u, v)
    return stub


def test_seeds_fill_gaps_and_refuse_out_of_range(only):
    known, fresh, big, zero = (uuid_mod.uuid4() for _ in range(4))
    only(_ext('s', reputation=ReputationHooks(
        label='probe',
        trust_seeds=lambda proc: [(known, 0.3, 'x'), (fresh, 0.3, 'x'),
                                  (big, 1.5, 'x'), (zero, 0.0, 'x'),
                                  ('not-a-uuid', 0.3, 'x')])))
    rp = _rep_stub()
    rp.reputations.current[known] = 0.85
    ReputationProcess._apply_seeds(rp)
    assert rp.reputations.current == {known: 0.85, fresh: 0.3}


# -- C3/C4: the network hooks ---------------------------------------------------
def _net_stub(*names):
    stub = types.SimpleNamespace(_extensions=list(names),
                                 _excluded_uuids=set(), _excluded_keys=set())
    stub.is_excluded = lambda u, k=None: NetworkProcess.is_excluded(stub, u, k)
    return stub


def test_a_unicast_goes_to_the_first_extension_that_reaches_the_peer(only):
    sent = []
    only(_ext('no', network=NetworkHooks(reaches=lambda p, u: False,
                                         unicast=lambda p, u, f: sent.append('no'))),
         _ext('yes', network=NetworkHooks(reaches=lambda p, u: u == 'b',
                                          unicast=lambda p, u, f: sent.append('yes'))))
    stub = _net_stub('no', 'yes')
    assert NetworkProcess._unicast_carrier(stub, 'a') is None     # the transport
    carrier = NetworkProcess._unicast_carrier(stub, 'b')
    carrier.unicast(stub, 'b', b'frame')
    assert sent == ['yes']


def test_only_loaded_extensions_hook_the_network(only):
    only(_ext('x', network=NetworkHooks(reaches=lambda p, u: True,
                                        unicast=lambda p, u, f: None)))
    assert network_hooks(_net_stub()) == ()
    assert len(network_hooks(_net_stub('x'))) == 1


def test_an_exclusion_is_recorded_before_the_extensions_hear_of_it(only):
    heard = []
    stub = _net_stub('x')
    only(_ext('x', network=NetworkHooks(on_exclusion=lambda p, u, e: heard.append(
        (u, e, NetworkProcess.is_excluded(stub, u))))))
    stub.myself = types.SimpleNamespace(uuid='me')
    stub._exclusion_spec = NetworkProcess._exclusion_spec
    stub._norm_addr = lambda a: a
    stub._rejected_addresses = set()
    stub._peer_key = lambda u: 'ab' * 32
    stub._tell_exclusion = lambda u, e: NetworkProcess._tell_exclusion(stub, u, e)
    u = str(uuid_mod.uuid4())
    msg = types.SimpleNamespace(from_whom=None, obj='{"uuid": "%s"}' % u)
    NetworkProcess.handle_exclude(stub, {}, msg)
    assert heard == [(u, True, True)]
    # By key too: the same peer under a fresh uuid is still excluded.
    assert NetworkProcess.is_excluded(stub, str(uuid_mod.uuid4()), 'AB' * 32)
    NetworkProcess.handle_readmit(stub, {}, msg)
    assert heard[-1] == (u, False, False)
    assert not NetworkProcess.is_excluded(stub, u, 'ab' * 32)
