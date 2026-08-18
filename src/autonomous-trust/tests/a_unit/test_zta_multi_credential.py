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
"""Multi-anchor admission and binding enforcement (doc/architecture/zta-integration.md).

Two things are under test and they are easy to conflate:

* **Binding enforcement.** `binding_mode` decides whether a credential with no
  proof of entitlement may be used at all. `require` is the default because the
  alternative is first-use-wins, which is what is about.
* **Derived gateway authority.** Several credentials arise only at a network
  gateway bridging agencies. Nothing on the wire declares gatewayhood -- it emerges
  from group membership -- so a rule of the form "a gateway must present N
  credentials" would rest on the peer's own claim. Instead each verified credential
  earns authority for its anchor, recorded as `zta_anchors`, and crossing an agency
  boundary is gated on that. A peer that under-claims gains nothing.

Failure is graded throughout: a binding that is present and fails, or a credential
already bound elsewhere, condemns the identity (someone is lying); a credential that
is merely expired or chains to no anchor we hold is skipped (we cannot evaluate it,
which says nothing about the peer).

Real CAs, real chains, real signatures -- a stub could not tell a harvested binding
from an honest one.
"""
import hashlib
import logging
import os
import sys
from types import SimpleNamespace
from uuid import UUID

import pytest

pytest.importorskip("cryptography")

_ROOT = os.path.dirname(os.path.abspath(__file__))
while _ROOT != '/':
    if os.path.isfile(os.path.join(_ROOT, 'tools', 'provision_zta_certs.py')):
        break
    _ROOT = os.path.dirname(_ROOT)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from tools.provision_zta_certs import (# noqa: E402
    make_ca, make_leaf_keypair, ca_bundle_pem, cert_der)

from autonomous_trust.core._python.identity.identity import (# noqa: E402
    Identity, _HAS_ZTA_CREDENTIALS)
from autonomous_trust.core._python.identity.sign import Signature  # noqa: E402
from autonomous_trust.core._python.identity.encrypt import Encryptor  # noqa: E402
from autonomous_trust.core._python.identity.idprocess import IdentityProcess  # noqa: E402
from autonomous_trust.core._python.identity.zta_binding import (# noqa: E402
    ZTA_BINDING_MAX, ZTA_SAN_URI_TEMPLATE, zta_binding_preimage)
from autonomous_trust.core.identity.zta import (# noqa: E402
    ZtaPolicy, BINDING_MODE_OFF, BINDING_MODE_PREFER, BINDING_MODE_REQUIRE)


class _Gate:
    """The real admission gate with real verifiers and nothing else."""
    _zta_policy = IdentityProcess._zta_policy
    _zta_verifier = IdentityProcess._zta_verifier
    _zta_operator_verifier = IdentityProcess._zta_operator_verifier
    _zta_anchor_verifiers = IdentityProcess._zta_anchor_verifiers
    _zta_credentials = IdentityProcess._zta_credentials
    _zta_match_anchors = IdentityProcess._zta_match_anchors
    _zta_credential_replayed = IdentityProcess._zta_credential_replayed
    _is_operator_credential = IdentityProcess._is_operator_credential
    _mark_operator_bound = staticmethod(IdentityProcess._mark_operator_bound)
    _verify_operator_key = IdentityProcess._verify_operator_key
    _zta_admit = IdentityProcess._zta_admit
    # Derived gateway authority, enforced at group federation.
    _own_zta_anchors = IdentityProcess._own_zta_anchors
    _gateway_authorized = IdentityProcess._gateway_authorized
    _discover_child_gateway = IdentityProcess._discover_child_gateway
    _member_rank = IdentityProcess._member_rank

    def __init__(self, policy, peers=None, identity=None):
        self.configs = {ZtaPolicy.CONFIG_KEY: policy}
        self._zta_policy_cache = None
        self._zta_verifier_cache = None
        self._zta_operator_verifier_cache = None
        self._zta_anchor_cache = None
        self._own_anchor_cache = None
        self._zta_capped = set()
        self._operator_verified = set()
        self.logger = logging.getLogger('test.zta.multi')
        self.peers = peers if peers is not None else SimpleNamespace(all=[])
        self.identity = identity


def _identity(tag: str, seed: bytes = b'11') -> Identity:
    """A deterministic identity, so a binding made here is reproducible across runs.
    NOT `hash(tag)`: str hashing is salted per process, which would make the uuid --
    and therefore the signed pre-image -- differ run to run."""
    digest = hashlib.md5(tag.encode()).digest()   # a label, not a security claim
    return Identity(UUID(bytes=digest), '10.0.0.7', '%s.test' % tag,
                    Signature(seed * 32, public_only=False),
                    Encryptor(b'22' * 32, public_only=False))


def _sign(leaf_key, data: bytes) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    return leaf_key.sign(data, ec.ECDSA(hashes.SHA256()))


def _bind(leaf_key, identity, cred: bytes) -> bytes:
    return _sign(leaf_key, zta_binding_preimage(identity, cred))


@pytest.fixture
def agencies(tmp_path):
    """Two unrelated agency CAs, each with its own bundle on disk -- what a gateway
    bridging two agencies actually faces. Plus a third, untrusted CA."""
    out = {}
    for name in ('dod', 'dhs', 'rogue'):
        ca_key, ca_cert = make_ca('%s Root' % name.upper())
        bundle = str(tmp_path / ('%s-ca.pem' % name))
        with open(bundle, 'wb') as fp:
            fp.write(ca_bundle_pem(ca_cert))
        out[name] = SimpleNamespace(key=ca_key, cert=ca_cert, bundle=bundle)
    return out


def _policy(agencies, mode=BINDING_MODE_REQUIRE, names=('dod', 'dhs'), **kw):
    return ZtaPolicy(enabled=True, require_at_admission=True, verifier_type='x509',
                     binding_mode=mode,
                     anchors=[{'name': n, 'ca_bundle_path': agencies[n].bundle}
                              for n in names], **kw)


def _leaf(agencies, agency, cn='node'):
    key, cert = make_leaf_keypair(cn, agencies[agency].key, agencies[agency].cert)
    return key, cert_der(cert)


class TestBindingEnforcement:
    def test_bound_credential_admitted(self, agencies):
        me = _identity('alpha')
        key, cred = _leaf(agencies, 'dod')
        me.zta_credential, me.zta_credential_binding = cred, _bind(key, me, cred)
        assert _Gate(_policy(agencies))._zta_admit(me) == 'admit'

    def test_unbound_credential_rejected_under_require(self, agencies):
        """The flag day, stated as a test: a chain-valid credential with no proof of
        entitlement is refused. This is what closes TOFU."""
        me = _identity('alpha')
        _key, cred = _leaf(agencies, 'dod')
        me.zta_credential = cred
        assert _Gate(_policy(agencies))._zta_admit(me) == 'reject'

    def test_unbound_credential_capped_under_prefer(self, agencies):
        me = _identity('alpha')
        _key, cred = _leaf(agencies, 'dod')
        me.zta_credential = cred
        gate = _Gate(_policy(agencies, mode=BINDING_MODE_PREFER))
        assert gate._zta_admit(me) == 'admit_capped'
        assert str(me.uuid) in {str(u) for u in gate._zta_capped}

    def test_bound_credential_uncapped_under_prefer(self, agencies):
        me = _identity('alpha')
        key, cred = _leaf(agencies, 'dod')
        me.zta_credential, me.zta_credential_binding = cred, _bind(key, me, cred)
        assert _Gate(_policy(agencies, mode=BINDING_MODE_PREFER))._zta_admit(me) == 'admit'

    def test_unbound_credential_uncapped_under_off(self, agencies):
        # `off` is the no-change-in-behaviour setting for a fleet that has not
        # provisioned bindings yet: absence carries no penalty at all.
        me = _identity('alpha')
        _key, cred = _leaf(agencies, 'dod')
        me.zta_credential = cred
        assert _Gate(_policy(agencies, mode=BINDING_MODE_OFF))._zta_admit(me) == 'admit'

    @pytest.mark.parametrize('mode', [BINDING_MODE_REQUIRE, BINDING_MODE_PREFER,
                                      BINDING_MODE_OFF])
    def test_harvested_binding_rejected_in_every_mode(self, agencies, mode):
        """A binding lifted from the victim's announce along with the credential.
        Present-and-failing is affirmative evidence of forgery, so it is refused
        even under `off` -- `off` waives the REQUIREMENT for a binding, never the
        verification of one that was offered."""
        victim, attacker = _identity('alpha'), _identity('mallory')
        key, cred = _leaf(agencies, 'dod')
        harvested = _bind(key, victim, cred)
        attacker.zta_credential, attacker.zta_credential_binding = cred, harvested
        assert _Gate(_policy(agencies, mode=mode))._zta_admit(attacker) == 'reject'

    def test_garbage_binding_rejected(self, agencies):
        me = _identity('alpha')
        _key, cred = _leaf(agencies, 'dod')
        me.zta_credential, me.zta_credential_binding = cred, b'\x30\x06garbage'
        assert _Gate(_policy(agencies))._zta_admit(me) == 'reject'

    def test_san_bound_credential_needs_no_binding_blob(self, agencies):
        """CA-asserted binding: AT controls this CA's issuance, so the certificate
        names the node and there is nothing for the holder to assert."""
        me = _identity('alpha')
        uri = ZTA_SAN_URI_TEMPLATE.format(uuid=str(me.uuid))
        _key, cert = make_leaf_keypair('node', agencies['dod'].key,
                                       agencies['dod'].cert, san_uris=[uri])
        me.zta_credential = cert_der(cert)
        assert _Gate(_policy(agencies))._zta_admit(me) == 'admit'

    def test_san_for_another_node_does_not_bind(self, agencies):
        other = _identity('alpha')
        uri = ZTA_SAN_URI_TEMPLATE.format(uuid=str(other.uuid))
        _key, cert = make_leaf_keypair('node', agencies['dod'].key,
                                       agencies['dod'].cert, san_uris=[uri])
        mallory = _identity('mallory')
        mallory.zta_credential = cert_der(cert)
        assert _Gate(_policy(agencies))._zta_admit(mallory) == 'reject'

    def test_empty_san_template_leaves_only_the_signature_path(self, agencies):
        me = _identity('alpha')
        uri = ZTA_SAN_URI_TEMPLATE.format(uuid=str(me.uuid))
        _key, cert = make_leaf_keypair('node', agencies['dod'].key,
                                       agencies['dod'].cert, san_uris=[uri])
        me.zta_credential = cert_der(cert)
        gate = _Gate(_policy(agencies, san_uri_template=''))
        assert gate._zta_admit(me) == 'reject'


class TestDerivedGatewayAuthority:
    def _gateway(self, agencies, *pairs):
        """A node holding one bound credential per agency in `pairs`."""
        me = _identity('gateway')
        creds = []
        for agency in pairs:
            key, cred = _leaf(agencies, agency, cn='gateway-%s' % agency)
            creds.append({'der': cred, 'binding': _bind(key, me, cred),
                          'issuer': agency})
        me.zta_credential = creds[0]['der']
        me.zta_credential_binding = creds[0]['binding']
        me.zta_credentials = creds
        return me

    def test_single_credential_earns_one_anchor(self, agencies):
        me = self._gateway(agencies, 'dod')
        assert _Gate(_policy(agencies))._zta_admit(me) == 'admit'
        assert me.zta_anchors == ['dod']

    def test_gateway_earns_every_anchor_it_proves(self, agencies):
        me = self._gateway(agencies, 'dod', 'dhs')
        assert _Gate(_policy(agencies))._zta_admit(me) == 'admit'
        assert me.zta_anchors == ['dhs', 'dod']   # sorted, deduplicated

    def test_primary_listed_twice_is_deduplicated(self, agencies):
        """The primary appears in both the singular fields and the repeated list, by
        design -- it must not be counted twice."""
        me = self._gateway(agencies, 'dod')
        assert len(me.zta_credentials) == 1
        gate = _Gate(_policy(agencies))
        assert len(gate._zta_credentials(me)) == 1
        assert gate._zta_admit(me) == 'admit'

    def test_binding_recovered_from_the_repeated_entry(self, agencies):
        """The singular wire fields have nowhere to put a binding, so when the same
        credential appears both ways the bound copy must win."""
        me = self._gateway(agencies, 'dod')
        me.zta_credential_binding = b''        # as an old-format peer would send it
        gate = _Gate(_policy(agencies))
        assert gate._zta_credentials(me)[0][1] == me.zta_credentials[0]['binding']
        assert gate._zta_admit(me) == 'admit'

    def test_unbound_second_credential_costs_only_its_authority(self, agencies):
        """Partial provisioning degrades authority rather than denying admission: the
        node is admitted on what it proved, and simply cannot bridge dhs."""
        me = self._gateway(agencies, 'dod')
        _key, dhs_cred = _leaf(agencies, 'dhs', cn='gateway-dhs')
        me.zta_credentials.append({'der': dhs_cred, 'binding': b'', 'issuer': 'dhs'})
        assert _Gate(_policy(agencies))._zta_admit(me) == 'admit'
        assert me.zta_anchors == ['dod']

    def test_forged_second_binding_condemns_the_identity(self, agencies):
        """Contrast with the case above: a binding that was offered and fails is a
        lie, and one lie is enough regardless of what else verified."""
        me = self._gateway(agencies, 'dod')
        victim = _identity('someone-else')
        key, dhs_cred = _leaf(agencies, 'dhs', cn='gateway-dhs')
        me.zta_credentials.append({'der': dhs_cred,
                                   'binding': _bind(key, victim, dhs_cred),
                                   'issuer': 'dhs'})
        assert _Gate(_policy(agencies))._zta_admit(me) == 'reject'

    def test_credential_from_an_unheld_anchor_is_skipped(self, agencies):
        """Ignorance, not forgery: we hold no rogue anchor, so we cannot evaluate
        that credential. It earns nothing and costs nothing."""
        me = self._gateway(agencies, 'dod')
        key, rogue_cred = _leaf(agencies, 'rogue', cn='gateway-rogue')
        me.zta_credentials.append({'der': rogue_cred,
                                   'binding': _bind(key, me, rogue_cred),
                                   'issuer': 'rogue'})
        assert _Gate(_policy(agencies))._zta_admit(me) == 'admit'
        assert me.zta_anchors == ['dod']

    def test_expired_second_credential_is_skipped(self, agencies):
        import datetime
        me = self._gateway(agencies, 'dod')
        past = datetime.datetime(2000, 1, 2, tzinfo=datetime.timezone.utc)
        key, cert = make_leaf_keypair('gateway-dhs', agencies['dhs'].key,
                                      agencies['dhs'].cert,
                                      not_before=datetime.datetime(
                                          2000, 1, 1,
                                          tzinfo=datetime.timezone.utc),
                                      not_after=past)
        cred = cert_der(cert)
        me.zta_credentials.append({'der': cred, 'binding': _bind(key, me, cred),
                                   'issuer': 'dhs'})
        assert _Gate(_policy(agencies))._zta_admit(me) == 'admit'
        assert me.zta_anchors == ['dod']

    def test_no_credential_from_any_held_anchor_is_refused(self, agencies):
        me = _identity('rogue-node')
        key, cred = _leaf(agencies, 'rogue')
        me.zta_credential, me.zta_credential_binding = cred, _bind(key, me, cred)
        assert _Gate(_policy(agencies))._zta_admit(me) == 'reject'
        assert getattr(me, 'zta_anchors', None) in (None, [])

    def test_replayed_credential_still_condemns_the_identity(self, agencies):
        """The roster check runs before any chain walk and is unchanged; it remains
        the only defence for an unbound credential."""
        key, cred = _leaf(agencies, 'dod')
        incumbent = _identity('alpha')
        incumbent.zta_credential = cred
        attacker = _identity('mallory')
        attacker.zta_credential = cred
        attacker.zta_credential_binding = _bind(key, attacker, cred)
        gate = _Gate(_policy(agencies),
                     peers=SimpleNamespace(all=[incumbent]))
        assert gate._zta_admit(attacker) == 'reject'


class TestWireForm:
    """Fields 6/7/8 keep carrying the primary so a peer predating field 16
    interoperates unchanged; field 16 carries the whole set, which is the only place
    a binding can travel. The primary therefore appears twice on purpose."""

    def _gateway(self, agencies, *pairs):
        me = _identity('gateway')
        creds = []
        for agency in pairs:
            key, cred = _leaf(agencies, agency, cn='gateway-%s' % agency)
            creds.append({'der': cred, 'binding': _bind(key, me, cred),
                          'issuer': agency})
        me.zta_credential = creds[0]['der']
        me.zta_credential_binding = creds[0]['binding']
        me.zta_issuer = creds[0]['issuer']
        me.zta_credentials = creds
        return me

    def test_emitted_tuples_put_the_primary_first(self, agencies):
        me = self._gateway(agencies, 'dod', 'dhs')
        tuples = me._zta_credential_tuples()
        assert len(tuples) == 2
        assert tuples[0][0] == me.zta_credential
        assert tuples[0][1] == me.zta_credential_binding

    def test_primary_listed_in_both_places_emitted_once(self, agencies):
        """`zta_credentials` normally already contains the primary; emitting it twice
        would double every gateway's announce for nothing."""
        me = self._gateway(agencies, 'dod')
        assert len(me.zta_credentials) == 1
        assert len(me._zta_credential_tuples()) == 1

    def test_primary_absent_from_the_list_is_still_emitted(self, agencies):
        me = self._gateway(agencies, 'dod', 'dhs')
        me.zta_credentials = me.zta_credentials[1:]      # list holds only dhs
        tuples = me._zta_credential_tuples()
        assert [t[0] for t in tuples][0] == me.zta_credential
        assert len(tuples) == 2

    def test_credential_without_der_is_skipped(self, agencies):
        me = self._gateway(agencies, 'dod')
        me.zta_credentials.append({'der': b'', 'binding': b'x', 'issuer': 'junk'})
        assert len(me._zta_credential_tuples()) == 1

    @pytest.mark.skipif(not _HAS_ZTA_CREDENTIALS,
                        reason='pb2 predates Identity.zta_credentials (field 16); '
                               'regenerate with scripts/build-py.sh proto-only')
    def test_round_trip_preserves_the_set_and_the_bindings(self, agencies):
        me = self._gateway(agencies, 'dod', 'dhs')
        me.sync_to_message()
        back = Identity.from_wire_bytes(me.message.SerializeToString())
        assert [c['der'] for c in back.zta_credentials] == \
               [c['der'] for c in me.zta_credentials]
        assert [c['binding'] for c in back.zta_credentials] == \
               [c['binding'] for c in me.zta_credentials]
        # The primary's binding has to be recovered from the field-16 entry, since
        # fields 6-8 cannot carry it.
        assert back.zta_credential == me.zta_credential
        assert back.zta_credential_binding == me.zta_credential_binding

    @pytest.mark.skipif(not _HAS_ZTA_CREDENTIALS,
                        reason='pb2 predates Identity.zta_credentials (field 16)')
    def test_round_tripped_gateway_still_admits(self, agencies):
        """The end-to-end point: a gateway's bindings survive the wire, so the
        receiving node can verify them and grant per-anchor authority."""
        me = self._gateway(agencies, 'dod', 'dhs')
        me.sync_to_message()
        back = Identity.from_wire_bytes(me.message.SerializeToString())
        assert _Gate(_policy(agencies))._zta_admit(back) == 'admit'
        assert back.zta_anchors == ['dhs', 'dod']

    @pytest.mark.skipif(not _HAS_ZTA_CREDENTIALS,
                        reason='pb2 predates Identity.zta_credentials (field 16)')
    def test_shrunken_credential_set_is_not_re_advertised(self, agencies):
        """`self.message` is reused across calls, so a node that drops a credential
        must not keep announcing it -- the same staleness the operator fields clear."""
        me = self._gateway(agencies, 'dod', 'dhs')
        me.sync_to_message()
        me.zta_credentials = me.zta_credentials[:1]
        me.sync_to_message()
        assert len(me.message.zta_credentials) == 1

    @pytest.mark.skipif(not _HAS_ZTA_CREDENTIALS,
                        reason='pb2 predates Identity.zta_credentials (field 16)')
    def test_oversized_binding_dropped_on_receipt(self, agencies):
        me = self._gateway(agencies, 'dod')
        me.sync_to_message()
        me.message.zta_credentials[0].binding = b'\x00' * (ZTA_BINDING_MAX + 1)
        back = Identity.from_wire_bytes(me.message.SerializeToString())
        assert back.zta_credentials[0]['binding'] == b''


class TestFederationAuthority:
    """Derived authority at the point of use: a node may federate through a peer only
    if that peer PROVED an anchor this node also holds.

    The rule has to be enforced here rather than on a declared role, because
    gatewayhood is emergent -- it falls out of group membership and rank, and nothing
    on the wire announces it. A peer that simply declines to claim anything therefore
    gains nothing by it.
    """

    def _node(self, agencies, agency='dod', mode=BINDING_MODE_REQUIRE, peers=()):
        """This node, holding `agency`'s credential, with a roster of peers."""
        me = _identity('self')
        key, cred = _leaf(agencies, agency, cn='self')
        me.zta_credential, me.zta_credential_binding = cred, _bind(key, me, cred)
        roster = list(peers)
        gate = _Gate(_policy(agencies, mode=mode, names=('dod', 'dhs')),
                     peers=SimpleNamespace(
                         all=roster,
                         find_by_uuid=lambda u, r=roster: next(
                             (p for p in r if str(p.uuid) == str(u)), None)),
                     identity=me)
        gate.identity = me
        return gate, me

    def _admitted(self, agencies, gate, tag, agency):
        """A peer put through the real admission gate, so its zta_anchors are earned
        rather than assigned."""
        peer = _identity(tag)
        key, cred = _leaf(agencies, agency, cn=tag)
        peer.zta_credential, peer.zta_credential_binding = cred, _bind(key, peer, cred)
        assert gate._zta_admit(peer) == 'admit'
        return peer

    def test_own_anchors_come_from_our_own_credentials(self, agencies):
        gate, _me = self._node(agencies, agency='dod')
        assert gate._own_zta_anchors() == {'dod'}

    def test_peer_sharing_our_anchor_may_be_federated_through(self, agencies):
        gate, _me = self._node(agencies)
        peer = self._admitted(agencies, gate, 'ally', 'dod')
        gate.peers.all.append(peer)
        assert gate._gateway_authorized(peer.uuid) is True

    def test_peer_with_only_a_foreign_anchor_is_refused(self, agencies):
        """A dhs-only peer is a perfectly good node -- it just cannot carry our side of
        the boundary, so we will not route through it."""
        gate, _me = self._node(agencies)
        peer = self._admitted(agencies, gate, 'foreign', 'dhs')
        assert peer.zta_anchors == ['dhs']
        gate.peers.all.append(peer)
        assert gate._gateway_authorized(peer.uuid) is False

    def test_gateway_holding_both_is_authorized(self, agencies):
        gate, _me = self._node(agencies)
        peer = _identity('gateway')
        creds = []
        for agency in ('dod', 'dhs'):
            key, cred = _leaf(agencies, agency, cn='gw-%s' % agency)
            creds.append({'der': cred, 'binding': _bind(key, peer, cred),
                          'issuer': agency})
        peer.zta_credential = creds[0]['der']
        peer.zta_credential_binding = creds[0]['binding']
        peer.zta_credentials = creds
        assert gate._zta_admit(peer) == 'admit'
        assert peer.zta_anchors == ['dhs', 'dod']
        gate.peers.all.append(peer)
        assert gate._gateway_authorized(peer.uuid) is True

    def test_unknown_peer_is_refused(self, agencies):
        """Never admitted here, so nothing proved. Refusing is the point of deriving
        authority rather than accepting a claim."""
        gate, _me = self._node(agencies)
        assert gate._gateway_authorized('nobody-we-know') is False

    def test_inert_when_policy_not_enforcing(self, agencies):
        gate, _me = self._node(agencies)
        gate.configs[ZtaPolicy.CONFIG_KEY] = ZtaPolicy(enabled=False)
        gate._zta_policy_cache = None
        assert gate._gateway_authorized('nobody-we-know') is True

    def test_inert_when_we_hold_no_anchors(self, agencies):
        """Refusing every candidate because WE cannot prove anything would break
        federation rather than protect it."""
        gate, me = self._node(agencies)
        me.zta_credential, me.zta_credential_binding = b'', b''
        gate._own_anchor_cache = None
        assert gate._own_zta_anchors() == set()
        assert gate._gateway_authorized('nobody-we-know') is True

    def test_discovery_passes_over_an_unauthorized_higher_rank_member(self, agencies):
        """The eligible member is chosen even when a higher-rank one is not, rather
        than the group being abandoned."""
        gate, _me = self._node(agencies)
        ally = self._admitted(agencies, gate, 'ally', 'dod')
        foreign = self._admitted(agencies, gate, 'foreign', 'dhs')
        gate.peers.all.extend([ally, foreign])
        # foreign outranks ally, but cannot carry our side of the boundary.
        ranks = {str(foreign.uuid): 9, str(ally.uuid): 1}
        gate._member_rank = lambda u: ranks.get(str(u), 0)
        group = SimpleNamespace(_address_map={str(foreign.uuid): '10.0.0.1',
                                             str(ally.uuid): '10.0.0.2'})
        assert gate._discover_child_gateway(group, None) == str(ally.uuid)

    def test_discovery_returns_none_when_nobody_is_eligible(self, agencies):
        gate, _me = self._node(agencies)
        foreign = self._admitted(agencies, gate, 'foreign', 'dhs')
        gate.peers.all.append(foreign)
        gate._member_rank = lambda u: 1
        group = SimpleNamespace(_address_map={str(foreign.uuid): '10.0.0.1'})
        assert gate._discover_child_gateway(group, None) is None
